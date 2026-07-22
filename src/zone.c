/* zone.c — see zone.h. */
#include "zone.h"
#include "dns_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

/* ── small helpers ─────────────────────────────────────────────────────── */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into out (max cap). Returns byte count, or -1. */
static int hexdecode(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (s[0] && !isspace((unsigned char)s[0])) {
        int hi = hexval(s[0]), lo = hexval(s[1]);
        if (hi < 0 || lo < 0) return -1;
        if (n >= cap) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return (int)n;
}

/* Map a type mnemonic (or "TYPE52") to its numeric code; 0 if unknown. */
static uint16_t type_code(const char *s)
{
    if (!strcasecmp(s, "A"))          return DNS_A;
    if (!strcasecmp(s, "AAAA"))       return DNS_AAAA;
    if (!strcasecmp(s, "CNAME"))      return DNS_CNAME;
    if (!strcasecmp(s, "NS"))         return DNS_NS;
    if (!strcasecmp(s, "MX"))         return DNS_MX;
    if (!strcasecmp(s, "TXT"))        return DNS_TXT;
    if (!strcasecmp(s, "SRV"))        return DNS_SRV;
    if (!strcasecmp(s, "PTR"))        return DNS_PTR;
    if (!strcasecmp(s, "SSHFP"))      return DNS_SSHFP;
    if (!strcasecmp(s, "TLSA"))       return DNS_TLSA;
    if (!strcasecmp(s, "OPENPGPKEY")) return DNS_OPENPGPKEY;
    if (!strncasecmp(s, "TYPE", 4) && isdigit((unsigned char)s[4]))
        return (uint16_t)atoi(s + 4);
    return 0;
}

/* ── per-type rdata builders ───────────────────────────────────────────────
 * `rest` points at the first rdata token (rest of the record line, trimmed).
 * On success fill rec->rdata/rdlen and return 0; else -1. */

static int build_rdata(zone_rec *rec, const char *rest)
{
    uint8_t *rd = rec->rdata;

    switch (rec->type) {
    case DNS_A: {
        struct in_addr a;
        char tok[64]; sscanf(rest, "%63s", tok);
        if (inet_pton(AF_INET, tok, &a) != 1) return -1;
        memcpy(rd, &a.s_addr, 4); rec->rdlen = 4;
        return 0;
    }
    case DNS_AAAA: {
        struct in6_addr a;
        char tok[64]; sscanf(rest, "%63s", tok);
        if (inet_pton(AF_INET6, tok, &a) != 1) return -1;
        memcpy(rd, a.s6_addr, 16); rec->rdlen = 16;
        return 0;
    }
    case DNS_CNAME:
    case DNS_NS:
    case DNS_PTR: {
        char tok[256]; sscanf(rest, "%255s", tok);
        int n = dns_encode_name(rd, ZONE_MAX_RDATA, tok);
        if (n < 0) return -1;
        rec->rdlen = (uint16_t)n;
        return 0;
    }
    case DNS_MX: {
        unsigned pref; char host[256];
        if (sscanf(rest, "%u %255s", &pref, host) != 2) return -1;
        rd[0] = (uint8_t)(pref >> 8); rd[1] = (uint8_t)pref;
        int n = dns_encode_name(rd + 2, ZONE_MAX_RDATA - 2, host);
        if (n < 0) return -1;
        rec->rdlen = (uint16_t)(2 + n);
        return 0;
    }
    case DNS_TXT: {
        /* One character-string; strip surrounding quotes if present. */
        const char *s = rest;
        size_t len = strlen(s);
        char buf[256];
        if (len >= 2 && s[0] == '"' && s[len - 1] == '"') { s++; len -= 2; }
        if (len > 255) return -1;
        memcpy(buf, s, len);
        rd[0] = (uint8_t)len;
        memcpy(rd + 1, buf, len);
        rec->rdlen = (uint16_t)(1 + len);
        return 0;
    }
    case DNS_TLSA: {
        unsigned usage, sel, mtype; char hex[1024];
        if (sscanf(rest, "%u %u %u %1023s", &usage, &sel, &mtype, hex) != 4)
            return -1;
        rd[0] = (uint8_t)usage; rd[1] = (uint8_t)sel; rd[2] = (uint8_t)mtype;
        int n = hexdecode(hex, rd + 3, ZONE_MAX_RDATA - 3);
        if (n < 0) return -1;
        rec->rdlen = (uint16_t)(3 + n);
        return 0;
    }
    case DNS_SSHFP: {
        unsigned algo, fptype; char hex[1024];
        if (sscanf(rest, "%u %u %1023s", &algo, &fptype, hex) != 3) return -1;
        rd[0] = (uint8_t)algo; rd[1] = (uint8_t)fptype;
        int n = hexdecode(hex, rd + 2, ZONE_MAX_RDATA - 2);
        if (n < 0) return -1;
        rec->rdlen = (uint16_t)(2 + n);
        return 0;
    }
    default: {
        /* Generic: rdata is a raw hex blob (covers OPENPGPKEY, TYPEnnn, …). */
        char hex[1024]; sscanf(rest, "%1023s", hex);
        int n = hexdecode(hex, rd, ZONE_MAX_RDATA);
        if (n < 0) return -1;
        rec->rdlen = (uint16_t)n;
        return 0;
    }
    }
}

/* ── public single-record builder (shared by the file parser and the CLI) ── */

int zone_build_rec(const char *label, const char *type_s, uint32_t ttl,
                   const char *rdata_text, zone_rec *out)
{
    memset(out, 0, sizeof *out);
    if (!strcmp(label, "@")) out->label[0] = '\0';
    else snprintf(out->label, sizeof out->label, "%s", label);
    out->type = type_code(type_s);
    if (out->type == 0) return -1;
    out->ttl = ttl;
    if (!rdata_text || rdata_text[0] == '\0') { out->rdlen = 0; return 0; }  /* delete */
    return build_rdata(out, rdata_text);
}

const char *zone_type_name(uint16_t type, char *buf, size_t cap)
{
    switch (type) {
    case DNS_A:          return "A";
    case DNS_AAAA:       return "AAAA";
    case DNS_CNAME:      return "CNAME";
    case DNS_NS:         return "NS";
    case DNS_MX:         return "MX";
    case DNS_TXT:        return "TXT";
    case DNS_SRV:        return "SRV";
    case DNS_PTR:        return "PTR";
    case DNS_SSHFP:      return "SSHFP";
    case DNS_TLSA:       return "TLSA";
    case DNS_OPENPGPKEY: return "OPENPGPKEY";
    default: snprintf(buf, cap, "TYPE%u", type); return buf;
    }
}

/* ── file parser ───────────────────────────────────────────────────────── */

int zone_load(zone *z, const char *path, const char *apex)
{
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "zone: cannot open %s\n", path); return -1; }

    memset(z, 0, sizeof *z);
    snprintf(z->apex, sizeof z->apex, "%s", apex);

    char line[2048];
    int lineno = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#' || *p == ';') continue;   /* blank/comment */

        /* Directive: serial N */
        if (!strncmp(p, "serial", 6) && isspace((unsigned char)p[6])) {
            z->serial = strtoull(p + 6, NULL, 10);
            continue;
        }

        /* Record: <label> <TYPE> <ttl> <rdata...> */
        char label[64], type_s[16];
        unsigned ttl;
        int consumed = 0;
        if (sscanf(p, "%63s %15s %u %n", label, type_s, &ttl, &consumed) < 3) {
            fprintf(stderr, "zone: %s:%d: malformed record\n", path, lineno);
            fclose(f); return -1;
        }
        if (z->n >= ZONE_MAX_RECS) {
            fprintf(stderr, "zone: %s: too many records\n", path);
            fclose(f); return -1;
        }

        zone_rec *rec = &z->recs[z->n];
        memset(rec, 0, sizeof *rec);
        /* "@" is the apex → empty label internally. */
        if (!strcmp(label, "@")) rec->label[0] = '\0';
        else snprintf(rec->label, sizeof rec->label, "%s", label);
        rec->type = type_code(type_s);
        rec->ttl  = ttl;
        if (rec->type == 0) {
            fprintf(stderr, "zone: %s:%d: unknown type %s\n", path, lineno, type_s);
            fclose(f); return -1;
        }

        char *rest = p + consumed;
        /* trim trailing newline/space */
        size_t rl = strlen(rest);
        while (rl && isspace((unsigned char)rest[rl - 1])) rest[--rl] = '\0';

        if (build_rdata(rec, rest) != 0) {
            fprintf(stderr, "zone: %s:%d: bad rdata for %s\n", path, lineno, type_s);
            fclose(f); return -1;
        }
        z->n++;
    }
    fclose(f);
    return 0;
}
