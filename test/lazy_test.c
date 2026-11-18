#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1   /* mkstemp/getentropy/strdup under -std=c11 (any build) */
#endif
/* lazy_test.c — LZ (lazy / namespace-only mode), in-process, fake clock.
 *
 * PROVEN HERE
 *   • dns_lazy table: absent -> loading (fetch queued once, deduped), done(ok)
 *     -> ready; TTL -> stale-while-revalidate (still READY, one re-fetch
 *     queued); verified-empty uses the short empty TTL; a failed fetch -> FAILED
 *     and is retried only after fail_retry_s; a failed REFRESH keeps serving the
 *     old verified zone until max_stale, then LOADING (never NXDOMAIN); LRU
 *     eviction by last use, bounded by max_names and max_bytes; pinned and
 *     loading names are never evicted; invalidate (owner change) forgets data;
 *     a full table answers LOADING, never ABSENT; restart adoption = READY+stale.
 *   • dnsd_core in lazy mode: an OWNED name whose zone is not fetched answers
 *     SERVFAIL + EDE 14 (Not Ready) — never NXDOMAIN, never an empty/missing
 *     TLSA; FAILED answers SERVFAIL + EDE 22; a non-EDNS client gets plain
 *     SERVFAIL; dnsd_core_answer_lazy reports not-ready without answering (the
 *     park path); an UNOWNED name is still NXDOMAIN at once; once the zone is
 *     admitted + done, answers are byte-identical to full mode; rows held for a
 *     previous owner are not served (re-fetch). Full mode (lazy=0) unchanged. */
#include "dns_lazy.h"
#include "dnsd_core.h"
#include "dns_state.h"
#include "dns_wire.h"
#include "zone.h"
#include "dns_mesh.h"      /* dogenet/ or pepenet/ mesh headers */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_ok, g_fail;
#define CK(c, m) do { if (c) { g_ok++; printf("  ok   %s\n", m); } \
                      else { g_fail++; printf("  FAIL %s  (line %d)\n", m, __LINE__); } } while (0)

static int64_t g_ms = 1000000;
int64_t lz_clock(void) { return g_ms; }

/* ── fake chain ─────────────────────────────────────────────────────────── */
static uint32_t g_tip = 500;
static uint8_t  g_owner160[20], g_other160[20];
static int g_transfer = 0;
static int fk_owner(void *u, const char *name, uint8_t owner[20]) {
    (void)u;
    if (strcmp(name, "dogenet") && strcmp(name, "gpt")) return 0;
    memcpy(owner, g_transfer && !strcmp(name, "gpt") ? g_other160 : g_owner160, 20);
    return 1;
}
static int fk_header(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    if (height > g_tip) return 0;
    uint8_t seed[8] = { 'h','d','r',1, (uint8_t)height, (uint8_t)(height >> 8),
                        (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(seed, sizeof seed, out);
    return 1;
}
static uint32_t fk_tip(void *u) { (void)u; return g_tip; }
static SpChainOracle ORC = { NULL, fk_owner, fk_header, fk_tip };

static void p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t g16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static size_t mkq(uint8_t *b, const char *qname, uint16_t qtype, int edns) {
    p16(b, 0x1234); p16(b + 2, 0x0100);
    p16(b + 4, 1); p16(b + 6, 0); p16(b + 8, 0); p16(b + 10, edns ? 1 : 0);
    size_t o = 12;
    o += (size_t)dns_encode_name(b + o, 300, qname);
    p16(b + o, qtype); o += 2; p16(b + o, 1); o += 2;
    if (edns) { b[o++] = 0; p16(b + o, 41); o += 2; p16(b + o, 1232); o += 2;
                b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = 0; p16(b + o, 0); o += 2; }
    return o;
}
/* rcode, answer count, EDE info code (-1 none) */
typedef struct { int rcode, an, ede, opt; char ede_txt[256]; } R;
static R ask(DnsdCore *dc, const char *qname, uint16_t qtype, int edns) {
    uint8_t qb[512], out[4096]; R r; memset(&r, 0, sizeof r); r.ede = -1;
    size_t ql = mkq(qb, qname, qtype, edns);
    dns_query q;
    if (dns_parse_query(qb, ql, &q)) { r.rcode = -1; return r; }
    size_t n = dnsd_core_answer(dc, &q, out, sizeof out, 0);
    if (n < 12) { r.rcode = -2; return r; }
    r.rcode = out[3] & 15; r.an = g16(out + 6);
    int ar = g16(out + 10);
    size_t o = 12;
    while (out[o]) o += out[o] + 1u;
    o += 5;
    for (int i = 0; i < r.an; i++) {
        if ((out[o] & 0xC0) == 0xC0) o += 2; else { while (out[o]) o += out[o] + 1u; o++; }
        o += 8; uint16_t rl = g16(out + o); o += 2 + rl;
    }
    for (int i = 0; i < ar && o < n; i++) {
        o++;                                   /* root name */
        uint16_t t = g16(out + o); uint16_t rl = g16(out + o + 8); o += 10;
        if (t == 41) {
            r.opt = 1;
            size_t e = o + rl;
            while (o + 4 <= e) {
                uint16_t code = g16(out + o), ol = g16(out + o + 2);
                if (code == 15 && ol >= 2) {
                    r.ede = g16(out + o + 4);
                    int tl = ol - 2; if (tl > 255) tl = 255;
                    memcpy(r.ede_txt, out + o + 6, (size_t)tl); r.ede_txt[tl] = 0;
                }
                o += 4u + ol;
            }
            o = e;
        } else o += rl;
    }
    return r;
}

static void testkey(const char *seed, uint8_t priv[32], uint8_t pub[33]) {
    sp_sha256((const uint8_t *)seed, strlen(seed), priv);
    while (!sp_pubkey(priv, pub)) sp_sha256(priv, 32, priv);
}

int main(void) {
    char nm[64];
    printf("== dns_lazy table ==\n");
    DnsLazyConf c; dns_lazy_conf_default(&c);
    c.max_names = 16; c.max_bytes = 1 << 20; c.ttl_s = 300; c.empty_ttl_s = 60;
    c.max_stale_s = 3600; c.fail_retry_s = 5;
    dns_lazy_init(&c);
    CK(dns_lazy_enabled(), "enabled after init");
    int age;
    CK(dns_lazy_want("alpha", &age) == DNS_LAZY_LOADING && age == -1, "absent name -> LOADING, no age");
    CK(dns_lazy_want("alpha", NULL) == DNS_LAZY_LOADING, "second want still LOADING");
    CK(dns_lazy_pop_request(nm) && !strcmp(nm, "alpha"), "one fetch queued");
    CK(!dns_lazy_pop_request(nm), "deduped: no second request");
    CK(dns_lazy_tracked("alpha"), "loading name is tracked (inv/dat accepted)");
    CK(!dns_lazy_tracked("beta"), "untouched name is not tracked (gossip ignored)");
    dns_lazy_begin("alpha");
    dns_lazy_done("alpha", 1, 500, 0);
    CK(dns_lazy_want("alpha", &age) == DNS_LAZY_READY && age == 0, "done(ok) -> READY, age 0");
    CK(!dns_lazy_pop_request(nm), "fresh: no re-fetch");
    g_ms += 301 * 1000;
    CK(dns_lazy_want("alpha", &age) == DNS_LAZY_READY && age == 301, "past TTL: still READY (stale-while-revalidate)");
    CK(dns_lazy_pop_request(nm) && !strcmp(nm, "alpha"), "past TTL: one re-fetch queued");
    dns_lazy_begin("alpha");
    CK(dns_lazy_want("alpha", NULL) == DNS_LAZY_READY, "refresh in flight: old verified zone still served");
    dns_lazy_done("alpha", 0, 0, 0);
    CK(dns_lazy_want("alpha", NULL) == DNS_LAZY_READY, "refresh FAILED: old zone served (within max_stale)");
    CK(!dns_lazy_pop_request(nm), "failed: no retry before fail_retry_s");
    g_ms += 6000;
    dns_lazy_want("alpha", NULL);
    CK(dns_lazy_pop_request(nm), "failed: retried after fail_retry_s");
    dns_lazy_begin("alpha"); dns_lazy_done("alpha", 0, 0, 0);
    g_ms += 3600 * 1000;
    CK(dns_lazy_want("alpha", NULL) == DNS_LAZY_LOADING, "beyond max_stale with refresh failing: LOADING (re-fetch), not served");
    CK(dns_lazy_pop_request(nm), "beyond max_stale: re-fetch queued");
    dns_lazy_begin("alpha"); dns_lazy_done("alpha", 1, 400, 0);

    CK(dns_lazy_want("gamma", NULL) == DNS_LAZY_LOADING, "gamma loading");
    dns_lazy_pop_request(nm); dns_lazy_begin("gamma"); dns_lazy_done("gamma", 0, 0, 0);
    CK(dns_lazy_want("gamma", NULL) == DNS_LAZY_FAILED, "fetch failed with no data -> FAILED");
    g_ms += 6000;
    CK(dns_lazy_want("gamma", NULL) == DNS_LAZY_LOADING, "FAILED retried by the next query -> LOADING");
    dns_lazy_pop_request(nm); dns_lazy_begin("gamma"); dns_lazy_done("gamma", 1, 0, 1);
    CK(dns_lazy_want("gamma", NULL) == DNS_LAZY_READY, "verified-empty zone READY");
    g_ms += 61 * 1000;
    dns_lazy_want("gamma", NULL);
    CK(dns_lazy_pop_request(nm) && !strcmp(nm, "gamma"), "verified-empty uses the short empty TTL");
    dns_lazy_begin("gamma"); dns_lazy_done("gamma", 1, 0, 1);

    /* LRU */
    dns_lazy_pin("mine");
    for (int i = 0; i < 30; i++) {
        char n[16]; snprintf(n, sizeof n, "n%02d", i);
        g_ms += 10;
        dns_lazy_want(n, NULL); dns_lazy_pop_request(nm); dns_lazy_begin(n); dns_lazy_done(n, 1, 100, 0);
        char v[64]; while (dns_lazy_evict_one(v)) {}
    }
    DnsLazyStats st; dns_lazy_stats(&st);
    CK(st.names <= 16, "LRU keeps <= max_names zones");
    CK(dns_lazy_peek("n29", NULL) == DNS_LAZY_READY, "most recent name kept");
    CK(dns_lazy_peek("n00", NULL) == DNS_LAZY_ABSENT, "least recent name evicted");
    CK(dns_lazy_pinned("mine"), "pinned name survives eviction");
    dns_lazy_want("n20", NULL);                     /* touch -> recent */
    g_ms += 10;
    dns_lazy_want("zz1", NULL); dns_lazy_pop_request(nm); dns_lazy_begin("zz1"); dns_lazy_done("zz1", 1, 100, 0);
    { char v[64]; while (dns_lazy_evict_one(v)) {} }
    CK(dns_lazy_peek("n20", NULL) == DNS_LAZY_READY, "a touched name moves to the LRU head");
    dns_lazy_want("ld1", NULL); dns_lazy_pop_request(nm); dns_lazy_begin("ld1");
    for (int i = 0; i < 40; i++) { char n[16]; snprintf(n, sizeof n, "m%02d", i); g_ms += 10;
        dns_lazy_want(n, NULL); dns_lazy_pop_request(nm); dns_lazy_begin(n); dns_lazy_done(n, 1, 100, 0);
        char v[64]; while (dns_lazy_evict_one(v)) {} }
    CK(dns_lazy_tracked("ld1"), "a LOADING name is never evicted");
    dns_lazy_done("ld1", 1, 100, 0);
    /* bytes bound */
    for (int i = 0; i < 8; i++) { char n[16]; snprintf(n, sizeof n, "big%d", i); g_ms += 10;
        dns_lazy_want(n, NULL); dns_lazy_pop_request(nm); dns_lazy_begin(n); dns_lazy_done(n, 1, 300000, 0);
        char v[64]; while (dns_lazy_evict_one(v)) {} }
    dns_lazy_stats(&st);
    CK(st.bytes <= (1 << 20), "LRU keeps held bytes <= max_bytes");
    dns_lazy_invalidate("big7");
    CK(dns_lazy_peek("big7", NULL) != DNS_LAZY_READY, "invalidate (owner change) forgets the data");
    dns_lazy_adopt("restart1", 200);
    CK(dns_lazy_want("restart1", NULL) == DNS_LAZY_READY, "adopted (restart) zone served at once");
    int q = 0; while (dns_lazy_pop_request(nm)) if (!strcmp(nm, "restart1")) q = 1;
    CK(q, "adopted zone is stale: re-validated on first use");
    /* table full: never ABSENT for want */
    DnsLazyConf c2 = c; c2.max_names = 16; dns_lazy_init(&c2);
    int bad = 0;
    for (int i = 0; i < 2000; i++) { char n[16]; snprintf(n, sizeof n, "f%04d", i);
        int s = dns_lazy_want(n, NULL); if (s == DNS_LAZY_ABSENT || s == DNS_LAZY_READY) bad++; }
    CK(!bad, "2000 distinct wants with a 16-zone table: always LOADING (never absent/ready-empty)");

    printf("== dnsd_core lazy answers ==\n");
    dns_lazy_init(&c);
    uint8_t OPRIV[32], OPUB[33]; testkey("owner", OPRIV, OPUB);
    sp_hash160(OPUB, 33, g_owner160);
    uint8_t xp[32], xpub[33]; testkey("other", xp, xpub); sp_hash160(xpub, 33, g_other160);
    SpState *st0 = sp_state_open(":memory:");
    DnsdCore dc; memset(&dc, 0, sizeof dc);
    dc.st = st0; dc.oracle = ORC; dc.suffix = "doge"; dc.ufd = dc.tfd = -1;
    dc.lazy = 1; dc.lazy_wait_ms = 3000;
    R r = ask(&dc, "www.dogenet.doge", 1, 1);
    CK(r.rcode == 2 && r.ede == 14 && r.an == 0, "owned, not fetched: SERVFAIL + EDE 14 Not Ready");
    CK(strstr(r.ede_txt, "loading") != NULL, "EDE extra text says loading");
    r = ask(&dc, "_443._tcp.dogenet.doge", 52, 1);
    CK(r.rcode == 2 && r.ede == 14, "TLSA while loading: SERVFAIL/EDE14, never NXDOMAIN or empty");
    r = ask(&dc, "www.dogenet.doge", 1, 0);
    CK(r.rcode == 2 && !r.opt, "non-EDNS client: plain SERVFAIL (no OPT)");
    r = ask(&dc, "nope.doge", 1, 1);
    CK(r.rcode == 3, "unowned name: NXDOMAIN at once (namespace says so)");
    { uint8_t qb[512], out[4096]; size_t ql = mkq(qb, "www.dogenet.doge", 1, 1); dns_query qq;
      dns_parse_query(qb, ql, &qq); int nr = 0;
      size_t n = dnsd_core_answer_lazy(&dc, &qq, out, sizeof out, 0, &nr);
      CK(n == 0 && nr == DNS_LAZY_LOADING, "answer_lazy: not-ready -> park (no answer built)"); }
    CK(dns_lazy_pop_request(nm) && !strcmp(nm, "dogenet"), "the query queued exactly one fetch");
    while (dns_lazy_pop_request(nm)) {}
    dns_lazy_begin("dogenet"); dns_lazy_done("dogenet", 0, 0, 0);
    r = ask(&dc, "www.dogenet.doge", 1, 1);
    CK(r.rcode == 2 && r.ede == 22, "fetch failed: SERVFAIL + EDE 22 No Reachable Authority");
    /* the fetch lands: publish + done */
    zone_rec rec; memset(&rec, 0, sizeof rec);
    snprintf(rec.label, sizeof rec.label, "www"); rec.type = 1; rec.ttl = 300; rec.rdlen = 4;
    rec.rdata[0] = 192; rec.rdata[1] = 0; rec.rdata[2] = 2; rec.rdata[3] = 7;
    char err[128];
    CK(dns_state_put(st0, &ORC, "dogenet", &rec, OPRIV, OPUB, SP_CERT_NONE, NULL, 0, err, sizeof err) == 1, "zone admitted");
    dns_lazy_done("dogenet", 1, sp_state_sum(st0, "dogenet"), 0);
    r = ask(&dc, "www.dogenet.doge", 1, 1);
    CK(r.rcode == 0 && r.an == 1 && r.ede == -1 && r.opt, "ready: NOERROR, 1 A, plain OPT");
    r = ask(&dc, "nothere.dogenet.doge", 1, 1);
    CK(r.rcode == 3, "ready: unknown label NXDOMAIN (same as full mode)");
    DnsdCore full = dc; full.lazy = 0;
    uint8_t qb[512], o1[4096], o2[4096]; size_t ql = mkq(qb, "www.dogenet.doge", 1, 1); dns_query qq;
    dns_parse_query(qb, ql, &qq);
    size_t n1 = dnsd_core_answer(&dc, &qq, o1, sizeof o1, 0), n2 = dnsd_core_answer(&full, &qq, o2, sizeof o2, 0);
    CK(n1 == n2 && !memcmp(o1, o2, n1), "ready lazy answer byte-identical to full mode");
    /* previous-owner rows */
    CK(dns_state_put(st0, &ORC, "gpt", &rec, OPRIV, OPUB, SP_CERT_NONE, NULL, 0, err, sizeof err) == 1, "gpt zone admitted");
    dns_lazy_want("gpt", NULL); while (dns_lazy_pop_request(nm)) {}
    dns_lazy_begin("gpt"); dns_lazy_done("gpt", 1, 100, 0);
    g_transfer = 1;
    r = ask(&dc, "www.gpt.doge", 1, 1);
    CK(r.rcode == 2 && r.ede == 14, "transfer: previous owner's rows not served; re-fetch (loading)");
    q = 0; while (dns_lazy_pop_request(nm)) if (!strcmp(nm, "gpt")) q = 1;
    CK(q, "transfer: re-fetch queued");
    g_transfer = 0;
    /* full mode untouched */
    DnsdCore f2; memset(&f2, 0, sizeof f2); f2.st = sp_state_open(":memory:"); f2.oracle = ORC; f2.suffix = "doge";
    r = ask(&f2, "www.dogenet.doge", 1, 1);
    CK(r.rcode == 3 && r.ede == -1, "full mode (lazy=0): empty store -> NXDOMAIN exactly as before");
    printf("%d ok, %d failed\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
