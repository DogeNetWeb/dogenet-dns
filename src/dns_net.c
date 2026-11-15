/* dns_net.c — see dns_net.h. */
#include "dns_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "dogenet/wire.h"
#include "dogenet/crypto.h"

#define MAX_PEERS   64
#define HOLD_SLOTS  64
#define HOLD_TTL_S  120
#define INV_BATCH   64          /* names per dnzinv frame */
#define AE_PERIOD_S 60          /* anti-entropy: re-inv the store this often */

/* ── local anti-spam limits (P1–P4, P6–P8, P10) ───────────────────────────────
 * Everything below changes only what THIS node relays, pulls, serves or admits
 * right now. No message, frame, field or command is added or reinterpreted:
 * the three dn* frames keep their exact grammar (dns_net.h), and an op that a
 * limit defers is never rejected for good — the name is re-pulled once the
 * bucket refills, and the newest set wins (sp_state's per-key LWW). Every
 * limit is sized for abuse only: an owner publishing, editing (even several
 * times a block) or transferring never touches one (see the mixed-version
 * tests in the antispam-local evidence). Override any value at build time. */
#ifndef DNSNET_AE_PAGE
#define DNSNET_AE_PAGE      4096    /* P8: names per peer per AE period (rotating cursor) */
#endif
#ifndef DNSNET_OUT_RATE
#define DNSNET_OUT_RATE     65536   /* P6: dn* bytes/s we send one peer */
#endif
#ifndef DNSNET_OUT_BURST
#define DNSNET_OUT_BURST    524288  /* P6: burst (well under the serve queue's 2 MiB) */
#endif
#ifndef DNSNET_ANN_BURST
#define DNSNET_ANN_BURST    4       /* P2: immediate announces per name ... */
#endif
#ifndef DNSNET_ANN_REFILL_MS
#define DNSNET_ANN_REFILL_MS 15000  /* P2: ... then one per 15 s (P1: newest set only) */
#endif
#ifndef DNSNET_PULL_PER_PEER
#define DNSNET_PULL_PER_PEER 32     /* P3: zgets in flight to one peer */
#endif
#ifndef DNSNET_PULL_TIMEOUT_S
#define DNSNET_PULL_TIMEOUT_S 10    /* P3: in-flight zget gives up after this */
#endif
#ifndef DNSNET_GET_RATE
#define DNSNET_GET_RATE     64      /* P7: zgets/s we answer one peer ... */
#endif
#ifndef DNSNET_GET_BURST
#define DNSNET_GET_BURST    512     /* P7: ... burst; the rest wait in a FIFO */
#endif
#ifndef DNSNET_NAME_BURST
#define DNSNET_NAME_BURST   65536   /* P4: admitted op bytes per name: burst (8x budget) */
#endif
#ifndef DNSNET_NAME_RATE_MIN
#define DNSNET_NAME_RATE_MIN 16384  /* P4: ... refill per minute (2x budget) */
#endif
#ifndef DNSNET_REC_BURST
#define DNSNET_REC_BURST    8       /* P4: replacements of one record: burst ... */
#endif
#ifndef DNSNET_REC_REFILL_MS
#define DNSNET_REC_REFILL_MS 15000  /* P4: ... then one per 15 s (blocks are ~60 s) */
#endif
#ifndef DNSNET_SENIOR_ALL
#define DNSNET_SENIOR_ALL   0
#endif
#define ANN_SLOTS   8192
#define ANN_PROBE   8
#define RING        16384           /* announce log shared by all peers */
#define PULL_SLOTS  8192
#define PULL_PROBE  16
#define PULL_ALTS   4
#define SQ_CAP      4096            /* P7 per-peer FIFO of names awaiting a dump */
#define BK_SLOTS    16384           /* P4 bucket tables */
#define BK_PROBE    4

typedef struct {
    void          *peer;
    dnsnet_send_fn send;
    int            used;
    /* P6 */
    int64_t        out_tok; int64_t out_ms;
    /* P7 */
    int64_t        get_tok; int64_t get_ms;
    int            sq_head, sq_n;            /* ring into sq_names[slot] */
    /* P8 */
    char           ae_cursor[SP_NAME_MAX + 1];
    int            ae_left;                  /* names still owed in the current page */
    time_t         ae_next;
    /* P1/P2 announce log position */
    uint64_t       ann_seq[2];               /* [0] senior ring, [1] junior ring */
    /* P3 */
    int            inflight;
} Peer;

typedef struct {
    uint8_t blob[SP_STATE_OP_MAX];
    int     len;
    time_t  expiry;
} Held;

static struct {
    SpState      *st;
    SpChainOracle o;
    int           verbose;
    Peer          peers[MAX_PEERS];
    Held          hold[HOLD_SLOTS];
    time_t        next_ae;
    time_t        last_scan;
    int64_t       last_pull_ms; int pull_kick;
    int (*senior)(const char *name);
    uint64_t      ann_head[2];
    struct {                                  /* counters for the 10-min line */
        unsigned long ann_coalesced, ann_open, ring_skip, pull_dedup, pull_timeout,
                      pull_full, defer_name, defer_rec, get_queued, get_shed, out_wait, ae_names;
    } c, c_logged;
    time_t        next_log;
} g;

/* big tables live outside g: dnsnet_init resets their indices, never the
 * contents, so a (test) re-init stays cheap */
static struct { char name[SP_NAME_MAX + 1]; uint8_t dg[32]; } g_ring[2][RING];
static char g_sq[MAX_PEERS][SQ_CAP][SP_NAME_MAX + 1];
typedef struct { char name[SP_NAME_MAX + 1]; int64_t tok, ms; int dirty; } AnnSlot;
static AnnSlot g_ann[ANN_SLOTS];
typedef struct {
    char    name[SP_NAME_MAX + 1];
    Peer   *inflight; time_t sent_at; time_t not_before; int senior;
    int     nalt; struct { Peer *p; uint8_t dg[32]; int force; } alt[PULL_ALTS];
} PullSlot;
static PullSlot g_pull[PULL_SLOTS];
typedef struct { uint64_t tag; int64_t tok, ms; } Bucket;
static Bucket g_nb[BK_SLOTS], g_rb[BK_SLOTS];
static uint64_t g_seed;

#ifdef DNSNET_TEST_CLOCK_MS          /* tests: a fake millisecond clock */
int64_t DNSNET_TEST_CLOCK_MS(void);
static int64_t now_ms(void) { return DNSNET_TEST_CLOCK_MS(); }
#else
static int64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif
static uint64_t hname(const char *s, const uint8_t *k, int kl) {
    uint64_t h = 1469598103934665603ULL ^ g_seed;
    for (; *s; s++) { h ^= (uint8_t)*s; h *= 1099511628211ULL; }
    h ^= 0xFF; h *= 1099511628211ULL;
    for (int i = 0; i < kl; i++) { h ^= k[i]; h *= 1099511628211ULL; }
    h ^= h >> 29;
    return h ? h : 1;
}
/* refill a token bucket: rate tokens per `per_ms`, capped at burst */
static void refill(int64_t *tok, int64_t *ms, int64_t burst, int64_t rate, int64_t per_ms, int64_t now) {
    if (!*ms) { *tok = burst; *ms = now; return; }
    int64_t dt = now - *ms;
    if (dt <= 0) return;
    int64_t add = dt * rate / per_ms;
    if (add <= 0) return;
    *tok += add; if (*tok > burst) *tok = burst;
    *ms += add * per_ms / rate;
    if (*tok >= burst) *ms = now;
}

/* ── no-change reply limiter ───────────────────────────────────────────────────
 * on_zdat answers a dump that changed nothing with our digest (send_inv_one).
 * When one side CANNOT admit the other's ops (lapsed on its chain view, budget,
 * rule/version drift) the digests never match, and inv → get → dat → inv cycles
 * at round-trip speed. Cap that reply at one per (peer, name) bucket per AE
 * period. The table is FIXED-size and keyed by a hash, so attacker-chosen names
 * cannot grow it; a collision only suppresses more, never sends more. The 60 s
 * send_inv_all still re-offers everything, so convergence is unchanged. Wire-
 * neutral: no new command, frame or field — only how often dnzinv is sent.
 * Bounds: the hash is seeded per process (rl_seed), so a peer cannot aim at a
 * slot. A peer spraying no-op dumps for >1024 names per minute can keep most
 * slots stamped; that only delays honest no-change replies by <=60 s per
 * exchange (send_inv_all re-offers every AE period), never sends more, and the
 * table stays 1024 x time_t. A reused g.peers[] slot may inherit a stamp and
 * delay its first reply by <=60 s; acceptable (dnsnet_up's greeting inv covers
 * it). A stamp in the future (wall clock stepped back) counts as expired. */
#ifndef DNSNET_RL_SLOTS
#define DNSNET_RL_SLOTS 1024
#endif
#if DNSNET_RL_SLOTS > 0
static time_t rl_last[DNSNET_RL_SLOTS];
static uint64_t rl_seed;
static void rl_reseed(void) {
    uint64_t s = 0;
    if (getentropy(&s, sizeof s) != 0)
        s = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32) ^ (uint64_t)(uintptr_t)&s;
    rl_seed = s;
}
static int noop_reply_ok(const Peer *from, const char *name) {
    uint64_t h = (1469598103934665603ULL ^ rl_seed) ^ (uint64_t)(uintptr_t)from; /* seeded FNV-1a */
    for (const char *c = name; *c; c++) { h ^= (uint8_t)*c; h *= 1099511628211ULL; }
    h ^= h >> 29;
    time_t now = time(NULL), *s = &rl_last[h % DNSNET_RL_SLOTS];
    if (*s && now >= *s && now - *s < AE_PERIOD_S) return 0;   /* future stamp => expired */
    *s = now;
    return 1;
}
#else
static int noop_reply_ok(const Peer *from, const char *name) { (void)from; (void)name; return 1; }
#endif

void dnsnet_init(SpState *st, SpChainOracle oracle, int verbose) {
    memset(&g, 0, sizeof g);
#if DNSNET_RL_SLOTS > 0
    memset(rl_last, 0, sizeof rl_last);
    rl_reseed();
#endif
    if (getentropy(&g_seed, sizeof g_seed) != 0)
        g_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    for (int i = 0; i < ANN_SLOTS; i++) g_ann[i].name[0] = '\0';
    for (int i = 0; i < PULL_SLOTS; i++) g_pull[i].name[0] = '\0';
    for (int i = 0; i < BK_SLOTS; i++) { g_nb[i].tag = 0; g_rb[i].tag = 0; }
    g.st = st; g.o = oracle; g.verbose = verbose;
    g.next_log = time(NULL) + 600;
}

void dnsnet_set_seniority(int (*fn)(const char *name)) { g.senior = fn; }

static int is_senior(const char *name) {
    if (DNSNET_SENIOR_ALL || !g.senior) return 1;
    return g.senior(name) ? 1 : 0;
}

int dnsnet_peers(void) {
    int n = 0;
    for (int i = 0; i < MAX_PEERS; i++) if (g.peers[i].used) n++;
    return n;
}

/* ── P6: every dn* byte we send a peer is debited from its bucket ─────────── */
static int out_room(Peer *p, int64_t n) {
    refill(&p->out_tok, &p->out_ms, DNSNET_OUT_BURST, DNSNET_OUT_RATE, 1000, now_ms());
    return p->out_tok >= n;
}
static void psend(Peer *p, const char *cmd, const uint8_t *pay, size_t n) {
    if (!p->used) return;
    p->out_tok -= (int64_t)n + 24;
    p->send(p->peer, cmd, pay, n);
}

/* ── senders ─────────────────────────────────────────────────────────────────── */
typedef struct { uint8_t buf[16 + INV_BATCH * (1 + SP_NAME_MAX + 32)]; int off, count; Peer *to; } InvAcc;

static void inv_flush(InvAcc *a) {
    if (!a->count) return;
    uint8_t hdr[8]; int hn = sp_wvar(hdr, (uint64_t)a->count);
    uint8_t out[sizeof a->buf + 8];
    memcpy(out, hdr, (size_t)hn);
    memcpy(out + hn, a->buf, (size_t)a->off);
    if (a->to) psend(a->to, "dnzinv", out, (size_t)(hn + a->off));
    a->off = 0; a->count = 0;
}

static void inv_add_dg(InvAcc *a, const char *name, const uint8_t dg[32]) {
    int nlen = (int)strlen(name);
    if (nlen < 1 || nlen > SP_NAME_MAX) return;
    a->buf[a->off++] = (uint8_t)nlen;
    memcpy(a->buf + a->off, name, (size_t)nlen); a->off += nlen;
    memcpy(a->buf + a->off, dg, 32); a->off += 32;
    if (++a->count >= INV_BATCH) inv_flush(a);
}
static void inv_add(InvAcc *a, const char *name) {
    uint8_t dg[32]; dns_state_digest(g.st, name, dg);
    inv_add_dg(a, name, dg);
}

/* P8: one page of the store for one peer, from its rotating cursor. A page
 * is at most DNSNET_AE_PAGE names and never laps the cursor it started from,
 * so a store smaller than a page is offered whole, exactly as before. */
typedef struct { InvAcc *a; Peer *p; int left, stop, wrapped; char start[SP_NAME_MAX + 1]; } PageAcc;
static int page_cb(void *u, const char *name) {
    PageAcc *pa = u;
    if (pa->left <= 0) return 0;
    if (pa->wrapped && pa->start[0] && strcmp(name, pa->start) > 0) { pa->left = 0; return 0; }
    /* room for a whole frame before we start one (never tear the page) */
    if (pa->a->count == 0 && !out_room(pa->p, 24 + 8 + INV_BATCH * (1 + SP_NAME_MAX + 32))) {
        pa->stop = 1; g.c.out_wait++; return 0;
    }
    inv_add(pa->a, name);
    snprintf(pa->p->ae_cursor, sizeof pa->p->ae_cursor, "%s", name);
    pa->left--; g.c.ae_names++;
    return 1;
}
static void ae_page(Peer *p) {
    static InvAcc a;
    a.off = 0; a.count = 0; a.to = p;
    PageAcc pa; memset(&pa, 0, sizeof pa);
    pa.a = &a; pa.p = p; pa.left = p->ae_left;
    snprintf(pa.start, sizeof pa.start, "%s", p->ae_cursor);
    while (pa.left > 0 && !pa.stop) {
        int want = pa.left;
        int got = sp_state_names_after(g.st, p->ae_cursor, want, page_cb, &pa);
        if (pa.stop || pa.left <= 0) break;
        if (got < want) {                       /* end of the store */
            if (pa.wrapped || !pa.start[0]) break;
            p->ae_cursor[0] = '\0'; pa.wrapped = 1;
        }
    }
    inv_flush(&a);
    if (pa.stop) { p->ae_left = pa.left; return; }   /* owed: resume next tick */
    p->ae_left = 0;
}

typedef struct { uint8_t *buf; int off, cap, count; } DatAcc;

static int dat_cb(void *u, const uint8_t *key, int klen, int op,
                  uint32_t anchor, const uint8_t *blob, int blen) {
    (void)key; (void)klen; (void)op; (void)anchor;
    DatAcc *a = u;
    uint8_t hdr[8]; int hn = sp_wvar(hdr, (uint64_t)blen);
    if (a->off + hn + blen > a->cap) return 0;
    memcpy(a->buf + a->off, hdr, (size_t)hn); a->off += hn;
    memcpy(a->buf + a->off, blob, (size_t)blen); a->off += blen;
    a->count++;
    return 1;
}

/* build the dump for `name`; returns its length in frame[] */
static int build_zdat(const char *name, uint8_t *frame) {
    int nlen = (int)strlen(name);
    static uint8_t body[2 * DNS_BUDGET];
    DatAcc a = { body, 0, sizeof body, 0 };
    uint8_t *cb; int cl;
    if (sp_state_clear_get(g.st, name, &cb, &cl)) {   /* clear FIRST: floor before rows */
        dat_cb(&a, NULL, 0, SP_OP_CLEAR, 0, cb, cl);
        free(cb);
    }
    sp_state_iter(g.st, name, dat_cb, &a);
    int o = 0;
    frame[o++] = (uint8_t)nlen;
    memcpy(frame + o, name, (size_t)nlen); o += nlen;
    o += sp_wvar(frame + o, (uint64_t)a.count);
    memcpy(frame + o, body, (size_t)a.off); o += a.off;
    return o;
}

/* send one dump if the peer's byte bucket has room; 1 sent, 0 no room */
static int send_zdat(Peer *to, const char *name) {
    int nlen = (int)strlen(name);
    if (nlen < 1 || nlen > SP_NAME_MAX || !to->used) return 1;
    /* budgeted zone + clear op + per-op length prefixes: 2× budget is ample */
    static uint8_t frame[2 * DNS_BUDGET + 64];
    int o = build_zdat(name, frame);
    if (!out_room(to, o + 24)) return 0;
    psend(to, "dnzdat", frame, (size_t)o);
    return 1;
}

/* ── P1/P2: per-name announce limiter + the shared announce log ─────────────── */
static void ring_flush_peer(Peer *p) {
    for (int r = 0; r < 2; r++) {                       /* P10: senior ring first */
        while (p->used && p->ann_seq[r] < g.ann_head[r]) {
            if (g.ann_head[r] - p->ann_seq[r] > RING) {   /* fell a whole ring behind */
                g.c.ring_skip += g.ann_head[r] - p->ann_seq[r] - RING;
                p->ann_seq[r] = g.ann_head[r] - RING;
            }
            if (!out_room(p, 24 + 8 + INV_BATCH * (1 + SP_NAME_MAX + 32))) { g.c.out_wait++; return; }
            static InvAcc a;
            a.off = 0; a.count = 0; a.to = p;
            while (p->ann_seq[r] < g.ann_head[r] && a.count < INV_BATCH - 1) {
                uint64_t s = p->ann_seq[r]++;
                inv_add_dg(&a, g_ring[r][s % RING].name, g_ring[r][s % RING].dg);
            }
            inv_flush(&a);
        }
        if (r == 0 && p->ann_seq[0] < g.ann_head[0]) return;
    }
}
static void ring_flush_all(void) {
    for (int i = 0; i < MAX_PEERS; i++) if (g.peers[i].used) ring_flush_peer(&g.peers[i]);
}
static void ring_append(const char *name) {
    int r = is_senior(name) ? 0 : 1;
    uint64_t s = g.ann_head[r]++;
    snprintf(g_ring[r][s % RING].name, sizeof g_ring[r][0].name, "%s", name);
    dns_state_digest(g.st, name, g_ring[r][s % RING].dg);   /* the newest set, now */
}

static AnnSlot *ann_slot(const char *name, int create) {
    uint64_t h = hname(name, NULL, 0);
    AnnSlot *free_s = NULL, *idle = NULL;
    int64_t now = now_ms();
    for (int i = 0; i < ANN_PROBE; i++) {
        AnnSlot *s = &g_ann[(h + (uint64_t)i) % ANN_SLOTS];
        if (s->name[0] && !strcmp(s->name, name)) return s;
        if (!s->name[0]) { if (!free_s) free_s = s; continue; }
        if (!s->dirty && !idle) {
            refill(&s->tok, &s->ms, DNSNET_ANN_BURST, 1, DNSNET_ANN_REFILL_MS, now);
            if (s->tok >= DNSNET_ANN_BURST) idle = s;     /* a full bucket == a fresh one */
        }
    }
    if (!create) return NULL;
    AnnSlot *s = free_s ? free_s : idle;
    if (!s) return NULL;
    snprintf(s->name, sizeof s->name, "%s", name);
    s->tok = DNSNET_ANN_BURST; s->ms = now; s->dirty = 0;
    return s;
}

void dnsnet_announce(const char *name) {
    size_t nl = name ? strlen(name) : 0;
    if (nl < 1 || nl > SP_NAME_MAX) return;
    AnnSlot *s = ann_slot(name, 1);
    if (!s) { g.c.ann_open++; ring_append(name); ring_flush_all(); return; }  /* table full: never lose it */
    refill(&s->tok, &s->ms, DNSNET_ANN_BURST, 1, DNSNET_ANN_REFILL_MS, now_ms());
    if (s->tok >= 1) { s->tok--; s->dirty = 0; ring_append(name); ring_flush_all(); return; }
    if (!s->dirty) g.c.ann_coalesced++;
    s->dirty = 1;                       /* P1: relayed once, as the newest set, on refill */
}

static void ann_service(void) {
    int64_t now = now_ms(); int any = 0;
    for (int i = 0; i < ANN_SLOTS; i++) {
        AnnSlot *s = &g_ann[i];
        if (!s->name[0] || !s->dirty) continue;
        refill(&s->tok, &s->ms, DNSNET_ANN_BURST, 1, DNSNET_ANN_REFILL_MS, now);
        if (s->tok >= 1) { s->tok--; s->dirty = 0; ring_append(s->name); any = 1; }
    }
    if (any) ring_flush_all();
}

static void send_inv_one(Peer *to, const char *name) {
    static InvAcc a;
    if (!out_room(to, 24 + 8 + 1 + SP_NAME_MAX + 32)) { g.c.out_wait++; return; }
    a.off = 0; a.count = 0; a.to = to;
    inv_add(&a, name);
    inv_flush(&a);
}

/* ── P3: pull table — one zget in flight per name, alternates remembered ───── */
static PullSlot *pull_find(const char *name, int create) {
    uint64_t h = hname(name, NULL, 0);
    PullSlot *fr = NULL;
    for (int i = 0; i < PULL_PROBE; i++) {
        PullSlot *s = &g_pull[(h + (uint64_t)i) % PULL_SLOTS];
        if (s->name[0] && !strcmp(s->name, name)) return s;
        if (!s->name[0] && !fr) fr = s;
    }
    if (!create || !fr) return NULL;
    memset(fr, 0, sizeof *fr);
    snprintf(fr->name, sizeof fr->name, "%s", name);
    fr->senior = is_senior(name);
    return fr;
}
static void pull_alt(PullSlot *s, Peer *p, const uint8_t *dg, int force) {
    for (int i = 0; i < s->nalt; i++)
        if (s->alt[i].p == p) { if (dg) memcpy(s->alt[i].dg, dg, 32); s->alt[i].force |= force; return; }
    if (s->nalt >= PULL_ALTS) { memmove(&s->alt[0], &s->alt[1], sizeof s->alt[0] * (PULL_ALTS - 1)); s->nalt--; }
    s->alt[s->nalt].p = p; s->alt[s->nalt].force = force;
    if (dg) memcpy(s->alt[s->nalt].dg, dg, 32); else memset(s->alt[s->nalt].dg, 0, 32);
    s->nalt++;
}
static void pull_free(PullSlot *s) { s->name[0] = '\0'; s->nalt = 0; s->inflight = NULL; }
static void send_zget(Peer *to, const char *name) {
    int nlen = (int)strlen(name);
    uint8_t req[1 + SP_NAME_MAX]; int ro = 0;
    req[ro++] = (uint8_t)nlen;
    memcpy(req + ro, name, (size_t)nlen); ro += nlen;
    psend(to, "dnzget", req, (size_t)ro);
}
/* try to put one zget for this slot on the wire; frees it when nobody differs */
static void pull_dispatch(PullSlot *s, time_t now) {
    if (!s->name[0] || s->inflight || now < s->not_before) return;
    uint8_t ours[32]; int have_ours = 0;
    for (int i = 0; i < s->nalt; ) {
        Peer *p = s->alt[i].p;
        if (!p || !p->used) { memmove(&s->alt[i], &s->alt[i + 1], sizeof s->alt[0] * (size_t)(s->nalt - i - 1)); s->nalt--; continue; }
        if (!s->alt[i].force) {
            if (!have_ours) { dns_state_digest(g.st, s->name, ours); have_ours = 1; }
            if (!memcmp(ours, s->alt[i].dg, 32)) {  /* already converged with it */
                memmove(&s->alt[i], &s->alt[i + 1], sizeof s->alt[0] * (size_t)(s->nalt - i - 1)); s->nalt--; continue;
            }
        }
        if (p->inflight >= DNSNET_PULL_PER_PEER || !out_room(p, 24 + 1 + SP_NAME_MAX)) { i++; continue; }
        send_zget(p, s->name);
        p->inflight++;
        s->inflight = p; s->sent_at = now;
        memmove(&s->alt[i], &s->alt[i + 1], sizeof s->alt[0] * (size_t)(s->nalt - i - 1)); s->nalt--;
        return;
    }
    if (!s->nalt) pull_free(s);
}
static void pull_want(Peer *from, const char *name, const uint8_t their[32], time_t now) {
    PullSlot *s = pull_find(name, 1);
    if (!s) {                               /* table full: ask directly, unthrottled by P3 */
        g.c.pull_full++;
        if (out_room(from, 24 + 1 + SP_NAME_MAX)) send_zget(from, name);
        return;
    }
    if (s->inflight) g.c.pull_dedup++;
    pull_alt(s, from, their, 0);
    pull_dispatch(s, now);
}
/* a dump for `name` arrived from `from` (solicited or not) */
static void pull_done(Peer *from, const char *name, int deferred, time_t now, time_t retry_at) {
    PullSlot *s = pull_find(name, deferred);
    if (!s) return;
    if (s->inflight == from) { s->inflight = NULL; if (from->inflight > 0) from->inflight--; g.pull_kick = 1; }
    if (deferred) { pull_alt(s, from, NULL, 1); if (retry_at > s->not_before) s->not_before = retry_at; }
    if (!s->inflight) pull_dispatch(s, now);
}
static void pull_service(time_t now) {
    for (int pass = 0; pass < 2; pass++)          /* P10: senior names get the slots first */
        for (int i = 0; i < PULL_SLOTS; i++) {
            PullSlot *s = &g_pull[i];
            if (!s->name[0]) continue;
            if (s->inflight && now - s->sent_at >= DNSNET_PULL_TIMEOUT_S) {
                g.c.pull_timeout++;
                if (s->inflight->inflight > 0) s->inflight->inflight--;
                s->inflight = NULL;
                if (!s->nalt) { pull_free(s); continue; }
            }
            if (s->inflight) continue;
            if ((pass == 0) != (s->senior == 1)) continue;
            pull_dispatch(s, now);
        }
}

/* ── P4: admission buckets (defer, never reject for good) ───────────────────── */
static Bucket *bucket(Bucket *t, uint64_t tag, int64_t burst, int64_t rate, int64_t per_ms, int64_t now) {
    Bucket *fr = NULL;
    for (int i = 0; i < BK_PROBE; i++) {
        Bucket *b = &t[(tag + (uint64_t)i * 0x9E3779B97F4A7C15ULL) % BK_SLOTS];
        if (b->tag == tag) { refill(&b->tok, &b->ms, burst, rate, per_ms, now); return b; }
        if (!fr) {
            if (!b->tag) fr = b;
            else { refill(&b->tok, &b->ms, burst, rate, per_ms, now); if (b->tok >= burst) fr = b; }
        }
    }
    if (!fr) return NULL;                  /* every candidate busy: fail open (never block) */
    fr->tag = tag; fr->tok = burst; fr->ms = now;
    return fr;
}
/* would admitting this (already parsed) op replace a held row / clear? i.e. is
 * it new to us. Dups are free and never deferred. */
static int op_is_new(const char *name, const SpStateOp *p) {
    uint8_t *blob; int bl; int found;
    if (p->op == SP_OP_CLEAR) found = sp_state_clear_get(g.st, name, &blob, &bl);
    else found = sp_state_get(g.st, name, p->key, p->key_len, &blob, &bl);
    if (!found) return 1;
    SpStateOp h; int same = sp_state_op_parse(blob, bl, &h) && !memcmp(h.op_id, p->op_id, 32);
    free(blob);
    return !same;
}
/* 1 = go ahead and admit; 0 = defer (sets *retry_at) */
static int admit_gate(const char *name, const SpStateOp *p, int len, time_t *retry_at) {
    int64_t now = now_ms();
    Bucket *nb = bucket(g_nb, hname(name, NULL, 0), DNSNET_NAME_BURST, DNSNET_NAME_RATE_MIN, 60000, now);
    Bucket *rb = p->op == SP_OP_CLEAR ? NULL
               : bucket(g_rb, hname(name, p->key, p->key_len), DNSNET_REC_BURST, 1, DNSNET_REC_REFILL_MS, now);
    int name_ok = !nb || nb->tok > 0, rec_ok = !rb || rb->tok >= 1;
    if (name_ok && rec_ok) return 1;
    if (!op_is_new(name, p)) return 1;          /* a dup: free (admit returns -1) */
    if (!name_ok) { g.c.defer_name++; *retry_at = time(NULL) + 1 + (time_t)((-nb->tok + 1) * 60 / DNSNET_NAME_RATE_MIN); }
    else          { g.c.defer_rec++;  *retry_at = time(NULL) + 1 + DNSNET_REC_REFILL_MS / 1000; }
    (void)len;
    return 0;
}
static void admit_debit(const char *name, const SpStateOp *p, int len) {
    int64_t now = now_ms();
    Bucket *nb = bucket(g_nb, hname(name, NULL, 0), DNSNET_NAME_BURST, DNSNET_NAME_RATE_MIN, 60000, now);
    if (nb) nb->tok -= len;
    if (p->op != SP_OP_CLEAR) {
        Bucket *rb = bucket(g_rb, hname(name, p->key, p->key_len), DNSNET_REC_BURST, 1, DNSNET_REC_REFILL_MS, now);
        if (rb) rb->tok -= 1;
    }
}

/* ── hold queue (ops anchored ahead of our sync) ─────────────────────────────── */
static void hold_push(const uint8_t *op, int len) {
    for (int i = 0; i < HOLD_SLOTS; i++)
        if (!g.hold[i].len) {
            memcpy(g.hold[i].blob, op, (size_t)len);
            g.hold[i].len = len;
            g.hold[i].expiry = time(NULL) + HOLD_TTL_S;
            return;
        }
}

static void hold_service(void) {
    time_t now = time(NULL);
    char err[128];
    for (int i = 0; i < HOLD_SLOTS; i++) {
        if (!g.hold[i].len) continue;
        if (g.hold[i].expiry <= now) { g.hold[i].len = 0; continue; }
        SpStateOp p;
        char name[SP_NAME_MAX + 1] = "";
        int parsed = sp_state_op_parse(g.hold[i].blob, g.hold[i].len, &p);
        if (parsed) { memcpy(name, p.name, (size_t)p.name_len); name[p.name_len] = '\0'; }
        time_t ra;
        if (parsed && !admit_gate(name, &p, g.hold[i].len, &ra)) continue;   /* P4: keep holding */
        int rc = sp_state_admit(g.st, &g.o, DNS_BUDGET, DNS_SCOPE,
                                g.hold[i].blob, g.hold[i].len, err, sizeof err);
        if (rc == -2) continue;             /* still ahead — keep holding */
        if (rc == 1 && parsed) {
            admit_debit(name, &p, g.hold[i].len);
            dnsnet_announce(name);
        }
        g.hold[i].len = 0;                  /* admitted / rejected / dup — done */
    }
}

/* ── P7: zget answers, paced per peer ──────────────────────────────────────── */
static int sq_push(Peer *p, const char *name) {
    int slot = (int)(p - g.peers);
    for (int i = 0, k = p->sq_head; i < p->sq_n; i++, k = (k + 1) % SQ_CAP)
        if (i >= p->sq_n - 8 && !strcmp(g_sq[slot][k], name)) return 1;   /* recent dup */
    if (p->sq_n >= SQ_CAP) return 0;
    snprintf(g_sq[slot][(p->sq_head + p->sq_n) % SQ_CAP], SP_NAME_MAX + 1, "%s", name);
    p->sq_n++;
    return 1;
}
static void sq_service(Peer *p) {
    int slot = (int)(p - g.peers);
    while (p->used && p->sq_n > 0) {
        refill(&p->get_tok, &p->get_ms, DNSNET_GET_BURST, DNSNET_GET_RATE, 1000, now_ms());
        if (p->get_tok < 1) return;
        if (!send_zdat(p, g_sq[slot][p->sq_head])) { g.c.out_wait++; return; }
        p->get_tok--;
        p->sq_head = (p->sq_head + 1) % SQ_CAP; p->sq_n--;
    }
}

/* ── receive ─────────────────────────────────────────────────────────────────── */
static void on_zinv(Peer *from, const uint8_t *pay, int n) {
    int off = 0; uint64_t count;
    if (!sp_rvar(pay, n, &off, &count) || count > 4096) return;
    time_t now = time(NULL);
    for (uint64_t i = 0; i < count; i++) {
        if (off + 1 > n) return;
        int nlen = pay[off++];
        if (nlen < 1 || nlen > SP_NAME_MAX || off + nlen + 32 > n) return;
        char name[SP_NAME_MAX + 1];
        memcpy(name, pay + off, (size_t)nlen); name[nlen] = '\0'; off += nlen;
        const uint8_t *their = pay + off; off += 32;
        if (!sp_name_valid(name, (size_t)nlen)) continue;
        uint8_t ours[32];
        dns_state_digest(g.st, name, ours);
        if (memcmp(ours, their, 32) != 0) pull_want(from, name, their, now);
    }
}

static void on_zget(Peer *from, const uint8_t *pay, int n) {
    if (n < 1) return;
    int nlen = pay[0];
    if (nlen < 1 || nlen > SP_NAME_MAX || 1 + nlen > n) return;
    char name[SP_NAME_MAX + 1];
    memcpy(name, pay + 1, (size_t)nlen); name[nlen] = '\0';
    if (!sp_name_valid(name, (size_t)nlen)) return;
    refill(&from->get_tok, &from->get_ms, DNSNET_GET_BURST, DNSNET_GET_RATE, 1000, now_ms());
    if (from->sq_n == 0 && from->get_tok >= 1 && send_zdat(from, name)) { from->get_tok--; return; }
    if (sq_push(from, name)) g.c.get_queued++; else g.c.get_shed++;
}

static void on_zdat(Peer *from, const uint8_t *pay, int n) {
    if (n < 1) return;
    int off = 0;
    int nlen = pay[off++];
    if (nlen < 1 || nlen > SP_NAME_MAX || off + nlen > n) return;
    char name[SP_NAME_MAX + 1];
    memcpy(name, pay + off, (size_t)nlen); name[nlen] = '\0'; off += nlen;
    if (!sp_name_valid(name, (size_t)nlen)) return;
    uint64_t count;
    if (!sp_rvar(pay, n, &off, &count) || count > 1024) return;
    int changed = 0, deferred = 0;
    time_t retry_at = 0;
    char err[128];
    for (uint64_t i = 0; i < count; i++) {
        uint64_t ol;
        if (!sp_rvar(pay, n, &off, &ol) || ol < 1 || ol > SP_STATE_OP_MAX || off + (int)ol > n) return;
        const uint8_t *op = pay + off; off += (int)ol;
        /* the frame's name must match the op's (one name per dump) */
        SpStateOp p;
        if (!sp_state_op_parse(op, (int)ol, &p) ||
            p.name_len != nlen || memcmp(p.name, name, (size_t)nlen) != 0) continue;
        time_t ra = 0;
        if (!admit_gate(name, &p, (int)ol, &ra)) {       /* P4: later, not never */
            deferred = 1; if (ra > retry_at) retry_at = ra;
            continue;
        }
        int rc = sp_state_admit(g.st, &g.o, DNS_BUDGET, DNS_SCOPE, op, (int)ol, err, sizeof err);
        if (rc == 1) { changed = 1; admit_debit(name, &p, (int)ol); }
        else if (rc == -2) hold_push(op, (int)ol);
        else if (rc == 0 && g.verbose)
            fprintf(stderr, "dnsnet: reject %s: %s\n", name, err);
    }
    pull_done(from, name, deferred, time(NULL), retry_at);
    if (changed) {
        /* announce to everyone — including the source: if we also hold ops it
         * lacked, its digest now mismatches ours and it pulls back. */
        dnsnet_announce(name);
    } else if (!deferred) {
        /* nothing new for us — the source may be the stale side. Answer with
         * OUR digest for the name (cheap, idempotent); the source zgets from
         * us iff it actually differs, so an equal-state exchange goes silent
         * instead of ping-ponging dumps. (Not while we are deferring its ops:
         * our digest is behind on purpose and the re-pull is scheduled.) */
        if (noop_reply_ok(from, name)) send_inv_one(from, name);
    }
}

/* ── the IdxMeshHooks mirror ─────────────────────────────────────────────────── */
void *dnsnet_up(void *peer, dnsnet_send_fn send) {
    for (int i = 0; i < MAX_PEERS; i++)
        if (!g.peers[i].used) {
            Peer *p = &g.peers[i];
            memset(p, 0, sizeof *p);
            p->peer = peer;
            p->send = send;
            p->used = 1;
            p->ann_seq[0] = g.ann_head[0]; p->ann_seq[1] = g.ann_head[1];
            p->ae_left = DNSNET_AE_PAGE;     /* first page of our shelf, on connect */
            p->ae_next = time(NULL) + AE_PERIOD_S;
            ae_page(p);
            return p;
        }
    return NULL;
}

void dnsnet_msg(void *handle, const char *cmd, const uint8_t *pay, int n) {
    Peer *p = handle;
    if (!p || !p->used || n < 0) return;
    /* idx_serve strips the "dn" transport prefix before the hook (sync.c
     * serve_dispatch hands cmd + 2) — we send "dnzinv", we receive "zinv". */
    if      (!strcmp(cmd, "zinv")) on_zinv(p, pay, n);
    else if (!strcmp(cmd, "zget")) on_zget(p, pay, n);
    else if (!strcmp(cmd, "zdat")) on_zdat(p, pay, n);
}

void dnsnet_down(void *handle) {
    Peer *p = handle;
    if (!p) return;
    for (int i = 0; i < PULL_SLOTS; i++) {        /* P3: forget it as source and target */
        PullSlot *s = &g_pull[i];
        if (!s->name[0]) continue;
        if (s->inflight == p) s->inflight = NULL;
        for (int k = 0; k < s->nalt; ) {
            if (s->alt[k].p == p) { memmove(&s->alt[k], &s->alt[k + 1], sizeof s->alt[0] * (size_t)(s->nalt - k - 1)); s->nalt--; }
            else k++;
        }
        if (!s->nalt && !s->inflight && !s->not_before) pull_free(s);
    }
    p->used = 0; p->peer = NULL; p->send = NULL; p->sq_n = 0; p->inflight = 0;
}

static void log_limits(time_t now) {
    if (now < g.next_log) return;
    g.next_log = now + 600;
    if (!memcmp(&g.c, &g.c_logged, sizeof g.c)) return;
    g.c_logged = g.c;
    fprintf(stderr, "dnsnet: limits ae_names=%lu ann_coalesced=%lu ann_open=%lu ring_skip=%lu "
            "pull_dedup=%lu pull_timeout=%lu pull_full=%lu defer_name=%lu defer_rec=%lu "
            "get_queued=%lu get_shed=%lu out_wait=%lu\n",
            g.c.ae_names, g.c.ann_coalesced, g.c.ann_open, g.c.ring_skip, g.c.pull_dedup,
            g.c.pull_timeout, g.c.pull_full, g.c.defer_name, g.c.defer_rec,
            g.c.get_queued, g.c.get_shed, g.c.out_wait);
}

void dnsnet_tick(void) {
    hold_service();
    time_t now = time(NULL);
    /* P8: each peer gets its next page every AE period (paced by P6) */
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer *p = &g.peers[i];
        if (!p->used) continue;
        if (!p->ae_left && (now >= p->ae_next || p->ae_next - now > AE_PERIOD_S)) {
            p->ae_next = now + AE_PERIOD_S;
            p->ae_left = DNSNET_AE_PAGE;
        }
        if (p->ae_left) ae_page(p);
        ring_flush_peer(p);
        sq_service(p);
    }
    int64_t ms = now_ms();
    if (g.pull_kick && ms - g.last_pull_ms >= 100) {   /* a pull slot freed: refill soon */
        g.pull_kick = 0; g.last_pull_ms = ms;
        pull_service(now);
    }
    if (now != g.last_scan) {                     /* table scans: once a second */
        g.last_scan = now;
        ann_service();
        pull_service(now);
        log_limits(now);
    }
}
