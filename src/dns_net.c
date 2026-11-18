/* dns_net.c — see dns_net.h. */
#include "dns_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "dogenet/wire.h"
#include "dogenet/crypto.h"
#include "dns_lazy.h"

#define MAX_PEERS   64
#define HOLD_SLOTS  64
#define HOLD_TTL_S  120
#define INV_BATCH   64          /* names per dnzinv frame */
#define AE_PERIOD_S 60          /* anti-entropy: re-inv the store this often */

/* ── local anti-spam limits (P1–P4, P6–P8, P11; L1–L10) ─────────────────────────
 * Everything below changes only what THIS node relays, pulls, serves or admits
 * right now. No message, frame, field or command is added or reinterpreted:
 * the three dn* frames keep their exact grammar (dns_net.h), and an op that a
 * limit defers is never rejected for good — the name is re-pulled once the
 * bucket refills, and the newest set wins (sp_state's per-key LWW). Override
 * any value at build time.
 *
 * L1  every fixed table FAILS SLOW, never open: a full announce table, pull
 *     table or admission-bucket table no longer means "unthrottled"; names wait
 *     in bounded two-lane FIFOs (overflow beyond them is dropped and repaired by
 *     anti-entropy), buckets fall back to one shared, bounded overflow bucket.
 * L2  per-name relay CREDIT counted in BLOCKS: burst DNSNET_CREDIT_BURST, then
 *     one relay per `credit_blocks` blocks (default 10, dnsnet_set_credit_blocks).
 *     Credit only refills when the monotonic max-seen tip height rises, so a
 *     stalled chain mints nothing beyond the burst, and a reorg (height down, or
 *     a different hash at the same height) can neither mint extra credit nor
 *     underflow; a big jump refills at most to the burst. Refills are
 *     STAGGERED: a name gains its credit on the heights h with h % credit_blocks
 *     == phase(name), phase = SipHash-2-4(name) under a per-process random key
 *     (no grinding names onto one phase); a jump counts every phase height it
 *     crosses (capped at the burst). Over credit = LATER
 *     (P1: the newest set is relayed on refill), never refused. Priority is
 *     STALE-FIRST: every relay goes into one of DNSNET_LANES lanes by how long
 *     the name has been quiet (blocks since its last relayed change); lower
 *     lanes always go first. This replaces P10's ownership-age seniority.
 * L3  priority dispatch of pulls (lane, live relay before AE page, then waiting
 *     time; a live pull jumps the overflow FIFO) and a high lane in
 *     the responder's zget FIFO.
 * L4  dnzinv (announce + anti-entropy + no-change reply) bytes are capped at
 *     25% of each link's P6 budget; dumps and zgets get the other 75%.
 * L5  ops we already hold are skipped before admission (and the mesh store
 *     dedups op_id before ECDSA).
 * L6  per-peer inbound dn* byte budget + a usefulness score: peers whose
 *     UNSOLICITED dumps are mostly useless are deprioritised, then disconnected
 *     (never loopback or an outbound seat; answers to our own zgets never count
 *     against a peer, so an honest stale peer is never scored down).
 * L7  peer cap for small uplinks (dnsnet_set_peer_cap; dnsd --uplink-mbit:
 *     cap = uplink / 0.52 Mbit/s), and P6 refill frozen while the socket's send
 *     queue has not drained.
 * L8  each link starts its anti-entropy cursor (and period) at a random place.
 * L9  one store transaction per received dump.
 * L10 cached per-name digests (dns_state.c). */
#ifndef DNSNET_AE_PAGE
#define DNSNET_AE_PAGE      4096    /* P8: names per peer per AE period (rotating cursor) */
#endif
#ifndef DNSNET_OUT_RATE
#define DNSNET_OUT_RATE     65536   /* P6: dn* bytes/s we send one peer */
#endif
#ifndef DNSNET_OUT_BURST
#define DNSNET_OUT_BURST    524288  /* P6: burst (well under the serve queue's 2 MiB) */
#endif
#ifndef DNSNET_INV_PCT
#define DNSNET_INV_PCT      25      /* L4: % of P6 that dnzinv may use; dumps get the rest */
#endif
#ifndef DNSNET_CREDIT_BURST
#define DNSNET_CREDIT_BURST 4       /* L2 (was P2): immediate relays per name ... */
#endif
#ifndef DNSNET_CREDIT_BLOCKS
#define DNSNET_CREDIT_BLOCKS 10     /* L2: ... then one per this many blocks */
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
#ifndef DNSNET_BK_OVF_MULT
#define DNSNET_BK_OVF_MULT  16      /* L1: the shared overflow bucket = 16 names' worth */
#endif
#ifndef DNSNET_IN_RATE
#define DNSNET_IN_RATE      262144  /* L6: dn* bytes/s we accept from one peer (4x P6) */
#endif
#ifndef DNSNET_IN_BURST
#define DNSNET_IN_BURST     4194304 /* L6: ... burst (2 max-size frames) */
#endif
#ifndef DNSNET_USE_HALF_S
#define DNSNET_USE_HALF_S   600     /* L6: usefulness counters halve this often */
#endif
#ifndef DNSNET_LOW_BAD
#define DNSNET_LOW_BAD      64      /* L6: deprioritise at >= this many useless dumps ... */
#endif
#ifndef DNSNET_LOW_RATIO
#define DNSNET_LOW_RATIO    4       /* ... and more than this x useful ones */
#endif
#ifndef DNSNET_KICK_BAD
#define DNSNET_KICK_BAD     4096    /* L6: disconnect at >= this many (~5/s sustained) ... */
#endif
#ifndef DNSNET_KICK_RATIO
#define DNSNET_KICK_RATIO   32      /* ... and more than this x useful ones */
#endif
#ifndef DNSNET_DRAIN_MAX
#define DNSNET_DRAIN_MAX    262144  /* L7: no new dn* bytes while more than this is unsent */
#endif
#define LANES       5               /* L2/L3 stale-first lanes, 0 = quietest */
#define LANE_HI     2               /* lanes 0..LANE_HI are "high" in two-lane queues */
#define ANN_SLOTS   8192            /* names waiting for relay credit (P1 coalesced) */
#define ANN_PROBE   8
#define ANN_OVF     2048            /* L1: per lane */
#ifndef DNSNET_RING
#define DNSNET_RING 8192            /* announce log per lane, shared by all peers */
#endif
#define RING        DNSNET_RING
#define PULL_SLOTS  8192
#define PULL_PROBE  16
#define PULL_ALTS   4
#define FRESH_FRAME 4               /* a dnzinv frame of <= this many names counts as live */
#define PULL_OVF    2048            /* L1: per lane */
#define SQ_CAP      4096            /* P7 per-peer FIFO of names awaiting a dump */
#define SQH_CAP     1024            /* L3: its high lane */
#define BK_SLOTS    16384           /* P4 bucket tables */
#define BK_PROBE    4
#ifndef DNSNET_NR_BITS
#define DNSNET_NR_BITS 16           /* L2: 2^16 sets x 4 ways of per-name credit (4 MiB) */
#endif
#define NR_SETS     (1u << DNSNET_NR_BITS)
#define NR_WAYS     4
#define NR_RELAYED  1u
#define NR_IN_OVF   2u
#define INV_FRAME   (24 + 8 + INV_BATCH * (1 + SP_NAME_MAX + 32))

typedef struct {
    void          *peer;
    dnsnet_send_fn send;
    int            used;
    uint32_t       gen;                      /* L1: identifies this session in queues */
    /* P6, split by L4: dumps + zgets | dnzinv */
    int64_t        out_tok; int64_t out_ms;
    int64_t        inv_tok; int64_t inv_ms;
    /* P7 */
    int64_t        get_tok; int64_t get_ms;
    int            sq_head, sq_n;            /* ring into g_sq[slot] */
    int            sqh_head, sqh_n;          /* L3: high lane, ring into g_sqh[slot] */
    /* P8 */
    char           ae_cursor[SP_NAME_MAX + 1];
    int            ae_left;                  /* names still owed in the current page */
    time_t         ae_next;
    /* L2 announce log position, per lane */
    uint64_t       ann_seq[LANES];
    /* P3 */
    int            inflight;
    /* L6 */
    int64_t        in_tok, in_ms;
    unsigned long  in_drop;
    unsigned       good, bad;
    time_t         use_half_at;
    int            lowprio, kick, kicked;
    /* LZ: lazy-fetch per-peer score (local only) */
    int            lz_inflight;
    unsigned       lz_ok, lz_fail, lz_bad, lz_stale;
    int64_t        lz_backoff_ms;
} Peer;

typedef struct {
    uint8_t blob[SP_STATE_OP_MAX];
    int     len;
    time_t  expiry;
} Held;

#define COUNTERS(X) \
    X(ae_names) X(ann_coalesced) X(ann_open) X(ring_skip) X(pull_dedup) X(pull_timeout) \
    X(pull_full) X(defer_name) X(defer_rec) X(get_queued) X(get_shed) X(out_wait) \
    X(ann_ovf) X(ann_ovf_drop) X(pull_ovf) X(pull_ovf_drop) X(bk_ovf) \
    X(relay) X(relay_l0) X(relay_l1) X(relay_l2) X(relay_l3) X(relay_l4) \
    X(credit_wait) X(nr_evict) X(nr_evict_young) X(get_hi) X(inv_wait) X(drain_wait) \
    X(zdat_ops) X(l5_skip) X(admit_calls) X(admit_new) X(admit_dup) X(batch) X(batch_fail) \
    X(in_drop) X(useless) X(useful) X(lowprio) X(kick) X(peer_capped) \
    X(lz_fetch) X(lz_ask) X(lz_ok) X(lz_fail) X(lz_forged) X(lz_stale) X(lz_timeout) X(lz_evict) \
    X(lz_inv_skip) X(lz_dat_skip)

static struct {
    SpState      *st;
    SpChainOracle o;
    int           verbose;
    Peer          peers[MAX_PEERS];
    Held          hold[HOLD_SLOTS];
    time_t        next_ae;
    time_t        last_scan;
    int64_t       last_pull_ms; int pull_kick;
    int (*senior)(const char *name);         /* kept for API compatibility (P10 -> L2 lanes) */
    uint64_t      ann_head[LANES];
    uint32_t      blk;                       /* L2: monotonic max-seen tip height */
    int           min_wait_lane;             /* L3: best lane still waiting for a peer */
    int           lazy;                      /* LZ: lazy (namespace-only) mode */
    struct {                                  /* counters for the 10-min line */
#define X(n) unsigned long n;
        COUNTERS(X)
#undef X
    } c, c_logged;
    time_t        next_log;
} g;

/* settings that survive dnsnet_init (set by the host before or after it) */
static int g_credit_blocks = DNSNET_CREDIT_BLOCKS;
static int g_peer_cap = MAX_PEERS;
static struct {
    size_t (*pending)(void *peer);
    void   (*drop)(void *peer, const char *why);
    int    (*is_local)(void *peer);
} g_tr;
static uint32_t g_gen;

/* big tables live outside g: dnsnet_init resets their indices, never the
 * contents, so a (test) re-init stays cheap */
static struct { char name[SP_NAME_MAX + 1]; uint8_t dg[32]; } g_ring[LANES][RING];
static char g_sq[MAX_PEERS][SQ_CAP][SP_NAME_MAX + 1];
static char g_sqh[MAX_PEERS][SQH_CAP][SP_NAME_MAX + 1];
typedef struct { char name[SP_NAME_MAX + 1]; } AnnSlot;     /* a name owed one relay */
static AnnSlot g_ann[ANN_SLOTS];
typedef struct { uint32_t tag, relay_h, refill_h; uint8_t tok, flags; uint16_t pad; } NameRec;   /* pad = L2 phase hash */
static NameRec g_nr[NR_SETS][NR_WAYS];
typedef struct {
    char    name[SP_NAME_MAX + 1];
    Peer   *inflight; time_t sent_at; time_t not_before;
    int     lane, fresh; int64_t wait_ms;
    int     nalt; struct { Peer *p; uint8_t dg[32]; int force; } alt[PULL_ALTS];
} PullSlot;
static PullSlot g_pull[PULL_SLOTS];
static int g_pidx[PULL_SLOTS];
typedef struct { uint64_t tag; int64_t tok, ms; } Bucket;
static Bucket g_nb[BK_SLOTS], g_rb[BK_SLOTS], g_nb_ovf, g_rb_ovf;
static uint64_t g_seed, g_rng;
static uint8_t  g_phase_key[16];            /* L2 stagger: SipHash key, per process */
static uint16_t name_phase_hash(const char *name);
/* L1 overflow FIFOs: [0] high lane, [1] low lane */
static struct { char name[SP_NAME_MAX + 1]; } g_aovf[2][ANN_OVF];
static int g_aovf_head[2], g_aovf_n[2];
typedef struct { char name[SP_NAME_MAX + 1]; int pi; uint32_t gen; uint8_t dg[32]; int fresh; } PullOvf;
static PullOvf g_povf[2][PULL_OVF];
static int g_povf_head[2], g_povf_n[2];

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
static uint64_t rnd64(void) {                 /* xorshift64*, seeded per process */
    g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27;
    return g_rng * 2685821657736338717ULL;
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

static int  lz_adopt_cb(void *u, const char *name);
static void lz_evict(void);
void dnsnet_init(SpState *st, SpChainOracle oracle, int verbose) {
    memset(&g, 0, sizeof g);
#if DNSNET_RL_SLOTS > 0
    memset(rl_last, 0, sizeof rl_last);
    rl_reseed();
#endif
    if (getentropy(&g_seed, sizeof g_seed) != 0)
        g_seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    g_rng = g_seed ^ 0x9E3779B97F4A7C15ULL; if (!g_rng) g_rng = 1;
    if (getentropy(g_phase_key, sizeof g_phase_key) != 0)     /* L2 stagger key */
        for (int i = 0; i < 16; i++) g_phase_key[i] = (uint8_t)(g_seed >> (8 * (i & 7))) ^ (uint8_t)(i * 0x9D);
    for (int i = 0; i < ANN_SLOTS; i++) g_ann[i].name[0] = '\0';
    for (int i = 0; i < PULL_SLOTS; i++) g_pull[i].name[0] = '\0';
    for (int i = 0; i < BK_SLOTS; i++) { g_nb[i].tag = 0; g_rb[i].tag = 0; }
    memset(&g_nb_ovf, 0, sizeof g_nb_ovf); memset(&g_rb_ovf, 0, sizeof g_rb_ovf);
    memset(g_nr, 0, sizeof g_nr);
    g_aovf_head[0] = g_aovf_head[1] = g_aovf_n[0] = g_aovf_n[1] = 0;
    g_povf_head[0] = g_povf_head[1] = g_povf_n[0] = g_povf_n[1] = 0;
    g.st = st; g.o = oracle; g.verbose = verbose;
    g.min_wait_lane = LANES;
    g.blk = g.o.tip ? g.o.tip(g.o.u) : 0;     /* L2: restart = every name at its burst */
    g.next_log = time(NULL) + 600;
    dns_state_cache_attach(st);               /* L10 */
    g.lazy = dns_lazy_enabled();
    if (g.lazy) {                             /* LZ: a restart keeps its cache */
        sp_state_names(st, lz_adopt_cb, NULL);
        lz_evict();
    }
}

void dnsnet_set_seniority(int (*fn)(const char *name)) { g.senior = fn; }

int dnsnet_credit_phase(const char *name) {     /* L2 stagger (tests, status) */
    return (int)((uint32_t)name_phase_hash(name) % (uint32_t)g_credit_blocks);
}
void dnsnet_set_credit_blocks(int blocks) {
    if (blocks < 1) blocks = 1;
    if (blocks > 1440) blocks = 1440;            /* = dnsd --relay-credit-blocks range */
    g_credit_blocks = blocks;
}
void dnsnet_set_peer_cap(int cap) {
    if (cap < 1) cap = 1;
    if (cap > MAX_PEERS) cap = MAX_PEERS;
    g_peer_cap = cap;
}
int dnsnet_peer_cap_for_uplink(double mbit) {
    if (!(mbit > 0)) return MAX_PEERS;
    /* one saturated link = P6 = 65,536 B/s = 0.524 Mbit/s each way */
    double per = (double)DNSNET_OUT_RATE * 8.0 / 1e6;
    int cap = (int)(mbit / per);
    if (cap < 2) cap = 2;
    if (cap > MAX_PEERS) cap = MAX_PEERS;
    return cap;
}
void dnsnet_set_transport(size_t (*pending)(void *peer), void (*drop)(void *peer, const char *why),
                          int (*is_local)(void *peer)) {
    g_tr.pending = pending; g_tr.drop = drop; g_tr.is_local = is_local;
}
unsigned long dnsnet_counter(const char *name) {
#define X(n) if (!strcmp(name, #n)) return g.c.n;
    COUNTERS(X)
#undef X
    if (!strcmp(name, "blk")) return g.blk;
    return 0;
}

int dnsnet_peers(void) {
    int n = 0;
    for (int i = 0; i < MAX_PEERS; i++) if (g.peers[i].used) n++;
    return n;
}

/* ── L2: block height, per-name credit, stale-first lanes ───────────────────── */
/* The ONLY height credit ever sees: the max tip seen so far. A lower tip (reorg
 * down, flapping, a lagging oracle) or the same height with another hash
 * changes nothing; credit is minted only for heights never seen before. */
static void blk_observe(void) {
    if (!g.o.tip) return;
    uint32_t t = g.o.tip(g.o.u);
    if (t > g.blk) g.blk = t;
}
static uint32_t lane_floor(int lane) {        /* min quiet blocks for lanes 0..3 */
    uint32_t cb = (uint32_t)g_credit_blocks;
    uint32_t t3 = cb, t2 = 4 * cb > t3 + 1 ? 4 * cb : t3 + 1;
    uint32_t t1 = 144 > t2 + 1 ? 144 : t2 + 1, t0 = 1440 > t1 + 1 ? 1440 : t1 + 1;
    switch (lane) { case 0: return t0; case 1: return t1; case 2: return t2; default: return t3; }
}
static int lane_of(const NameRec *r) {
    if (!r || !(r->flags & NR_RELAYED)) return 0;           /* never relayed here: quietest */
    uint32_t q = g.blk >= r->relay_h ? g.blk - r->relay_h : 0;
    for (int l = 0; l < LANES - 1; l++) if (q >= lane_floor(l)) return l;
    return LANES - 1;
}
/* L2 stagger: SipHash-2-4 of the name under a per-process random key (drawn in
 * dnsnet_init), so a remote party cannot grind names onto one refill phase */
#define SIP_ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIP_ROUND do { v0 += v1; v1 = SIP_ROTL(v1, 13); v1 ^= v0; v0 = SIP_ROTL(v0, 32); \
                       v2 += v3; v3 = SIP_ROTL(v3, 16); v3 ^= v2; \
                       v0 += v3; v3 = SIP_ROTL(v3, 21); v3 ^= v0; \
                       v2 += v1; v1 = SIP_ROTL(v1, 17); v1 ^= v2; v2 = SIP_ROTL(v2, 32); } while (0)
static uint64_t sip_le64(const uint8_t *p) {
    uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v;
}
static uint64_t siphash24(const uint8_t k[16], const uint8_t *m, size_t n) {
    uint64_t k0 = sip_le64(k), k1 = sip_le64(k + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    size_t end = n - (n % 8);
    for (size_t i = 0; i < end; i += 8) { uint64_t mi = sip_le64(m + i); v3 ^= mi; SIP_ROUND; SIP_ROUND; v0 ^= mi; }
    uint64_t b = (uint64_t)n << 56;
    for (size_t i = 0; i < n % 8; i++) b |= (uint64_t)m[end + i] << (8 * i);
    v3 ^= b; SIP_ROUND; SIP_ROUND; v0 ^= b;
    v2 ^= 0xff; SIP_ROUND; SIP_ROUND; SIP_ROUND; SIP_ROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
static uint16_t name_phase_hash(const char *name) {
    return (uint16_t)(siphash24(g_phase_key, (const uint8_t *)name, strlen(name)) & 0xffff);
}
/* the refill heights of a name: h with h % credit_blocks == phase */
static uint32_t nr_phase(const NameRec *r) { return (uint32_t)r->pad % (uint32_t)g_credit_blocks; }
/* how many refill heights lie in (0, x] for this phase (shifted, no negatives) */
static uint32_t phase_hits_upto(uint32_t x, uint32_t ph) {
    return (uint32_t)(((uint64_t)x + (uint32_t)g_credit_blocks - ph) / (uint32_t)g_credit_blocks);
}
static void nr_refill(NameRec *r);
static NameRec *nr_find(const char *name, int create) {
    uint64_t h = hname(name, NULL, 0);
    uint32_t tag = (uint32_t)(h >> 32) | 1u;
    NameRec *w = g_nr[h & (NR_SETS - 1)], *v = NULL;
    for (int i = 0; i < NR_WAYS; i++) if (w[i].tag == tag) return &w[i];
    if (!create) return NULL;
    for (int i = 0; i < NR_WAYS && !v; i++) if (!w[i].tag) v = &w[i];
    if (!v) {                                    /* evict the quietest (least information lost) */
        for (int i = 0; i < NR_WAYS; i++) {
            if (w[i].flags & NR_IN_OVF) continue;
            if (!v || lane_of(&w[i]) < lane_of(v) ||
                (lane_of(&w[i]) == lane_of(v) && w[i].relay_h < v->relay_h)) v = &w[i];
        }
        if (!v) v = &w[0];
        g.c.nr_evict++;
        if (lane_of(v) > 0) {
            /* the victim relayed within the last lane-0 window: the newcomer
             * INHERITS its (refilled) credit, refill height and lane, so
             * cycling > NR_WAYS names through one set can never mint credit
             * (no fail-open under eviction); a quiet victim's credit was full
             * anyway */
            g.c.nr_evict_young++;
            nr_refill(v);
            v->tag = tag; v->flags &= NR_RELAYED; v->pad = name_phase_hash(name);
            return v;
        }
    }
    v->tag = tag; v->tok = DNSNET_CREDIT_BURST; v->refill_h = g.blk; v->relay_h = 0; v->flags = 0;
    v->pad = name_phase_hash(name);
    return v;
}
/* STAGGERED refill: a name gains one credit on each height h with
 * h % credit_blocks == its phase (keyed hash of the name), so names refill on
 * different blocks instead of all together. New credits = the phase heights
 * crossed in (refill_h, max_seen] (several on a multi-block jump), capped at
 * the burst; refill_h = the last height accounted, only ever moves forward. */
static void nr_refill(NameRec *r) {
    if (g.blk <= r->refill_h) return;                     /* stalled / reorged: nothing */
    uint32_t ph = nr_phase(r);
    uint32_t add = phase_hits_upto(g.blk, ph) - phase_hits_upto(r->refill_h, ph);
    r->refill_h = g.blk;
    if (!add) return;
    r->tok = (uint32_t)r->tok + add >= DNSNET_CREDIT_BURST ? DNSNET_CREDIT_BURST : (uint8_t)(r->tok + add);
}
static int name_lane(const char *name) { return lane_of(nr_find(name, 0)); }

/* ── P6 (split by L4) + L7 drain: every dn* byte we send a peer is debited ──── */
#define INV_RATE   ((int64_t)DNSNET_OUT_RATE  * DNSNET_INV_PCT / 100)
#define INV_BURST  ((int64_t)DNSNET_OUT_BURST * DNSNET_INV_PCT / 100)
#define DAT_RATE   ((int64_t)DNSNET_OUT_RATE  - INV_RATE)
#define DAT_BURST  ((int64_t)DNSNET_OUT_BURST - INV_BURST)
static int drained(Peer *p, int64_t now) {      /* L7: refill tracks real socket drain */
    if (!g_tr.pending || g_tr.pending(p->peer) <= DNSNET_DRAIN_MAX) return 1;
    if (p->out_ms) p->out_ms = now;             /* nothing accrues while it is not reading */
    if (p->inv_ms) p->inv_ms = now;
    g.c.drain_wait++;
    return 0;
}
static int out_room(Peer *p, int64_t n) {       /* dumps + zgets: 75% */
    int64_t now = now_ms();
    if (!drained(p, now)) return 0;
    refill(&p->out_tok, &p->out_ms, DAT_BURST, DAT_RATE, 1000, now);
    return p->out_tok >= n;
}
static int inv_room(Peer *p, int64_t n) {       /* dnzinv: 25% */
    int64_t now = now_ms();
    if (!drained(p, now)) return 0;
    refill(&p->inv_tok, &p->inv_ms, INV_BURST, INV_RATE, 1000, now);
    if (p->inv_tok >= n) return 1;
    g.c.inv_wait++;
    return 0;
}
static void psend(Peer *p, const char *cmd, const uint8_t *pay, size_t n) {
    if (!p->used) return;
    if (!strcmp(cmd, "dnzinv")) p->inv_tok -= (int64_t)n + 24;
    else                        p->out_tok -= (int64_t)n + 24;
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
 * so a store smaller than a page is offered whole, exactly as before. (L8: the
 * cursor starts at a random point per link, see dnsnet_up.) */
typedef struct { InvAcc *a; Peer *p; int left, stop, wrapped; char start[SP_NAME_MAX + 1]; } PageAcc;
static int page_cb(void *u, const char *name) {
    PageAcc *pa = u;
    if (pa->left <= 0) return 0;
    if (pa->wrapped && pa->start[0] && strcmp(name, pa->start) > 0) { pa->left = 0; return 0; }
    /* room for a whole frame before we start one (never tear the page) */
    if (pa->a->count == 0 && !inv_room(pa->p, INV_FRAME)) {
        pa->stop = 1; g.c.out_wait++; return 0;
    }
    /* LZ: a lazy node offers only its own (pinned) names: its cache is the
     * user's browsing, and every full peer already holds those zones */
    if (!g.lazy || dns_lazy_pinned(name)) inv_add(pa->a, name);
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

/* ── P1/L2: per-name relay credit + the shared, laned announce log ──────────── */
/* flush lanes [lo, hi] for one peer, lowest lane first; a lane with backlog
 * that cannot be flushed (no L4 room) blocks the lanes after it */
static int ring_flush_lanes(Peer *p, int lo, int hi) {
    for (int r = lo; r <= hi; r++) {
        while (p->used && p->ann_seq[r] < g.ann_head[r]) {
            if (g.ann_head[r] - p->ann_seq[r] > RING) {   /* fell a whole ring behind */
                g.c.ring_skip += g.ann_head[r] - p->ann_seq[r] - RING;
                p->ann_seq[r] = g.ann_head[r] - RING;
            }
            if (!inv_room(p, INV_FRAME)) { g.c.out_wait++; return 0; }
            static InvAcc a;
            a.off = 0; a.count = 0; a.to = p;
            while (p->ann_seq[r] < g.ann_head[r] && a.count < INV_BATCH - 1) {
                uint64_t s = p->ann_seq[r]++;
                inv_add_dg(&a, g_ring[r][s % RING].name, g_ring[r][s % RING].dg);
            }
            inv_flush(&a);
        }
    }
    return 1;
}
static void ring_flush_peer(Peer *p) { ring_flush_lanes(p, 0, LANES - 1); }
static void ring_flush_all(void) {
    for (int i = 0; i < MAX_PEERS; i++) if (g.peers[i].used) ring_flush_peer(&g.peers[i]);
}
static void ring_append(const char *name, int r) {
    uint64_t s = g.ann_head[r]++;
    snprintf(g_ring[r][s % RING].name, sizeof g_ring[r][0].name, "%s", name);
    dns_state_digest(g.st, name, g_ring[r][s % RING].dg);   /* the newest set, now */
}
/* spend one credit: the lane is how long the name had been quiet */
static void relay_now(const char *name, NameRec *r) {
    int lane = lane_of(r);
    r->tok--; r->relay_h = g.blk; r->flags |= NR_RELAYED;
    ring_append(name, lane);
    g.c.relay++;
    switch (lane) {
        case 0: g.c.relay_l0++; break; case 1: g.c.relay_l1++; break; case 2: g.c.relay_l2++; break;
        case 3: g.c.relay_l3++; break; default: g.c.relay_l4++; break;
    }
}

static AnnSlot *ann_find(const char *name, int create) {
    uint64_t h = hname(name, NULL, 0);
    AnnSlot *fr = NULL;
    for (int i = 0; i < ANN_PROBE; i++) {
        AnnSlot *s = &g_ann[(h + (uint64_t)i) % ANN_SLOTS];
        if (s->name[0] && !strcmp(s->name, name)) return s;
        if (!s->name[0] && !fr) fr = s;
    }
    if (!create || !fr) return NULL;
    snprintf(fr->name, sizeof fr->name, "%s", name);
    return fr;
}
/* L1: the announce table is full -> a bounded two-lane FIFO (never unthrottled;
 * beyond it the name is left to anti-entropy, which re-offers every name) */
static int aovf_push(int lane, const char *name, int front) {
    int q = lane <= LANE_HI ? 0 : 1;
    if (g_aovf_n[q] >= ANN_OVF) return 0;
    int k;
    if (front) { g_aovf_head[q] = (g_aovf_head[q] + ANN_OVF - 1) % ANN_OVF; k = g_aovf_head[q]; }
    else k = (g_aovf_head[q] + g_aovf_n[q]) % ANN_OVF;
    snprintf(g_aovf[q][k].name, SP_NAME_MAX + 1, "%s", name);
    g_aovf_n[q]++;
    return 1;
}

void dnsnet_announce(const char *name) {
    size_t nl = name ? strlen(name) : 0;
    if (nl < 1 || nl > SP_NAME_MAX) return;
    blk_observe();
    NameRec *r = nr_find(name, 1);
    nr_refill(r);
    AnnSlot *s = ann_find(name, 0);
    if (r->tok >= 1) {                             /* credit: relay now */
        if (s) s->name[0] = '\0';
        relay_now(name, r);
        ring_flush_all();
        return;
    }
    g.c.credit_wait++;
    if (s || (r->flags & NR_IN_OVF)) return;       /* already owed one relay (P1) */
    if (ann_find(name, 1)) { g.c.ann_coalesced++; return; }   /* relayed as the newest set on refill */
    g.c.ann_open++;                                 /* table full (was: unthrottled relay) */
    if (aovf_push(lane_of(r), name, 0)) { r->flags |= NR_IN_OVF; g.c.ann_ovf++; }
    else g.c.ann_ovf_drop++;
}

typedef struct { int idx; int lane; uint32_t relay_h; } AnnCand;
static int ann_cmp(const void *a, const void *b) {
    const AnnCand *x = a, *y = b;
    if (x->lane != y->lane) return x->lane - y->lane;             /* stale-first */
    return x->relay_h < y->relay_h ? -1 : x->relay_h > y->relay_h;
}
static void ann_service(void) {
    static AnnCand cand[ANN_SLOTS];
    int n = 0, any = 0;
    for (int i = 0; i < ANN_SLOTS; i++) {
        if (!g_ann[i].name[0]) continue;
        NameRec *r = nr_find(g_ann[i].name, 1);
        nr_refill(r);
        if (r->tok < 1) continue;
        cand[n].idx = i; cand[n].lane = lane_of(r); cand[n].relay_h = r->relay_h; n++;
    }
    if (n > 1) qsort(cand, (size_t)n, sizeof cand[0], ann_cmp);
    for (int k = 0; k < n; k++) {
        AnnSlot *s = &g_ann[cand[k].idx];
        NameRec *r = nr_find(s->name, 1);
        if (r->tok >= 1) { relay_now(s->name, r); any = 1; }
        s->name[0] = '\0';
    }
    /* L1 overflow: each queued name once per pass, high lane first */
    for (int q = 0; q < 2; q++) {
        int cnt = g_aovf_n[q];
        for (int k = 0; k < cnt; k++) {
            char nm[SP_NAME_MAX + 1];
            snprintf(nm, sizeof nm, "%s", g_aovf[q][g_aovf_head[q]].name);
            g_aovf_head[q] = (g_aovf_head[q] + 1) % ANN_OVF; g_aovf_n[q]--;
            NameRec *r = nr_find(nm, 1);
            r->flags &= (uint8_t)~NR_IN_OVF;
            nr_refill(r);
            if (r->tok >= 1) { relay_now(nm, r); any = 1; continue; }
            if (ann_find(nm, 1)) continue;                    /* a slot freed: wait there */
            if (aovf_push(q == 0 ? 0 : LANES - 1, nm, 0)) r->flags |= NR_IN_OVF;
            else g.c.ann_ovf_drop++;
        }
    }
    if (any) ring_flush_all();
}

static void send_inv_one(Peer *to, const char *name) {
    static InvAcc a;
    if (!inv_room(to, 24 + 8 + 1 + SP_NAME_MAX + 32)) { g.c.out_wait++; return; }
    a.off = 0; a.count = 0; a.to = to;
    inv_add(&a, name);
    inv_flush(&a);
}

/* ── P3 + L1/L3: pull table — one zget in flight per name, priority dispatch ─ */
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
    fr->lane = name_lane(name);
    fr->wait_ms = now_ms();
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
static void alt_drop(PullSlot *s, int i) {
    memmove(&s->alt[i], &s->alt[i + 1], sizeof s->alt[0] * (size_t)(s->nalt - i - 1)); s->nalt--;
}
/* try to put one zget for this slot on the wire; frees it when nobody differs.
 * L6: a deprioritised peer is asked only when no other advertiser can be. */
static void pull_dispatch(PullSlot *s, time_t now) {
    if (!s->name[0] || s->inflight || now < s->not_before) return;
    uint8_t ours[32]; int have_ours = 0;
    for (int i = 0; i < s->nalt; ) {
        Peer *p = s->alt[i].p;
        if (!p || !p->used) { alt_drop(s, i); continue; }
        if (!s->alt[i].force) {
            if (!have_ours) { dns_state_digest(g.st, s->name, ours); have_ours = 1; }
            if (!memcmp(ours, s->alt[i].dg, 32)) { alt_drop(s, i); continue; }   /* converged with it */
        }
        i++;
    }
    for (int pass = 0; pass < 2; pass++)
        for (int i = 0; i < s->nalt; i++) {
            Peer *p = s->alt[i].p;
            if (pass == 0 && p->lowprio) continue;
            if (p->inflight >= DNSNET_PULL_PER_PEER || !out_room(p, 24 + 1 + SP_NAME_MAX)) continue;
            send_zget(p, s->name);
            p->inflight++;
            s->inflight = p; s->sent_at = now;
            alt_drop(s, i);
            return;
        }
    if (!s->nalt) pull_free(s);
}
/* L1: the pull table is full -> a bounded two-lane FIFO (was: a direct zget
 * that bypassed P3); beyond it, anti-entropy re-offers the name */
static int povf_push(int q, const PullOvf *e, int front) {
    if (g_povf_n[q] >= PULL_OVF) return 0;
    int k;
    if (front) { g_povf_head[q] = (g_povf_head[q] + PULL_OVF - 1) % PULL_OVF; k = g_povf_head[q]; }
    else k = (g_povf_head[q] + g_povf_n[q]) % PULL_OVF;
    g_povf[q][k] = *e;
    g_povf_n[q]++;
    return 1;
}
/* fresh = learned from a small dnzinv frame (a live relay, not an AE page):
 * pulled first within its lane, and queued at the FRONT of the bounded
 * overflow FIFO, so a live change is not stuck behind a bulk catch-up */
/* a live pull found its probe window full: move one waiting (not in flight)
 * AE pull from that window to the back of the bounded overflow FIFO */
static PullSlot *pull_bump(const char *name) {
    uint64_t h = hname(name, NULL, 0);
    for (int i = 0; i < PULL_PROBE; i++) {
        PullSlot *v = &g_pull[(h + (uint64_t)i) % PULL_SLOTS];
        if (!v->name[0] || v->inflight || v->fresh || v->nalt < 1) continue;
        PullOvf e; memset(&e, 0, sizeof e);
        Peer *p = v->alt[v->nalt - 1].p;
        snprintf(e.name, sizeof e.name, "%s", v->name);
        e.pi = (int)(p - g.peers); e.gen = p->gen; memcpy(e.dg, v->alt[v->nalt - 1].dg, 32);
        if (povf_push(v->lane <= LANE_HI ? 0 : 1, &e, 0)) g.c.pull_ovf++;
        else g.c.pull_ovf_drop++;                  /* AE re-offers it later */
        pull_free(v);
        return pull_find(name, 1);
    }
    return NULL;
}
static void pull_want(Peer *from, const char *name, const uint8_t their[32], time_t now, int fresh) {
    PullSlot *s = pull_find(name, 1);
    if (!s && fresh) s = pull_bump(name);
    if (!s) {
        g.c.pull_full++;
        PullOvf e; memset(&e, 0, sizeof e);
        snprintf(e.name, sizeof e.name, "%s", name);
        e.pi = (int)(from - g.peers); e.gen = from->gen; memcpy(e.dg, their, 32); e.fresh = fresh;
        if (povf_push(name_lane(name) <= LANE_HI ? 0 : 1, &e, fresh)) g.c.pull_ovf++;
        else g.c.pull_ovf_drop++;
        return;
    }
    if (s->inflight) g.c.pull_dedup++;
    if (fresh) s->fresh = 1;
    pull_alt(s, from, their, 0);
    if (s->lane <= g.min_wait_lane) pull_dispatch(s, now);   /* L3: never ahead of a better lane */
    else g.pull_kick = 1;
}
/* a dump for `name` arrived from `from` (solicited or not) */
static void pull_done(Peer *from, const char *name, int deferred, time_t now, time_t retry_at) {
    PullSlot *s = pull_find(name, deferred);
    if (!s) return;
    if (s->inflight == from) { s->inflight = NULL; if (from->inflight > 0) from->inflight--; g.pull_kick = 1; }
    if (deferred) { pull_alt(s, from, NULL, 1); if (retry_at > s->not_before) s->not_before = retry_at; }
    if (!s->inflight && s->lane <= g.min_wait_lane) pull_dispatch(s, now);
}
static void povf_service(time_t now) {
    for (int q = 0; q < 2; q++) {
        int budget = 256;
        while (g_povf_n[q] > 0 && budget-- > 0) {
            PullOvf e = g_povf[q][g_povf_head[q]];
            g_povf_head[q] = (g_povf_head[q] + 1) % PULL_OVF; g_povf_n[q]--;
            if (e.pi < 0 || e.pi >= MAX_PEERS) continue;
            Peer *p = &g.peers[e.pi];
            if (!p->used || p->gen != e.gen) continue;            /* its peer left */
            uint8_t ours[32]; dns_state_digest(g.st, e.name, ours);
            if (!memcmp(ours, e.dg, 32)) continue;                 /* converged meanwhile */
            PullSlot *s = pull_find(e.name, 1);
            if (!s) { povf_push(q, &e, 1); break; }               /* still full: keep its place */
            if (e.fresh) s->fresh = 1;
            pull_alt(s, p, e.dg, 0);
        }
    }
    (void)now;
}
static int pull_cmp(const void *a, const void *b) {
    const PullSlot *x = &g_pull[*(const int *)a], *y = &g_pull[*(const int *)b];
    if (x->lane != y->lane) return x->lane - y->lane;
    if (x->fresh != y->fresh) return y->fresh - x->fresh;          /* live relays first */
    return x->wait_ms < y->wait_ms ? -1 : x->wait_ms > y->wait_ms;
}
static void pull_service(time_t now) {
    int n = 0;
    for (int i = 0; i < PULL_SLOTS; i++) {
        PullSlot *s = &g_pull[i];
        if (!s->name[0]) continue;
        if (s->inflight && now - s->sent_at >= DNSNET_PULL_TIMEOUT_S) {
            g.c.pull_timeout++;
            if (s->inflight->inflight > 0) s->inflight->inflight--;
            s->inflight = NULL;
            if (!s->nalt) { pull_free(s); continue; }
        }
    }
    povf_service(now);
    for (int i = 0; i < PULL_SLOTS; i++) {
        PullSlot *s = &g_pull[i];
        if (s->name[0] && !s->inflight && now >= s->not_before) g_pidx[n++] = i;
    }
    if (n > 1) qsort(g_pidx, (size_t)n, sizeof g_pidx[0], pull_cmp);   /* L3: lane, then age */
    int best = LANES;
    for (int k = 0; k < n; k++) {
        PullSlot *s = &g_pull[g_pidx[k]];
        pull_dispatch(s, now);
        if (s->name[0] && !s->inflight && s->nalt && s->lane < best) best = s->lane;
    }
    g.min_wait_lane = best;
}

/* ── P4: admission buckets (defer, never reject for good) ───────────────────── */
/* L1: every probed slot busy -> the table's ONE shared overflow bucket (was:
 * no limit at all). Bounded at DNSNET_BK_OVF_MULT names' worth. */
static Bucket *bucket(Bucket *t, Bucket *ovf, uint64_t tag, int64_t burst, int64_t rate, int64_t per_ms, int64_t now) {
    Bucket *fr = NULL;
    for (int i = 0; i < BK_PROBE; i++) {
        Bucket *b = &t[(tag + (uint64_t)i * 0x9E3779B97F4A7C15ULL) % BK_SLOTS];
        if (b->tag == tag) { refill(&b->tok, &b->ms, burst, rate, per_ms, now); return b; }
        if (!fr) {
            if (!b->tag) fr = b;
            else { refill(&b->tok, &b->ms, burst, rate, per_ms, now); if (b->tok >= burst) fr = b; }
        }
    }
    if (!fr) {
        g.c.bk_ovf++;
        refill(&ovf->tok, &ovf->ms, burst * DNSNET_BK_OVF_MULT, rate * DNSNET_BK_OVF_MULT, per_ms, now);
        return ovf;
    }
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
    Bucket *nb = bucket(g_nb, &g_nb_ovf, hname(name, NULL, 0), DNSNET_NAME_BURST, DNSNET_NAME_RATE_MIN, 60000, now);
    Bucket *rb = p->op == SP_OP_CLEAR ? NULL
               : bucket(g_rb, &g_rb_ovf, hname(name, p->key, p->key_len), DNSNET_REC_BURST, 1, DNSNET_REC_REFILL_MS, now);
    int name_ok = nb->tok > 0, rec_ok = !rb || rb->tok >= 1;
    if (name_ok && rec_ok) return 1;
    if (!op_is_new(name, p)) return 1;          /* a dup: free (admit returns -1) */
    int64_t nrate = nb == &g_nb_ovf ? DNSNET_NAME_RATE_MIN * DNSNET_BK_OVF_MULT : DNSNET_NAME_RATE_MIN;
    if (!name_ok) { g.c.defer_name++; *retry_at = time(NULL) + 1 + (time_t)((-nb->tok + 1) * 60 / nrate); }
    else          { g.c.defer_rec++;  *retry_at = time(NULL) + 1 + DNSNET_REC_REFILL_MS / 1000; }
    (void)len;
    return 0;
}
static void admit_debit(const char *name, const SpStateOp *p, int len) {
    int64_t now = now_ms();
    Bucket *nb = bucket(g_nb, &g_nb_ovf, hname(name, NULL, 0), DNSNET_NAME_BURST, DNSNET_NAME_RATE_MIN, 60000, now);
    nb->tok -= len;
    if (p->op != SP_OP_CLEAR) {
        Bucket *rb = bucket(g_rb, &g_rb_ovf, hname(name, p->key, p->key_len), DNSNET_REC_BURST, 1, DNSNET_REC_REFILL_MS, now);
        rb->tok -= 1;
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
            if (!g.lazy || dns_lazy_pinned(name)) dnsnet_announce(name);
            if (g.lazy) dns_lazy_bytes(name, sp_state_sum(g.st, name));
        }
        g.hold[i].len = 0;                  /* admitted / rejected / dup — done */
    }
}

/* ── P7 + L3: zget answers, paced per peer; quiet names in a high lane ──────── */
static int sq_push(Peer *p, const char *name) {
    int slot = (int)(p - g.peers);
    int hi = name_lane(name) <= LANE_HI;
    for (int i = 0, k = p->sqh_head; i < p->sqh_n; i++, k = (k + 1) % SQH_CAP)
        if (i >= p->sqh_n - 8 && !strcmp(g_sqh[slot][k], name)) return 1;   /* recent dup */
    for (int i = 0, k = p->sq_head; i < p->sq_n; i++, k = (k + 1) % SQ_CAP)
        if (i >= p->sq_n - 8 && !strcmp(g_sq[slot][k], name)) return 1;
    if (hi && p->sqh_n < SQH_CAP) {
        snprintf(g_sqh[slot][(p->sqh_head + p->sqh_n) % SQH_CAP], SP_NAME_MAX + 1, "%s", name);
        p->sqh_n++; g.c.get_hi++;
        return 1;
    }
    if (p->sq_n >= SQ_CAP) return 0;
    snprintf(g_sq[slot][(p->sq_head + p->sq_n) % SQ_CAP], SP_NAME_MAX + 1, "%s", name);
    p->sq_n++;
    return 1;
}
static void sq_service(Peer *p) {
    int slot = (int)(p - g.peers);
    while (p->used && (p->sqh_n > 0 || p->sq_n > 0)) {
        refill(&p->get_tok, &p->get_ms, DNSNET_GET_BURST, DNSNET_GET_RATE, 1000, now_ms());
        if (p->get_tok < 1) return;
        if (p->sqh_n > 0) {
            if (!send_zdat(p, g_sqh[slot][p->sqh_head])) { g.c.out_wait++; return; }
            p->sqh_head = (p->sqh_head + 1) % SQH_CAP; p->sqh_n--;
        } else {
            if (!send_zdat(p, g_sq[slot][p->sq_head])) { g.c.out_wait++; return; }
            p->sq_head = (p->sq_head + 1) % SQ_CAP; p->sq_n--;
        }
        p->get_tok--;
    }
}

/* ── L6: usefulness of what a peer sends us ──────────────────────────────────── */
static void use_note(Peer *p, int useful) {
    time_t now = time(NULL);
    if (!p->use_half_at) p->use_half_at = now + DNSNET_USE_HALF_S;
    while (now >= p->use_half_at) { p->good /= 2; p->bad /= 2; p->use_half_at += DNSNET_USE_HALF_S; }
    if (useful > 0) { p->good++; g.c.useful++; }
    else if (useful < 0) { p->bad++; g.c.useless++; }
    int low = p->bad >= DNSNET_LOW_BAD && p->bad > (unsigned)DNSNET_LOW_RATIO * p->good;
    if (low && !p->lowprio) g.c.lowprio++;
    p->lowprio = low;
    if (!p->kick && p->bad >= DNSNET_KICK_BAD && p->bad > (unsigned)DNSNET_KICK_RATIO * p->good &&
        g_tr.drop && !(g_tr.is_local && g_tr.is_local(p->peer)))
        p->kick = 1;                                   /* acted on in dnsnet_tick */
}

/* ── LZ: lazy (namespace-only) mode — on-demand zone fetch ───────────────────
 * A query for an owned name whose zone we do not hold queues a fetch
 * (dns_lazy.c). Here, on the net thread, a fetch asks LZ_FANOUT peers with the
 * EXISTING dnzget (the same frame a full node's pull sends; an old node
 * answers it with its dnzdat exactly as it answers any pull, an empty dump if
 * it holds nothing). The answer is admitted by the unchanged on_zdat path, so
 * every op passes sp_state_admit: signature by the namespace's CURRENT owner
 * (lease-gated) or its §2.2 DNS_SCOPE hot key, the anchor's header hash on our
 * chain, the per-key anchor order and the 8 KB budget. Forged ops never land.
 *
 * Freshness/withholding: there is no zone commitment on chain (gap G3), so a
 * single peer can serve an OLD but validly signed set, or nothing. A fetch
 * therefore merges answers from up to LZ_QUORUM peers (LWW: the newest op per
 * key wins, so ONE honest peer among them is enough), and waits LZ_SETTLE_MS
 * after the first answer for the others. A peer whose answer differs from the
 * merged result (stale / withheld) gets a short backoff; a peer whose ops fail
 * verification gets an exponential one; a timeout asks the next peer.
 * Backoffs only order which peers we ask (we still ask a backed-off peer when
 * it is the only one left) — local policy, nothing on the wire, same spirit as
 * L6 (answers to our own requests are never scored as spam). */
#ifndef LZ_FANOUT
#define LZ_FANOUT        2        /* peers asked at once */
#endif
#ifndef LZ_QUORUM
#define LZ_QUORUM        2        /* agreeing-or-merged valid answers that end a fetch */
#endif
#ifndef LZ_ASK_MAX
#define LZ_ASK_MAX       6        /* peers one fetch may try */
#endif
#ifndef LZ_SLOTS
#define LZ_SLOTS         64       /* fetches in flight */
#endif
#ifndef LZ_PER_PEER
#define LZ_PER_PEER      16       /* lazy zgets in flight to one peer */
#endif
#ifndef LZ_ASK_TIMEOUT_MS
#define LZ_ASK_TIMEOUT_MS 2000    /* one peer's answer */
#endif
#ifndef LZ_SETTLE_MS
#define LZ_SETTLE_MS     600      /* after the first valid answer, wait this for the rest */
#endif
#ifndef LZ_FETCH_MAX_MS
#define LZ_FETCH_MAX_MS  8000     /* no valid answer by then: FAILED (retry later) */
#endif

typedef struct { uint8_t x[16]; uint32_t n; } LzSum;   /* order-free op-set sum */
static void lz_sum_add(LzSum *s, const uint8_t id[32]) {
    for (int i = 0; i < 16; i++) s->x[i] ^= id[i];
    s->n++;
}
enum { LZA_SENT = 1, LZA_OK, LZA_BAD, LZA_TIMEOUT };
typedef struct {
    char    name[SP_NAME_MAX + 1];
    int64_t start_ms, first_ok_ms;
    int     nask, ok_n;
    struct { Peer *p; uint32_t gen; int64_t sent_ms; int st; LzSum sum; } ask[LZ_ASK_MAX];
} LzFetch;
static LzFetch g_lz[LZ_SLOTS];

static int lz_adopt_cb(void *u, const char *name) {
    (void)u;
    dns_lazy_adopt(name, sp_state_sum(g.st, name));
    return 1;
}
static void lz_evict(void) {
    char v[64]; int r;
    while ((r = dns_lazy_evict_one(v)) != 0)
        if (r == 1) { sp_state_drop_name(g.st, v); g.c.lz_evict++; }
}
static LzFetch *lz_find(const char *name) {
    for (int i = 0; i < LZ_SLOTS; i++) if (g_lz[i].name[0] && !strcmp(g_lz[i].name, name)) return &g_lz[i];
    return NULL;
}
static int lz_outstanding(const LzFetch *f) {
    int k = 0;
    for (int i = 0; i < f->nask; i++) if (f->ask[i].st == LZA_SENT) k++;
    return k;
}
static int lz_asked(const LzFetch *f, const Peer *p) {
    for (int i = 0; i < f->nask; i++) if (f->ask[i].p == p && f->ask[i].gen == p->gen) return 1;
    return 0;
}
/* the best peer not yet asked for this fetch; NULL if none can take it now */
static Peer *lz_pick(const LzFetch *f, int64_t now) {
    Peer *best = NULL; int64_t bs = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer *p = &g.peers[i];
        if (!p->used || lz_asked(f, p) || p->lz_inflight >= LZ_PER_PEER) continue;
        if (!out_room(p, 24 + 1 + SP_NAME_MAX)) continue;
        int64_t sc = (int64_t)p->lz_bad * 64 + (int64_t)p->lz_fail * 8 + (int64_t)p->lz_stale * 2
                   + (p->lz_backoff_ms > now ? 1000000 : 0) + (p->lowprio ? 4096 : 0)
                   + (int64_t)p->lz_inflight;
        sc = sc * 16 + (int64_t)(rnd64() & 15);            /* random tie-break */
        if (!best || sc < bs) { best = p; bs = sc; }
    }
    return best;
}
static int lz_can_ask_more(const LzFetch *f, int64_t now) {
    return f->nask < LZ_ASK_MAX && lz_pick(f, now) != NULL;
}
static int lz_ask(LzFetch *f, int64_t now) {
    if (f->nask >= LZ_ASK_MAX) return 0;
    Peer *p = lz_pick(f, now);
    if (!p) return 0;
    send_zget(p, f->name);
    p->lz_inflight++; g.c.lz_ask++;
    f->ask[f->nask].p = p; f->ask[f->nask].gen = p->gen; f->ask[f->nask].sent_ms = now;
    f->ask[f->nask].st = LZA_SENT; memset(&f->ask[f->nask].sum, 0, sizeof f->ask[0].sum);
    f->nask++;
    return 1;
}
static void lz_backoff(Peer *p, int64_t base_ms, unsigned n, int64_t cap_ms, int64_t now) {
    int64_t b = base_ms;
    for (unsigned i = 1; i < n && b < cap_ms; i++) b *= 2;
    if (b > cap_ms) b = cap_ms;
    if (now + b > p->lz_backoff_ms) p->lz_backoff_ms = now + b;
}
/* the held op-set sum of a name (clear + rows), to judge each answer */
static int lz_held_cb(void *u, const uint8_t *key, int klen, int op, uint32_t anchor, const uint8_t *blob, int blen) {
    (void)key; (void)klen; (void)op; (void)anchor;
    SpStateOp p;
    if (sp_state_op_parse(blob, blen, &p)) lz_sum_add(u, p.op_id);
    return 1;
}
static void lz_held_sum(const char *name, LzSum *s) {
    memset(s, 0, sizeof *s);
    uint8_t *cb; int cl;
    if (sp_state_clear_get(g.st, name, &cb, &cl)) {
        SpStateOp p;
        if (sp_state_op_parse(cb, cl, &p)) lz_sum_add(s, p.op_id);
        free(cb);
    }
    sp_state_iter(g.st, name, lz_held_cb, s);
}
static void lz_finish(LzFetch *f, int ok, int64_t now) {
    if (ok) {
        LzSum held; lz_held_sum(f->name, &held);
        for (int i = 0; i < f->nask; i++) {
            Peer *p = f->ask[i].p;
            if (f->ask[i].st != LZA_OK || !p->used || p->gen != f->ask[i].gen) continue;
            if (memcmp(&f->ask[i].sum, &held, sizeof held)) {       /* behind / withheld */
                p->lz_stale++; g.c.lz_stale++;
                lz_backoff(p, 10000, 1, 10000, now);
            } else { p->lz_ok++; if (p->lz_fail) p->lz_fail--; }
        }
        int64_t bytes = sp_state_sum(g.st, f->name);
        dns_lazy_done(f->name, 1, bytes, held.n == 0);
        g.c.lz_ok++;
    } else {
        dns_lazy_done(f->name, 0, 0, 0);
        g.c.lz_fail++;
    }
    for (int i = 0; i < f->nask; i++)                       /* free the per-peer seats */
        if (f->ask[i].st == LZA_SENT && f->ask[i].p->gen == f->ask[i].gen && f->ask[i].p->lz_inflight > 0)
            f->ask[i].p->lz_inflight--;
    f->name[0] = '\0';
    lz_evict();
}
/* an answer for a name we track arrived; 1 = it answers one of our fetch asks */
static int lz_on_dat(Peer *from, const char *name, int ops, int rejected, int pending, const LzSum *sum) {
    LzFetch *f = lz_find(name);
    if (!f) return 0;
    int64_t now = now_ms();
    for (int i = 0; i < f->nask; i++) {
        if (f->ask[i].p != from || f->ask[i].gen != from->gen || f->ask[i].st != LZA_SENT) continue;
        if (from->lz_inflight > 0) from->lz_inflight--;
        if (rejected > 0) {                                  /* forged / unverifiable ops */
            from->lz_bad++; g.c.lz_forged++;
            lz_backoff(from, 30000, from->lz_bad, 600000, now);
        }
        (void)ops; (void)pending;
        if (rejected > 0) {
            /* a peer that served ANY op failing verification is not trusted to
             * have served the WHOLE zone: its valid (owner-signed) ops still
             * landed, but its answer never completes a fetch — ask another. If
             * nobody else answers, the fetch FAILS (EDE 22), so a partial zone
             * from a forger is never served as if it were complete. */
            f->ask[i].st = LZA_BAD;
            lz_ask(f, now);
        } else {
            f->ask[i].st = LZA_OK; f->ask[i].sum = *sum;
            f->ok_n++;
            if (!f->first_ok_ms) f->first_ok_ms = now;
        }
        return 1;
    }
    return 0;
}
static void lz_peer_down(Peer *p) {
    for (int s = 0; s < LZ_SLOTS; s++) {
        LzFetch *f = &g_lz[s];
        if (!f->name[0]) continue;
        for (int i = 0; i < f->nask; i++)
            if (f->ask[i].p == p && f->ask[i].gen == p->gen && f->ask[i].st == LZA_SENT)
                f->ask[i].st = LZA_TIMEOUT;                  /* lz_service asks another */
    }
    p->lz_inflight = 0;
}
static void lz_service(int64_t now) {
    /* start queued fetches */
    char nm[64];
    for (int budget = 64; budget > 0; budget--) {
        LzFetch *fr = NULL;
        for (int i = 0; i < LZ_SLOTS && !fr; i++) if (!g_lz[i].name[0]) fr = &g_lz[i];
        if (!fr) break;
        if (!dns_lazy_pop_request(nm)) break;
        if (!sp_name_valid(nm, strlen(nm)) || lz_find(nm)) continue;
        memset(fr, 0, sizeof *fr);
        snprintf(fr->name, sizeof fr->name, "%s", nm);
        fr->start_ms = now;
        dns_lazy_begin(nm); g.c.lz_fetch++;
        for (int k = 0; k < LZ_FANOUT; k++) if (!lz_ask(fr, now)) break;
    }
    /* drive fetches in flight */
    for (int s = 0; s < LZ_SLOTS; s++) {
        LzFetch *f = &g_lz[s];
        if (!f->name[0]) continue;
        for (int i = 0; i < f->nask; i++) {
            if (f->ask[i].st != LZA_SENT) continue;
            Peer *p = f->ask[i].p;
            if (!p->used || p->gen != f->ask[i].gen) { f->ask[i].st = LZA_TIMEOUT; continue; }
            if (now - f->ask[i].sent_ms >= LZ_ASK_TIMEOUT_MS) {
                f->ask[i].st = LZA_TIMEOUT; g.c.lz_timeout++;
                if (p->lz_inflight > 0) p->lz_inflight--;
                p->lz_fail++;
                lz_backoff(p, 2000, p->lz_fail, 120000, now);
            }
        }
        int out = lz_outstanding(f);
        /* keep LZ_FANOUT asks open until we have a quorum of valid answers */
        while (f->ok_n + out < LZ_QUORUM && lz_ask(f, now)) out++;
        int more = lz_can_ask_more(f, now);
        if (f->ok_n >= LZ_QUORUM ||
            (f->ok_n >= 1 && out == 0 && !more) ||
            (f->ok_n >= 1 && now - f->first_ok_ms >= LZ_SETTLE_MS && out == 0) ||
            (f->ok_n >= 1 && now - f->first_ok_ms >= LZ_SETTLE_MS + LZ_ASK_TIMEOUT_MS)) {
            lz_finish(f, 1, now);
        } else if (now - f->start_ms >= LZ_FETCH_MAX_MS) {
            lz_finish(f, f->ok_n > 0, now);
        } else if (f->ok_n == 0 && out == 0 && f->nask >= LZ_ASK_MAX) {
            lz_finish(f, 0, now);                            /* everyone tried, nothing valid */
        }
    }
}

/* ── receive ─────────────────────────────────────────────────────────────────── */
static void on_zinv(Peer *from, const uint8_t *pay, int n) {
    int off = 0; uint64_t count;
    if (!sp_rvar(pay, n, &off, &count) || count > 4096) return;
    time_t now = time(NULL);
    int fresh = count <= FRESH_FRAME;
    for (uint64_t i = 0; i < count; i++) {
        if (off + 1 > n) return;
        int nlen = pay[off++];
        if (nlen < 1 || nlen > SP_NAME_MAX || off + nlen + 32 > n) return;
        char name[SP_NAME_MAX + 1];
        memcpy(name, pay + off, (size_t)nlen); name[nlen] = '\0'; off += nlen;
        const uint8_t *their = pay + off; off += 32;
        if (!sp_name_valid(name, (size_t)nlen)) continue;
        if (g.lazy && !dns_lazy_tracked(name)) { g.c.lz_inv_skip++; continue; }   /* LZ */
        uint8_t ours[32];
        dns_state_digest(g.st, name, ours);
        if (memcmp(ours, their, 32) != 0) pull_want(from, name, their, now, fresh);
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
    if (from->sq_n == 0 && from->sqh_n == 0 && from->get_tok >= 1 && send_zdat(from, name)) { from->get_tok--; return; }
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
    /* LZ: a lazy node stores only names it is fetching or already caches */
    if (g.lazy && !dns_lazy_tracked(name)) { g.c.lz_dat_skip++; return; }
    int changed = 0, deferred = 0, held = 0, ops = 0, batched = 0, tried = 0, rejected = 0;
    LzSum sum; memset(&sum, 0, sizeof sum);
    time_t retry_at = 0;
    char err[128];
    for (uint64_t i = 0; i < count; i++) {
        uint64_t ol;
        if (!sp_rvar(pay, n, &off, &ol) || ol < 1 || ol > SP_STATE_OP_MAX || off + (int)ol > n) break;
        const uint8_t *op = pay + off; off += (int)ol;
        /* the frame's name must match the op's (one name per dump) */
        SpStateOp p;
        if (!sp_state_op_parse(op, (int)ol, &p) ||
            p.name_len != nlen || memcmp(p.name, name, (size_t)nlen) != 0) { rejected++; continue; }
        ops++; g.c.zdat_ops++;
        lz_sum_add(&sum, p.op_id);
        if (!op_is_new(name, &p)) { g.c.l5_skip++; continue; }   /* L5: unchanged op: skip */
        time_t ra = 0;
        if (!admit_gate(name, &p, (int)ol, &ra)) {       /* P4: later, not never */
            deferred = 1; if (ra > retry_at) retry_at = ra;
            continue;
        }
        if (!tried) { tried = 1; batched = sp_state_batch_begin(g.st); if (batched) g.c.batch++; }   /* L9 */
        g.c.admit_calls++;
        int rc = sp_state_admit(g.st, &g.o, DNS_BUDGET, DNS_SCOPE, op, (int)ol, err, sizeof err);
        if (rc == 1) { changed = 1; g.c.admit_new++; admit_debit(name, &p, (int)ol); }
        else if (rc == -1) g.c.admit_dup++;
        else if (rc == -2) { held = 1; hold_push(op, (int)ol); }
        else if (rc == 0) {
            rejected++;
            if (g.verbose) fprintf(stderr, "dnsnet: reject %s: %s\n", name, err);
        }
    }
    if (batched && !sp_state_batch_end(g.st)) { g.c.batch_fail++; changed = 0; }
    /* L6: only an UNSOLICITED dump that taught us nothing counts against the
     * peer — an answer to our own zget costs what our P3 pull rate allows,
     * and an honest stale peer answering it must never be scored down. */
    int lz_asked = g.lazy && lz_on_dat(from, name, ops, rejected, deferred || held, &sum);
    { PullSlot *ps = pull_find(name, 0);
      int solicited = (ps && ps->inflight == from) || lz_asked;
      if (from->used) use_note(from, changed ? 1 : (!solicited && ops > 0 && !deferred && !held) ? -1 : 0); }
    pull_done(from, name, deferred, time(NULL), retry_at);
    if (changed) {
        /* announce to everyone — including the source: if we also hold ops it
         * lacked, its digest now mismatches ours and it pulls back.
         * LZ: a lazy node relays only its own names (privacy; see ae_page) */
        if (!g.lazy || dns_lazy_pinned(name)) dnsnet_announce(name);
        if (g.lazy) dns_lazy_bytes(name, sp_state_sum(g.st, name));
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
    if (dnsnet_peers() >= g_peer_cap) { g.c.peer_capped++; return NULL; }   /* L7 */
    for (int i = 0; i < MAX_PEERS; i++)
        if (!g.peers[i].used) {
            Peer *p = &g.peers[i];
            memset(p, 0, sizeof *p);
            p->peer = peer;
            p->send = send;
            p->used = 1;
            p->gen = ++g_gen; if (!p->gen) p->gen = ++g_gen;
            for (int r = 0; r < LANES; r++) p->ann_seq[r] = g.ann_head[r];
            /* L8: each link pages the store from its own random point, on its
             * own phase, so P links cover P different pages per period */
            static const char cs[] = "abcdefghijklmnopqrstuvwxyz0123456789";
            p->ae_cursor[0] = cs[rnd64() % (sizeof cs - 1)];
            p->ae_cursor[1] = cs[rnd64() % (sizeof cs - 1)]; p->ae_cursor[2] = '\0';
            p->ae_left = DNSNET_AE_PAGE;     /* first page of our shelf, on connect */
            p->ae_next = time(NULL) + AE_PERIOD_S / 2 + (time_t)(rnd64() % AE_PERIOD_S);
            ae_page(p);
            return p;
        }
    return NULL;
}

void dnsnet_msg(void *handle, const char *cmd, const uint8_t *pay, int n) {
    Peer *p = handle;
    if (!p || !p->used || n < 0) return;
    /* L6: inbound dn* budget per peer (halved for a deprioritised one) */
    refill(&p->in_tok, &p->in_ms, DNSNET_IN_BURST, p->lowprio ? DNSNET_IN_RATE / 2 : DNSNET_IN_RATE, 1000, now_ms());
    if (p->in_tok < (int64_t)n + 24) { p->in_drop++; g.c.in_drop++; return; }
    p->in_tok -= (int64_t)n + 24;
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
            if (s->alt[k].p == p) alt_drop(s, k);
            else k++;
        }
        if (!s->nalt && !s->inflight && !s->not_before) pull_free(s);
    }
    lz_peer_down(p);
    p->used = 0; p->peer = NULL; p->send = NULL; p->sq_n = 0; p->sqh_n = 0; p->inflight = 0;
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
    unsigned long hit = 0, miss = 0;
    dns_state_cache_stats(&hit, &miss, NULL, NULL);
    fprintf(stderr, "dnsnet: p2p blk=%u relay=%lu lanes=%lu/%lu/%lu/%lu/%lu credit_wait=%lu "
            "ann_ovf=%lu/%lu pull_ovf=%lu/%lu bk_ovf=%lu inv_wait=%lu drain_wait=%lu get_hi=%lu "
            "zdat_ops=%lu l5_skip=%lu admits=%lu new=%lu dup=%lu batch=%lu/%lu in_drop=%lu "
            "useful=%lu useless=%lu lowprio=%lu kick=%lu capped=%lu dg_hit=%lu dg_miss=%lu\n",
            g.blk, g.c.relay, g.c.relay_l0, g.c.relay_l1, g.c.relay_l2, g.c.relay_l3, g.c.relay_l4,
            g.c.credit_wait, g.c.ann_ovf, g.c.ann_ovf_drop, g.c.pull_ovf, g.c.pull_ovf_drop, g.c.bk_ovf,
            g.c.inv_wait, g.c.drain_wait, g.c.get_hi, g.c.zdat_ops, g.c.l5_skip, g.c.admit_calls,
            g.c.admit_new, g.c.admit_dup, g.c.batch, g.c.batch_fail, g.c.in_drop, g.c.useful,
            g.c.useless, g.c.lowprio, g.c.kick, g.c.peer_capped, hit, miss);
}

void dnsnet_tick(void) {
    hold_service();
    time_t now = time(NULL);
    for (int i = 0; i < MAX_PEERS; i++) {             /* L6: disconnect, once, outside any handler */
        Peer *p = &g.peers[i];
        if (p->used && p->kick && !p->kicked && g_tr.drop) {
            p->kicked = 1; g.c.kick++;
            fprintf(stderr, "dnsnet: disconnecting a peer that sends mostly useless ops (useless=%u useful=%u)\n",
                    p->bad, p->good);
            g_tr.drop(p->peer, "dnsnet: useless ops");
        }
    }
    /* per link: quiet lanes, then the AE page (P8), then busy lanes, then dumps */
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer *p = &g.peers[i];
        if (!p->used) continue;
        if (!p->ae_left && (now >= p->ae_next || p->ae_next - now > 2 * AE_PERIOD_S)) {
            p->ae_next = now + AE_PERIOD_S;
            p->ae_left = DNSNET_AE_PAGE;
        }
        if (ring_flush_lanes(p, 0, LANE_HI)) {
            if (p->ae_left) ae_page(p);
            if (!p->ae_left) ring_flush_lanes(p, LANE_HI + 1, LANES - 1);
        }
        sq_service(p);
    }
    int64_t ms = now_ms();
    if (g.pull_kick && ms - g.last_pull_ms >= 100) {   /* a pull slot freed: refill soon */
        g.pull_kick = 0; g.last_pull_ms = ms;
        pull_service(now);
    }
    if (g.lazy) lz_service(ms);                     /* LZ: on-demand fetches */
    if (now != g.last_scan) {                     /* table scans: once a second */
        g.last_scan = now;
        blk_observe();
        ann_service();
        pull_service(now);
        log_limits(now);
    }
}
