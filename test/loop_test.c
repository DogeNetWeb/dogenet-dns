/* loop_test.c — two INDEPENDENT dns_net instances (dns_net.c compiled twice,
 * symbols renamed A_/B_, time() faked) over an in-memory wire. Measures the
 * digest-mismatch exchange when one side cannot admit the other's ops.
 *
 * L1  A never held the name (owner says lapsed on A, live on B).
 * L2  A held the name, then lapsed + swept (floor/clear may survive the drop).
 * L3  mixed fleet: only ONE side patched must still break the loop.
 * Each scenario counts every frame over T simulated seconds with up to
 * DELIV_PER_S deliveries per second (a ~5 ms round-trip link), and asserts
 * total frames <= CAP (<= 12 frames per 60 s AE period + connect). Today's code
 * loops at link speed (bounded here only by DELIV_PER_S) and fails the cap.
 * Zero-op dnzdat frames are counted separately (A has nothing to send).
 */
#include "dns_state.h"
#include "zone.h"
#include CHAIN_CRYPTO_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef void (*send_fn)(void *, const char *, const uint8_t *, size_t);
#define DECL(P) \
 void P##_dnsnet_init(SpState *, SpChainOracle, int); \
 void *P##_dnsnet_up(void *, send_fn); \
 void P##_dnsnet_msg(void *, const char *, const uint8_t *, int); \
 void P##_dnsnet_tick(void); void P##_dnsnet_down(void *);
DECL(A) DECL(B)

static time_t g_now = 1000000;
time_t ft_time(time_t *t) { if (t) *t = g_now; return g_now; }

static int g_fail;
#define CK(c, m) do { if (c) printf("  ok   %s\n", m); else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

static uint8_t OWNER160[20], OPRIV[32], OPUB[33];
static int a_owns = 1;
static int own_A(void *u, const char *n, uint8_t o[20]) { (void)u; if (!a_owns || strcmp(n, "zone")) return 0; memcpy(o, OWNER160, 20); return 1; }
static int own_B(void *u, const char *n, uint8_t o[20]) { (void)u; if (strcmp(n, "zone")) return 0; memcpy(o, OWNER160, 20); return 1; }
static int hdr(void *u, uint32_t h, uint8_t out[32]) { (void)u; if (h > 500) return 0;
    uint8_t s[8] = {'h','d','r',1,(uint8_t)h,(uint8_t)(h>>8),(uint8_t)(h>>16),(uint8_t)(h>>24)}; sp_sha256(s, 8, out); return 1; }
static uint32_t tip(void *u) { (void)u; return 500; }
static SpChainOracle ORA = { NULL, own_A, hdr, tip }, ORB = { NULL, own_B, hdr, tip };

/* wire: FIFO of frames, each tagged with its destination */
#define QCAP 256
#define FCAP (2 * DNS_BUDGET + 64)
typedef struct { int to; char cmd[16]; int len; uint8_t pay[FCAP]; } Fr;
static Fr q[QCAP]; static int qh, qn, dropped;
static long n_frames, n_inv, n_get, n_dat, n_dat0;
static void push(int to, const char *cmd, const uint8_t *p, size_t n) {
    if (qn >= QCAP || n > FCAP) { dropped++; return; }
    Fr *f = &q[(qh + qn++) % QCAP];
    f->to = to; snprintf(f->cmd, sizeof f->cmd, "%s", cmd); memcpy(f->pay, p, n); f->len = (int)n;
    n_frames++;
    if (!strcmp(cmd, "dnzinv")) n_inv++; else if (!strcmp(cmd, "dnzget")) n_get++;
    else if (!strcmp(cmd, "dnzdat")) { n_dat++; int nl = p[0]; if (n > (size_t)(1+nl) && p[1+nl] == 0) n_dat0++; }
}
static void sendA(void *peer, const char *c, const uint8_t *p, size_t n) { (void)peer; push(1, c, p, n); } /* A -> B */
static void sendB(void *peer, const char *c, const uint8_t *p, size_t n) { (void)peer; push(0, c, p, n); } /* B -> A */

static int put_rec(SpState *st, const SpChainOracle *o) {
    zone_rec r; memset(&r, 0, sizeof r);
    snprintf(r.label, sizeof r.label, "www"); r.type = 1; r.ttl = 60; r.rdlen = 4;
    r.rdata[0] = 192; r.rdata[2] = 2; r.rdata[3] = 9;
    char err[128];
    return dns_state_put(st, o, "zone", &r, OPRIV, OPUB, SP_CERT_NONE, NULL, 0, err, sizeof err);
}

static int put_fat(SpState *st, const SpChainOracle *o, const char *lb) {
    zone_rec r; memset(&r, 0, sizeof r);
    snprintf(r.label, sizeof r.label, "%s", lb); r.type = 16; r.ttl = 60; r.rdlen = ZONE_MAX_RDATA;
    memset(r.rdata, 'x', ZONE_MAX_RDATA);
    char err[128];
    return dns_state_put(st, o, "zone", &r, OPRIV, OPUB, SP_CERT_NONE, NULL, 0, err, sizeof err);
}

#define DELIV_PER_S 200
static void run(const char *label, SpState *A, SpState *B, int T, long cap) {
    qh = qn = dropped = 0; n_frames = n_inv = n_get = n_dat = n_dat0 = 0;
    A_dnsnet_init(A, ORA, 0); B_dnsnet_init(B, ORB, 0);
    void *hA = A_dnsnet_up((void *)"B", sendA);   /* A's handle for peer B */
    void *hB = B_dnsnet_up((void *)"A", sendB);
    for (int s = 0; s < T; s++) {
        g_now++;
        A_dnsnet_tick(); B_dnsnet_tick();
        for (int d = 0; d < DELIV_PER_S && qn; d++) {
            Fr f = q[qh]; qh = (qh + 1) % QCAP; qn--;
            if (f.to == 0) A_dnsnet_msg(hA, f.cmd + 2, f.pay, f.len);
            else           B_dnsnet_msg(hB, f.cmd + 2, f.pay, f.len);
        }
    }
    A_dnsnet_down(hA); B_dnsnet_down(hB);
    double perh = (double)n_frames * 3600.0 / T;
    printf("     [%s] %d s: %ld frames (inv %ld, get %ld, dat %ld of which zero-op %ld), dropped %d => %.0f frames/h\n",
           label, T, n_frames, n_inv, n_get, n_dat, n_dat0, dropped, perh);
    char m[160]; snprintf(m, sizeof m, "%s: frames over %d s <= %ld (no round-trip-speed loop)", label, T, cap);
    CK(n_frames <= cap, m);
}

int main(void) {
    sp_sha256((const uint8_t *)"owner", 5, OPRIV);
    while (!sp_pubkey(OPRIV, OPUB)) sp_sha256(OPRIV, 32, OPRIV);
    sp_hash160(OPUB, 33, OWNER160);
    const int T = 3600;                       /* one simulated hour = 60 AE periods */
    const long CAP = 12L * (T / 60 + 1) + 16; /* <= 12 frames per AE period + connect:
                                                linear in AE periods, not in round trips */

    printf("-- L1: A never held the name; B holds it; A cannot admit --\n");
    { SpState *A = sp_state_open(":memory:"), *B = sp_state_open(":memory:");
      a_owns = 0; CK(put_rec(B, &ORB) == 1, "B published a record");
      run("L1", A, B, T, CAP);
      CK(n_dat0 > 0, "L1 exercised zero-op dnzdat frames");
      sp_state_close(A); sp_state_close(B); }

    printf("-- L2: A held the name, lapsed, swept --\n");
    { SpState *A = sp_state_open(":memory:"), *B = sp_state_open(":memory:");
      a_owns = 1; put_rec(B, &ORB); put_rec(A, &ORA);
      a_owns = 0; int sw = dns_state_sweep(A, &ORA);
      printf("     (A swept %d name(s))\n", sw);
      run("L2", A, B, T, CAP);
      sp_state_close(A); sp_state_close(B); }

#if defined(LOOP_A_LEGACY) && defined(LOOP_B_LEGACY)
#define LOOP_LIMITER_DESC "limiter off (both sides legacy)"
#elif defined(LOOP_A_LEGACY)
#define LOOP_LIMITER_DESC "limiter on B only (A legacy)"
#elif defined(LOOP_B_LEGACY)
#define LOOP_LIMITER_DESC "limiter on A only (B legacy)"
#else
#define LOOP_LIMITER_DESC "limiter on both sides"
#endif
    printf("-- L7: budget-full livelock (net_test N7), module kept alive, " LOOP_LIMITER_DESC " --\n");
    { SpState *A = sp_state_open(":memory:"), *B = sp_state_open(":memory:");
      a_owns = 1; int na = 0, nb = 0; char lb[16];
      for (int i = 0; i < 40; i++) { snprintf(lb, sizeof lb, "a%d", i); if (put_fat(A, &ORA, lb) == 1) na++; else break; }
      for (int i = 0; i < 40; i++) { snprintf(lb, sizeof lb, "b%d", i); if (put_fat(B, &ORB, lb) == 1) nb++; else break; }
      printf("     (A holds %d fat records, B holds %d)\n", na, nb);
      CK(na > 5 && nb > 5, "L7: both budgets full of different records");
      run("L7", A, B, T, 16L * (T / 60 + 1) + 16);   /* both sides hold rows: two AE triggers per round; mixed worst 15/round */
      uint8_t da[32], db[32]; dns_state_digest(A, "zone", da); dns_state_digest(B, "zone", db);
      CK(memcmp(da, db, 32) != 0, "L7: digests still differ (budget case, bounded not converged)");
      sp_state_close(A); sp_state_close(B); }

    printf("-- L0 control: both own; states merge and go quiet --\n");
    { SpState *A = sp_state_open(":memory:"), *B = sp_state_open(":memory:");
      a_owns = 1; put_rec(B, &ORB);
      run("L0", A, B, T, CAP);
      uint8_t da[32], db[32]; dns_state_digest(A, "zone", da); dns_state_digest(B, "zone", db);
      CK(!memcmp(da, db, 32), "L0: digests converge");
      sp_state_close(A); sp_state_close(B); }

    if (g_fail) { printf("\nloop_test: %d FAILED\n", g_fail); return 1; }
    printf("\nloop_test: all passed\n"); return 0;
}
