/* dns_lazy.c — see dns_lazy.h. One mutex-guarded open-addressing table of
 * tracked names + a small request ring; no allocation after init. */
#include "dns_lazy.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NAME_CAP 64
#define REQ_CAP  512

typedef struct {
    char     name[NAME_CAP];
    uint8_t  used, state, has_data, empty, queued, pinned;
    int64_t  fetched_ms;     /* last successful fetch (0 = never) */
    int64_t  used_ms;        /* last query (LRU) */
    int64_t  retry_ms;       /* FAILED: next query may re-fetch after this */
    int64_t  bytes;
} Ent;

static struct {
    int             on;
    DnsLazyConf     c;
    pthread_mutex_t mu;
    Ent            *t; uint32_t cap; int n, ndata; int64_t bytes;
    char            req[REQ_CAP][NAME_CAP]; int rh, rn;
    DnsLazyStats    st;
} L = { .mu = PTHREAD_MUTEX_INITIALIZER };

#ifdef DNS_LAZY_TEST_CLOCK_MS
int64_t DNS_LAZY_TEST_CLOCK_MS(void);
static int64_t now_ms(void) { return DNS_LAZY_TEST_CLOCK_MS(); }
#else
static int64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
#endif

void dns_lazy_conf_default(DnsLazyConf *c) {
    c->max_names = 2048; c->max_bytes = 8 << 20; c->ttl_s = 300; c->empty_ttl_s = 60;
    c->max_stale_s = 86400; c->wait_ms = 3000; c->fail_retry_s = 5;
}
const char *dns_lazy_state_name(int s) {
    switch (s) { case DNS_LAZY_LOADING: return "loading"; case DNS_LAZY_READY: return "ready";
                 case DNS_LAZY_FAILED: return "failed"; default: return "absent"; }
}

void dns_lazy_init(const DnsLazyConf *c) {
    pthread_mutex_lock(&L.mu);
    dns_lazy_conf_default(&L.c);
    if (c) L.c = *c;
    if (L.c.max_names < 16) L.c.max_names = 16;
    if (L.c.max_names > 1 << 20) L.c.max_names = 1 << 20;
    if (L.c.max_bytes < 65536) L.c.max_bytes = 65536;
    if (L.c.ttl_s < 1) L.c.ttl_s = 1;
    if (L.c.empty_ttl_s < 1) L.c.empty_ttl_s = 1;
    if (L.c.max_stale_s < L.c.ttl_s) L.c.max_stale_s = L.c.ttl_s;
    if (L.c.wait_ms < 0) L.c.wait_ms = 0;
    if (L.c.wait_ms > 9000) L.c.wait_ms = 9000;
    if (L.c.fail_retry_s < 1) L.c.fail_retry_s = 1;
    uint32_t cap = 256;
    while (cap < (uint32_t)L.c.max_names * 4u) cap <<= 1;   /* data + loading/failed, load <= 1/2 */
    free(L.t);
    L.t = calloc(cap, sizeof *L.t);
    L.cap = L.t ? cap : 0; L.n = L.ndata = 0; L.bytes = 0; L.rh = L.rn = 0;
    memset(&L.st, 0, sizeof L.st);
    L.on = L.t != NULL;
    pthread_mutex_unlock(&L.mu);
}
int dns_lazy_enabled(void) { return L.on; }
const DnsLazyConf *dns_lazy_conf(void) { return &L.c; }

static uint32_t h32(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) { h ^= (uint8_t)*s; h *= 16777619u; }
    h ^= h >> 15; h *= 0x2c1b3c6dU; h ^= h >> 12;
    return h;
}
static Ent *find(const char *name) {
    if (!L.cap) return NULL;
    for (uint32_t i = h32(name) & (L.cap - 1), k = 0; k < L.cap; i = (i + 1) & (L.cap - 1), k++) {
        if (!L.t[i].used) return NULL;
        if (!strcmp(L.t[i].name, name)) return &L.t[i];
    }
    return NULL;
}
static Ent *insert(const char *name) {
    if (!L.cap || strlen(name) >= NAME_CAP || (uint32_t)L.n * 2 >= L.cap) return NULL;
    uint32_t i = h32(name) & (L.cap - 1);
    while (L.t[i].used) i = (i + 1) & (L.cap - 1);
    memset(&L.t[i], 0, sizeof L.t[i]);
    snprintf(L.t[i].name, NAME_CAP, "%s", name);
    L.t[i].used = 1; L.n++;
    return &L.t[i];
}
/* backward-shift delete (linear probing stays tombstone-free) */
static void erase(Ent *e) {
    if (e->has_data) { L.ndata--; L.bytes -= e->bytes; }
    uint32_t i = (uint32_t)(e - L.t), j = i;
    L.t[i].used = 0; L.n--;
    for (;;) {
        j = (j + 1) & (L.cap - 1);
        if (!L.t[j].used) break;
        uint32_t k = h32(L.t[j].name) & (L.cap - 1);
        int move = (i <= j) ? (k <= i || k > j) : (k <= i && k > j);
        if (move) { L.t[i] = L.t[j]; L.t[j].used = 0; i = j; }
    }
}
static void enqueue(Ent *e) {
    if (e->queued || L.rn >= REQ_CAP) return;
    snprintf(L.req[(L.rh + L.rn) % REQ_CAP], NAME_CAP, "%s", e->name);
    L.rn++; e->queued = 1;
}
static int age_of(const Ent *e, int64_t now) {
    return e->has_data && e->fetched_ms ? (int)((now - e->fetched_ms) / 1000) : (e->has_data ? 0 : -1);
}
/* what the resolver may answer from right now */
static int servable(const Ent *e, int64_t now) {
    if (e->has_data && (now - e->fetched_ms) <= (int64_t)L.c.max_stale_s * 1000) return DNS_LAZY_READY;
    if (e->state == DNS_LAZY_FAILED) return DNS_LAZY_FAILED;
    return DNS_LAZY_LOADING;
}

static int want(const char *name, int *age_s, int touch, int fetch) {
    if (!L.on) { if (age_s) *age_s = -1; return DNS_LAZY_READY; }
    pthread_mutex_lock(&L.mu);
    int64_t now = now_ms();
    Ent *e = find(name);
    if (!e && fetch) e = insert(name);
    if (!e) {
        if (age_s) *age_s = -1;
        pthread_mutex_unlock(&L.mu);
        return fetch ? DNS_LAZY_LOADING : DNS_LAZY_ABSENT;   /* table full: never NXDOMAIN */
    }
    if (touch) e->used_ms = now;
    if (fetch) {
        int64_t ttl = (int64_t)(e->empty ? L.c.empty_ttl_s : L.c.ttl_s) * 1000;
        int due = 0;
        if (e->state == DNS_LAZY_ABSENT) due = 1;
        else if (e->state == DNS_LAZY_FAILED) due = now >= e->retry_ms;
        else if (e->state == DNS_LAZY_READY) due = !e->has_data || now - e->fetched_ms > ttl;
        if (due) {
            enqueue(e);
            if (e->queued) e->state = DNS_LAZY_LOADING;
        }
    }
    int s = servable(e, now);
    if (touch) {
        if (s == DNS_LAZY_READY) {
            L.st.hits++;
            int64_t ttl = (int64_t)(e->empty ? L.c.empty_ttl_s : L.c.ttl_s) * 1000;
            if (now - e->fetched_ms > ttl) L.st.stale_served++;
        } else L.st.misses++;
    }
    if (age_s) *age_s = age_of(e, now);
    pthread_mutex_unlock(&L.mu);
    return s;
}
int dns_lazy_want(const char *name, int *age_s) { return want(name, age_s, 1, 1); }
int dns_lazy_peek(const char *name, int *age_s) {
    if (!L.on) { if (age_s) *age_s = -1; return DNS_LAZY_ABSENT; }
    int s = want(name, age_s, 0, 0);
    if (s == DNS_LAZY_ABSENT) return s;
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    if (e && !e->has_data && e->state == DNS_LAZY_ABSENT) s = DNS_LAZY_ABSENT;
    pthread_mutex_unlock(&L.mu);
    return s;
}
int dns_lazy_prefetch(const char *name) {
    if (!L.on) return 0;
    pthread_mutex_lock(&L.mu);
    int64_t now = now_ms();
    Ent *e = find(name);
    if (!e) e = insert(name);
    int q = 0;
    if (e && e->state != DNS_LAZY_LOADING) {
        int64_t ttl = (int64_t)(e->empty ? L.c.empty_ttl_s : L.c.ttl_s) * 1000;
        if (!e->has_data || now - e->fetched_ms > ttl) {
            if (!e->used_ms) e->used_ms = now;
            enqueue(e);
            if (e->queued) { e->state = DNS_LAZY_LOADING; q = 1; }
        }
    }
    pthread_mutex_unlock(&L.mu);
    return q;
}
void dns_lazy_invalidate(const char *name) {
    if (!L.on) return;
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    if (e && e->state != DNS_LAZY_LOADING) {
        if (e->has_data) { L.ndata--; L.bytes -= e->bytes; }
        e->has_data = 0; e->bytes = 0; e->fetched_ms = 0; e->state = DNS_LAZY_ABSENT;
    }
    pthread_mutex_unlock(&L.mu);
}

int dns_lazy_pop_request(char name[64]) {
    pthread_mutex_lock(&L.mu);
    int ok = 0;
    while (L.rn > 0 && !ok) {
        char *r = L.req[L.rh]; L.rh = (L.rh + 1) % REQ_CAP; L.rn--;
        Ent *e = find(r);
        if (!e || !e->queued) continue;           /* evicted meanwhile */
        e->queued = 0;
        snprintf(name, NAME_CAP, "%s", r); ok = 1;
    }
    pthread_mutex_unlock(&L.mu);
    return ok;
}
void dns_lazy_requeue(const char *name) {
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    if (e) enqueue(e);
    pthread_mutex_unlock(&L.mu);
}
int dns_lazy_tracked(const char *name) {
    if (!L.on) return 1;
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    int t = e && (e->has_data || e->state == DNS_LAZY_LOADING || e->pinned);
    pthread_mutex_unlock(&L.mu);
    return t;
}
void dns_lazy_pin(const char *name) {
    if (!L.on) return;
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    if (!e) e = insert(name);
    if (e) { e->pinned = 1; e->used_ms = now_ms(); }
    pthread_mutex_unlock(&L.mu);
}
int dns_lazy_pinned(const char *name) {
    if (!L.on) return 0;
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    int p = e && e->pinned;
    pthread_mutex_unlock(&L.mu);
    return p;
}
void dns_lazy_begin(const char *name) {
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    if (!e) e = insert(name);
    if (e) e->state = DNS_LAZY_LOADING;
    pthread_mutex_unlock(&L.mu);
}
static void set_bytes(Ent *e, int64_t bytes) {
    if (e->has_data) L.bytes -= e->bytes; else L.ndata++;
    e->has_data = 1; e->bytes = bytes; L.bytes += bytes;
}
void dns_lazy_done(const char *name, int ok, int64_t bytes, int empty) {
    pthread_mutex_lock(&L.mu);
    int64_t now = now_ms();
    Ent *e = find(name);
    if (!e) e = insert(name);
    if (e) {
        if (ok) {
            set_bytes(e, bytes); e->empty = (uint8_t)(empty != 0);
            e->fetched_ms = now; e->state = DNS_LAZY_READY; L.st.fetch_ok++;
            if (!e->used_ms) e->used_ms = now;
        } else {
            e->state = DNS_LAZY_FAILED; e->retry_ms = now + (int64_t)L.c.fail_retry_s * 1000;
            L.st.fetch_fail++;
            if (!e->used_ms) e->used_ms = now;
        }
    }
    pthread_mutex_unlock(&L.mu);
}
void dns_lazy_bytes(const char *name, int64_t bytes) {
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    if (e && e->has_data) set_bytes(e, bytes);
    pthread_mutex_unlock(&L.mu);
}
void dns_lazy_adopt(const char *name, int64_t bytes) {
    pthread_mutex_lock(&L.mu);
    Ent *e = find(name);
    if (!e) e = insert(name);
    if (e) {
        int64_t now = now_ms();
        set_bytes(e, bytes); e->state = DNS_LAZY_READY;
        /* unknown age: stale at once (re-validated on first use), but servable */
        e->fetched_ms = now - ((int64_t)L.c.ttl_s + 1) * 1000;
        e->used_ms = 0;                         /* oldest in LRU until used */
    }
    pthread_mutex_unlock(&L.mu);
}
int dns_lazy_evict_one(char victim[64]) {
    pthread_mutex_lock(&L.mu);
    int64_t now = now_ms();
    int over = L.ndata > L.c.max_names || L.bytes > L.c.max_bytes || (uint32_t)L.n * 2 + 8 >= L.cap;
    Ent *best = NULL;
    if (over)
        for (uint32_t i = 0; i < L.cap; i++) {
            Ent *e = &L.t[i];
            if (!e->used || e->pinned || e->state == DNS_LAZY_LOADING || e->queued) continue;
            /* data-less FAILED/ABSENT entries go first (they hold no store bytes) */
            if (!e->has_data && (!best || best->has_data || e->used_ms < best->used_ms)) { best = e; continue; }
            if (e->has_data && (!best || (best->has_data && e->used_ms < best->used_ms))) best = e;
        }
    int ok = 0;
    if (best) {
        snprintf(victim, NAME_CAP, "%s", best->name);
        ok = best->has_data ? 1 : 2;                /* 2 = table-only (nothing in the store) */
        erase(best); L.st.evicted++;
    }
    (void)now;
    pthread_mutex_unlock(&L.mu);
    return ok;
}
void dns_lazy_stats(DnsLazyStats *s) {
    pthread_mutex_lock(&L.mu);
    *s = L.st;
    s->names = L.ndata; s->bytes = L.bytes; s->queued = L.rn;
    s->ready = s->loading = s->failed = 0;
    for (uint32_t i = 0; i < L.cap; i++) {
        if (!L.t[i].used) continue;
        if (L.t[i].state == DNS_LAZY_LOADING) s->loading++;
        else if (L.t[i].state == DNS_LAZY_FAILED) s->failed++;
        else if (L.t[i].has_data) s->ready++;
    }
    pthread_mutex_unlock(&L.mu);
}
void dns_lazy_each(int (*cb)(void *u, const char *name, int state, int age_s, int64_t bytes), void *u) {
    pthread_mutex_lock(&L.mu);
    int64_t now = now_ms();
    for (uint32_t i = 0; i < L.cap; i++) {
        Ent *e = &L.t[i];
        if (!e->used) continue;
        if (!cb(u, e->name, e->has_data ? servable(e, now) : e->state, age_of(e, now), e->bytes)) break;
    }
    pthread_mutex_unlock(&L.mu);
}
