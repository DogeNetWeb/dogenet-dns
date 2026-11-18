/* dns_lazy.h — lazy (namespace-only) mode: on-demand zone cache.
 *
 * A lazy node syncs the NAMESPACE (the indexer db: owner + lease per name)
 * exactly like a full node, but does not mirror every zone. A zone is fetched
 * from peers the first time a query needs it, with the EXISTING dnzget/dnzdat
 * pair (no new wire message), admitted through the same sp_state_admit
 * verification a full node uses (owner/§2.2 hot-key signature, lease-gated
 * current owner, anchor header hash on our chain), then cached in the --store
 * sqlite with a TTL and bounded LRU eviction.
 *
 * This module is the thread-safe shared state between the resolver thread
 * (asks "is this zone servable?", queues a fetch) and the net thread (runs
 * fetches in dns_net.c, records results, evicts). One instance per process.
 * Full mode never calls dns_lazy_init and every query is unaffected. */
#ifndef DNS_LAZY_H
#define DNS_LAZY_H

#include <stdint.h>

typedef struct {
    int     max_names;      /* cached zones kept (LRU beyond)       default 2048 */
    int64_t max_bytes;      /* sum of held op bytes kept (LRU)      default 8 MiB */
    int     ttl_s;          /* fresh for this long, then served stale while one
                               background re-fetch runs             default 300 */
    int     empty_ttl_s;    /* same, for a verified-EMPTY zone      default 60 */
    int     max_stale_s;    /* never serve a zone older than this
                               (re-fetch failing) — loading instead  default 86400 */
    int     wait_ms;        /* resolver parks a not-ready query up to this long
                               before answering the loading signal  default 3000 */
    int     fail_retry_s;   /* a FAILED fetch is retried by the next query after
                               this long                             default 5 */
} DnsLazyConf;

void dns_lazy_conf_default(DnsLazyConf *c);

/* states as the resolver sees them */
enum {
    DNS_LAZY_ABSENT  = 0,   /* never fetched (or evicted)                       */
    DNS_LAZY_LOADING = 1,   /* fetch in flight, nothing servable yet            */
    DNS_LAZY_READY   = 2,   /* verified zone held (maybe stale: refresh queued) */
    DNS_LAZY_FAILED  = 3,   /* last fetch got no valid answer from any peer     */
};
const char *dns_lazy_state_name(int st);

/* optional: called (any thread, outside the lock) whenever a fetch is queued,
 * so the host can wake its net loop at once (dnsd: idx_serve_wake_fd pipe) */
void dns_lazy_set_kick(void (*fn)(void));

/* turn lazy mode on for this process (call once, before the threads start) */
void dns_lazy_init(const DnsLazyConf *c);
int  dns_lazy_enabled(void);
const DnsLazyConf *dns_lazy_conf(void);

/* ── resolver side ─────────────────────────────────────────────────────────── */
/* A query needs `name` (already known OWNED in the namespace). Touches the
 * LRU, and queues a fetch when absent, past its TTL, or failed and due for a
 * retry. Returns the state to answer from: READY = serve from the store
 * (fresh or stale-while-revalidate); LOADING/FAILED = not servable yet.
 * *age_s (may be NULL) = seconds since the last successful fetch, -1 if none. */
int  dns_lazy_want(const char *name, int *age_s);
/* same, for a parked query's re-check (not counted again in hits/misses) */
int  dns_lazy_want_recheck(const char *name, int *age_s);
/* Read-only peek (no LRU touch, no fetch). */
int  dns_lazy_peek(const char *name, int *age_s);
/* Prefetch hook: queue a fetch now unless held fresh / loading. 1 queued. */
int  dns_lazy_prefetch(const char *name);
/* The resolver found the held rows belong to a PREVIOUS owner (transfer):
 * forget the cache state so the next want re-fetches. */
void dns_lazy_invalidate(const char *name);

/* ── net side (dns_net.c) ─────────────────────────────────────────────────── */
/* pop one queued fetch; 1 = name filled */
int  dns_lazy_pop_request(char name[64]);
/* push back a request we could not start (fetch table full) */
void dns_lazy_requeue(const char *name);
/* is the name of interest (held READY, or LOADING)? inv/dat filter */
int  dns_lazy_tracked(const char *name);
/* pinned names (this node's own --name) are never evicted, always AE-paged */
void dns_lazy_pin(const char *name);
int  dns_lazy_pinned(const char *name);
/* a fetch for `name` began / finished. ok: 1 = verified answer(s) admitted
 * (bytes = held op bytes now, empty = zero records), 0 = no valid answer */
void dns_lazy_begin(const char *name);
void dns_lazy_done(const char *name, int ok, int64_t bytes, int empty);
/* a live update to a cached name changed its held bytes */
void dns_lazy_bytes(const char *name, int64_t bytes);
/* over max_names/max_bytes? fill the least-recently-used evictable name
 * (READY/FAILED, not pinned, not loading) and forget it. 1 = victim */
int  dns_lazy_evict_one(char victim[64]);
/* restart: names already in the store are adopted as READY-but-stale
 * (served at once, re-validated on first use) */
void dns_lazy_adopt(const char *name, int64_t bytes);

/* status (thread-safe) */
typedef struct {
    int     names, ready, loading, failed, queued;
    int64_t bytes;
    unsigned long hits, misses, fetch_ok, fetch_fail, evicted, stale_served;
} DnsLazyStats;
void dns_lazy_stats(DnsLazyStats *s);
/* iterate tracked names (status endpoint); cb returns 0 to stop */
void dns_lazy_each(int (*cb)(void *u, const char *name, int state, int age_s, int64_t bytes), void *u);

#endif /* DNS_LAZY_H */
