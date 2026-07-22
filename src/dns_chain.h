/* dns_chain.h — the SpChainOracle over the namespace-indexer sqlite db.
 *
 * Read-only, own connection (WAL-safe beside a live sync thread). Answers the
 * three questions sp_state admission asks:
 *   owner_now  — names.owner, GATED on lease_expiry (a lapsed name is unowned
 *                here even while the stale row lingers; this is what drives
 *                record eviction now that storage has no TTL)
 *   header_at  — blocks.hash at height; 0 above the sync tip (hold), -1 below
 *                the checkpoint horizon (admit on signature)
 *   tip        — the sync cursor height
 */
#ifndef DNS_CHAIN_H
#define DNS_CHAIN_H

#include "pepenet/state.h"

typedef struct DnsChain DnsChain;

DnsChain     *dns_chain_open(const char *indexer_db_path);   /* NULL on failure */
void          dns_chain_close(DnsChain *c);
SpChainOracle dns_chain_oracle(DnsChain *c);

#endif /* DNS_CHAIN_H */
