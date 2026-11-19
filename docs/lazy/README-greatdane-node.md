# greatdane-node lazy mode — build recipe (PepeNet desktop tree 35047fd)

`greatdane-node-lazy-35047fd.patch` is a self-contained patch against the
PepeNet desktop tree at **35047fd** ("dnsd: L3 live relays ahead of an
anti-entropy catch-up"). It REPLACES the earlier overlay recipe
(`greatdane-node-lazy.patch` against cc5fd7d + copying dogenet-dns/src,
sync.c and indexer.h over the tree): do **not** overlay DogeNet files onto the
PepeNet tree — that tree's dns/ and indexer/ are a different lineage
(coin-magic `dns_rec_*(…, magic[2])`, `idx_coin_onchain_magic`,
`serve_conn_misbehave`/`dnsnet_set_misbehave`, PepeNet zget pacing, ECDSA
budget). The patch ports the lazy layer INTO the tree's own files and keeps
all of those APIs unchanged.

## Recipe

    git clone <pepenet-desktop> gdn && cd gdn
    git checkout 35047fd
    git apply /path/to/greatdane-node-lazy-35047fd.patch     # no overlay step
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target greatdane-node

## What the patch does

* dns/src: adds `dns_lazy.{c,h}` (unchanged from DogeNet) and `dns_mesh.h`
  (coin-agnostic mesh include: `dogenet/` or `pepenet/` — chosen by
  `__has_include`, or forced with `-DDNS_MESH_PEPENET` / `-DDNS_MESH_DOGENET`);
  every dns/src file includes `dns_mesh.h` instead of `pepenet/*.h`.
  `dns_net.c` gets the lazy fetch block ported onto PepeNet's own dns_net
  (lazy zgets obey the P3 pacing bucket — PepeNet peers answer one zget per
  GET_COOL_S — LZ_PER_PEER 2, ask timeout 3 s; an ECDSA-throttled partial dump
  is "incomplete", never a vote), plus the lazy service bit.
* CMakeLists.txt: `dns/src/dns_lazy.c` in the `dns_embed` list.
* dns/Makefile: dns_lazy.c in every link line, `lazy_test` + `check-lazy`;
  sibling paths auto-detected (`../mesh` + `../indexer` in this tree, or
  `../pepenet-mesh` + `../namespace-indexer`; override `make MESHDIR= IDX=`);
  mesh/Makefile likewise finds `../indexer/protocol` (`PROTO=`);
  `$(NETLIB)` builds only `libpepenetnet.a` (check-lazy no longer runs mesh
  `all`); `-D_DEFAULT_SOURCE` in CFLAGS. mesh/test/net_test.c and dns tests:
  `_DEFAULT_SOURCE` guard + `<stdlib.h>` (mkstemp under -std=c11).
* indexer/src: `idx_serve_wake_fd` (wake pipe), `idx_serve_extra_services`,
  `idx_serve_peer_services()`, `IDX_SVC_DOGENET_LAZY (1<<24)` — additive, the
  tree's existing peer_svc capture is reused.
* src/gd_node.c: `--lazy` / `GREATDANE_NODE_LAZY=1`, `--lazy-max-names`,
  `--lazy-max-mb`, `--lazy-ttl`, `--lazy-empty-ttl`, `--lazy-max-stale`,
  `--lazy-wait-ms`, `--lazy-cache-dir` (env `GREATDANE_NODE_LAZY_{MAX_NAMES,
  MAX_MB,TTL,EMPTY_TTL,MAX_STALE,WAIT_MS,CACHE_DIR}`; flags win). Status gains
  lazy / namespace_synced / zones_cached / zones_loading / zones_failed /
  namespace_sync_basis / best_known_height. `GREATDANE_NODE_SYNC_GRACE_S`
  (default 15) is the offline connect grace (see below).
* src/engine.{h,c}: `EngineStatus` gains `proj_height` and `best_known`
  (read-only; for the rule below).
* indexer/src/db.c: NULL/short blob columns no longer crash the sync thread
  (`col_blob_exact`, see "Fixes in v2").
* src/dnsnet.c: lazy cache store `<dir>/lazy-zones-<coin>.db` when
  `--lazy-cache-dir` is set; resolver cores park not-ready queries; advertises
  version.services bit 24 and stops AE pages to peers that advertise it
  (`GREATDANE_NODE_LAZY_NO_SVC_BIT=1` = A/B test only).
* tls/src/resolve.*, src/webproxy.c: `/gd/tlsa` → `{"status":"loading",…}`
  (never unowned/no_tlsa while the zone is not here), CONNECT → 503 +
  Retry-After: 1 + X-GreatDANE-Status: loading. Both wait up to the node's ONE
  lazy wait: `--lazy-wait-ms` > `GREATDANE_NODE_LAZY_WAIT_MS` > 3000 (cap 9000).
* dns/src/dnsd.c (standalone PepeNet dnsd): honours the lazy bit too.

## namespace_synced (exact rule)

`namespace_synced` is true when the ownership fold can be trusted for
"unowned". `namespace_sync_basis` says which branch held.

* **base:** `height > 0`, and the names projection covers our own block tip
  (`proj_height >= height`, or no projection yet and `height < activation`).
* **online, basis `"peers"`:** a live peer tip is known (`ph > 0`, from the sync
  pass handshake or a live serve peer), and `height + 2 >= ph`. It is never true
  while the node is catching up.
* **offline, basis `"offline"`:** all of the following hold:
  * at least one sync pass has finished;
  * since then, for `GREATDANE_NODE_SYNC_GRACE_S` (default 15 s) without a
    break, there has been no live peer tip and no connected peer;
  * the node is not behind the best tip it ever saw: `best_known_height == 0`,
    or `height + 2 >= best_known_height` (persisted meta `peer_height`).
* **otherwise:** false, basis `"none"`. A peer that connects later and shows a
  higher tip flips it back to false at once. Dane should follow the live value
  and not latch it. A fixture with `height == 0` is never synced.

## Fixes in v2 (Best In Show round 2)

1. SIGSEGV on an owned, unfetched name with no peers. The cause was
   `indexer/src/db.c:idx_db_load_state` doing memcpy from a NULL blob. The
   synthetic `names` row had no seller/buyer, and the sync thread crashed on
   its first pass. The bug is pre-existing in 35047fd and has nothing to do
   with lazy mode or the wait. It is fixed with exact-size blob copies
   (zero-fill otherwise).
2. The `namespace_synced` rule above.
3. `--lazy-wait-ms` now reaches /gd/tlsa and CONNECT.
4. check-lazy paths for this tree.

Run `test/gd_node_test.sh` inside `unshare -rn`. It adds lazy-01..03.

