# DogeNet lazy node: DESIGN (keeper/lazy-node, private)

Status: built and tested on a private branch only. Not deployed, not pushed publicly, no seed touched.
Scope: dogenet-dns `dnsd` plus the mesh glue, and the node Dane embeds (greatdane-node, as a patch).
Full mode is still the default. Without `--lazy`, behaviour is unchanged apart from these local
changes: the empty-answer, digest and rate rules apply only to lazy fetches, and the wake fd is set only in lazy mode.

## 1. What lazy mode does
* **Sync:** the node syncs the namespace only (the chain fold: owner h160 and lease per name). It does
  not page or pull zones. Inbound `dnzinv` for names it does not track is ignored (`lz_inv_skip`), and so is
  inbound `dnzdat` (`lz_dat_skip`).
* **On demand:** a query for an OWNED name whose zone is not held parks the query and queues a fetch.
  The fetch asks peers with the EXISTING `dnzget` (nlen,name). The peers answer with the EXISTING `dnzdat` full dump.
  **No new message and no wire change.** Old nodes serve it as a normal pull.
* **Unowned names:** these are answered NXDOMAIN from the namespace alone, with NO fetch. Random-name floods
  therefore cost nothing on the mesh.
* **Privacy:** a lazy node never relays or AE-offers names it browsed. It offers only pinned names (its own
  `--name`). The only `dnzinv` it sends for a browsed name is the no-change digest reply to the peer that just
  answered its own `dnzget`, and that peer already knows the name was asked about (interop test).

## 2. Fetch protocol (local policy over dnzget/dnzdat)
| knob | value |
|---|---|
| fanout | 2 peers at once, at most 6 per fetch, 64 fetches in flight, 16 lazy zgets per peer |
| quorum | 2 valid answers end a fetch. Otherwise it ends 600 ms after the first valid answer once nothing is outstanding, or when no candidate is left |
| per-ask timeout | 2,000 ms. Fetch cap 8,000 ms |
| start rate | token bucket of 32 fetches/s, burst 64. Excess stays LOADING (signal 14) |
| merge | every op passes `sp_state_admit` (signature, lease-gated current owner at MTP, anchor header, order, 8 KB budget). Answers merge by per-key anchor LWW, so one honest peer is enough |

**Answer classes**
* **valid:** every op admitted. It counts toward the quorum.
* **forged:** any op rejected. The ask is BAD and never completes the fetch, even if some of its ops were valid.
  The peer is penalised (`lz_bad`; backoff 30 s → 600 s, exponential) and another peer is asked.
* **hold-nothing** (empty dump): NOT a vote that the zone is empty. A lazy peer that never fetched the
  name answers this way. There is no penalty and the next peer is asked. A verified-empty zone needs at least 2 such answers and no
  valid data. With only 1 the fetch FAILS (EDE 22) rather than serve an empty zone for an owned name.
* **stale/withheld** (valid, but missing ops the merged set has): after the fetch, each OK answer's order-free op-set
  sum (XOR of op_ids plus count) is compared with the held set. A mismatch gives `lz_stale`, a 10 s backoff.
* **timeout:** backoff 2 s → 120 s and another peer is asked.

Penalties are local peer scores consistent with L1–L10. Solicited answers are never L6-scored as unsolicited.

## 3. Verification and freshness
* **Authenticity:** this is exactly what a full node does today (`sp_state_admit`). A forged or foreign-key op is never stored or served.
* **Freshness/completeness:** this CANNOT be proven today, because nothing in the namespace commits a zone digest
  (FOOTPRINT-CAP-DRAFT gap G3). A peer that alone serves an older but validly signed zone (`stale_only` test)
  is believed. Mitigations already in place are: ask 2 and merge, live `dnzinv` updates to cached names, TTL 300 s refresh, and the stale penalty.
* **A2, built:** zone digest = `sha256(sorted op_ids of the zone, clear op included)`. It is exposed as
  `dnsnet_zone_digest()` and ctl `DIGEST <name>`.
  * With a commitment source (`dns_lazy_set_digest_oracle`), a fetched zone must match before it is served.
    On a mismatch, every answer so far is marked stale and penalised, and other peers are asked (2 rounds). After that the fetch FAILS.
    With a digest, ANY peer can serve the zone: a lazy cache, a stranger, or a CDN.
  * The only built-in source today is `--lazy-digest-file` ("name hex" pins), an operator/test stand-in.
  * **The real source needs an on-chain or namespace commitment. That is an ON-CHAIN / PROTOCOL CHANGE
    needing nowon sign-off.** It was NOT built. See §7 Q1 for the options.
  * Tests: `digest_stale_only` never serves v1 (EDE 22), and `digest_2stale_honest_slow` serves v2 after rejecting 2 stale peers.

## 4. Cache
* **Size and TTL:** LRU on max names (2048) and max op bytes (8 MiB). TTL 300 s (verified-empty 60 s).
* **Refresh:** stale-while-revalidate. After the TTL the old zone is served while one background re-fetch runs, but never
  past max_stale (86,400 s). Past that the answer is "loading".
* **Never evicted:** pinned names (own `--name`) and LOADING names.
* **Restart:** names in the store are adopted as stale-but-servable, then refreshed on use.
* **Owner change:** rows of a previous owner trigger invalidate plus re-fetch, so they are never served.
* **Negative caching:**
  * unowned: answered from the namespace, nothing cached or fetched
  * verified-empty: 60 s
  * FAILED: retried by the next query after 5 s
* **Coalescing:** one fetch per name. Concurrent queries for it park on the same fetch, and the request ring is deduped.
* **Cache pollution:** only ops that passed `sp_state_admit` are stored. LRU plus the byte cap bound an attacker
  who queries many max-size zones, and the fetch rate bucket bounds the churn.

## 5. Resolver behaviour (Dane's "loading" contract)
* An owned name whose zone is not ready is NEVER answered NXDOMAIN, an empty NOERROR, or a missing TLSA.
* The query is parked (UDP park table, 64; TCP head-of-line) for `--lazy-wait-ms`, default **3,000 ms**, range 0..9,000.
  It is re-checked every 25 ms and answered the moment the zone is ready. While queries are parked the net loop is
  woken every 100 ms, and a newly queued fetch wakes it at once (wake pipe, `idx_serve_wake_fd`).
* At the deadline the answer is SERVFAIL + RFC 8914 EDE:
  * **EDE 14 "Not Ready"** with text "dogenet-lazy: zone loading; retry": the fetch is in flight
  * **EDE 22 "No Reachable Authority"** with text "dogenet-lazy: zone fetch failed (no verified answer from any peer); retrying":
    the last fetch got no verified answer. The next query retries after 5 s.
  * Non-EDNS clients get plain SERVFAIL.
* Once the zone is ready, answers are byte-identical to full mode (lazy_test).

## 6. Swarm (A1, built)
* **Re-serve:** a lazy node answers `dnzget` from its verified cache like any node (existing on_zget). Popular names
  therefore gain sources.
* **Pull-through:** a `dnzget` for an OWNED zone the lazy node does not hold is answered (empty) and also queues the node's own
  fetch. The asker's retry, or the no-change `dnzinv` digest that follows the fetch, then finds it there. This is bounded by
  the 32/s bucket, the LRU, and the L-series per-peer get rate.
* **Peer choice:** peers that served data before are preferred, and peers that often hold nothing sink but are still asked.
* **Test `swarm_pull_through`:** S(full) ← Z1(lazy, never queried by a client) ← Z(lazy, dials only Z1). Z's first query was
  answered with the correct zone in 51 ms. A second lazy node Z2 behind Z1 got it warm in 26 ms.

## 7. Specs, NOT built: A3–A6
The table below gives the wire/protocol status and an effort estimate for one engineer on this codebase.

| item | what | wire / protocol | effort |
|---|---|---|---|
| A2-commit | Zone digest committed so any peer can serve the zone (see the options below) | (a) ON-CHAIN FORMAT CHANGE. (b) PROTOCOL CHANGE: new op type; old nodes must relay it unread. Needs nowon sign-off | 1–2 wk incl. tests (the verifier side is built) |
| A3 PEX/DHT discovery | See below | none for PEX v1. A DHT (`dnfind`) or service bits are a **PROTOCOL CHANGE** | PEX v1 3–4 d; DHT 3–4 wk |
| A4 NAT | See below | none, except hole punching (rendezvous messages = **PROTOCOL CHANGE**) | outbound-first 1–2 d; UPnP/NAT-PMP 3–5 d; v6 2 d; hole punch 2 wk |
| A5 tit-for-tat | See below | none (local policy) | 3–5 d plus a sim round |
| A6 chunked snapshots | See below | **PROTOCOL CHANGE** (new messages) plus, for (b), the commitment | 3–5 wk |

**A2-commit options:**
* (a) An owner-signed zone-head op carrying {digest, op count, anchor}, committed on chain in the name's lease/update tx.
* (b) A per-name zone-head *mesh* op: the owner signs `{digest, n_ops, max_anchor}`, and it rides `dnzdat` like any op.
  This gives no on-chain change, but old nodes must store/relay an unknown key. Freshness then reduces to "latest owner-signed head",
  which is still withholdable. (a) also gives anti-withholding.

**A3 PEX/DHT discovery:**
* v1: use the existing `dngetaddr`/`dnaddr` exchange more aggressively:
  * keep a 1–2k address book with per-address /16 bucketing (eclipse resistance)
  * dial 8 outbound across ≥4 /16s
  * re-ask `dngetaddr` every 10 min from random peers, and remember good peers across restarts
* v2 (needs a new message): Kademlia-style "who holds name X" lookups over node IDs, so a lazy node finds zone holders without a seed.
* A lazy-capability service bit in `version`, so full nodes stop paging AE inventory to lazy peers, is also a PROTOCOL CHANGE.
* Removes the single-seed bottleneck: Round-9 lazy, 1 seed ≈ 300k names → 8 peers ≈ 2.1–2.4M.

**A4 NAT:**
* Outbound-first is already how a lazy node works (it dials out; `--no-listen` works).
* Add UPnP-IGD/NAT-PMP/PCP port mapping (miniupnpc-class code, opt-in) and listen on IPv6 when a global address exists
  (Starlink v6 is public). Starlink IPv4 is CGNAT, so v4 is outbound-only.
* UDP hole punching needs a rendezvous message plus a UDP transport. The mesh is TCP today, so it is a large change.
  Recommendation: v6 + UPnP first; skip hole punching.

**A5 tit-for-tat:**
* Per-peer ledger of bytes/zones served to us vs asked of us. When the serve queue is under load, order it by ratio
  (honest-first, as Round-9's fair client). Cap a zero-ratio peer at 2 in flight. New peers get a bootstrap credit.
* Cheap to add to the existing `sq_push`/get-token path.
* Lazy nodes are net consumers by design. Pull-through serving gives them a ratio, and full nodes must not starve them.
* Combined with the existing L1–L10 per-peer get-rate, this bounds query flooders.

**A6 chunked snapshots:**
* Namespace (and optionally zone) snapshot split into ~1 MB chunks with a manifest of chunk sha256s, fetched in parallel from many
  peers. Each chunk is verified against the manifest.
* The manifest root is checked against a state digest at height H obtained from ≥2 independent peers (or the commitment
  above). Fall back to the chain fold on disagreement.
* Snapshot trust stays local: a forged snapshot is caught when the fold catches up.

**Round-9 risks and how this design answers them:**
* **Query amplification (~166x):**
  * unowned names cost 0
  * owned names: ≤2 zgets per name per TTL, coalesced
  * 32/s fetch bucket; per-peer 16 in flight; the L-series get rate on the serving side
  * A5 adds honest-first
* **Withholding/stale:**
  * ask 2, merge LWW
  * hold-nothing is not a vote
  * digest gate (A2) once a commitment exists
  * live `dnzinv` refresh of cached names
* **Snapshot trust:** A6, with ≥2-source state digests.
* **Cache pollution:** admit-verified only, LRU plus byte cap, rate bucket.
* **Single seed:** A3 + A4.

## 8. Dane / Best In Show integration (exact answers)
1. **Flags.**
   * dnsd: `--lazy` or env `DOGENET_LAZY=1` or `GREATDANE_NODE_LAZY=1`.
   * greatdane-node (patch): `--lazy` or env `GREATDANE_NODE_LAZY=1`. Dane's placeholders are adopted as-is.
   * Tunables:
     * `--lazy-cache-dir <dir>` (dnsd: store = dir/lazy-zones.db when no `--store`; greatdane-node keeps its store under `--data`)
     * `--lazy-max-names` 2048
     * `--lazy-max-mb` 8
     * `--lazy-ttl` 300
     * `--lazy-empty-ttl` 60
     * `--lazy-max-stale` 86400
     * `--lazy-wait-ms` 3000 (0..9000; greatdane-node HTTP side: env `GREATDANE_NODE_LAZY_WAIT_MS`)
     * `--lazy-digest-file`
   * Eviction: LRU by names/bytes; pinned and loading names are never evicted.
2. **EDE:** "zone still fetching" = SERVFAIL + RFC 8914 **EDE 14 (Not Ready)**. "Fetch failed, retrying" = SERVFAIL + **EDE 22
   (No Reachable Authority)**. Both mean loading, so set `LAZY_LOADING_EDE = 14` and also treat 22 as loading/retryable.
3. **/gd/tlsa** lives in greatdane-node (pepenet-desktop `src/webproxy.c` `tlsa_api` + `tls/src/resolve.c`), which is the Dane tree, not this repo.
   * The exact change is `docs/lazy/greatdane-node-lazy.patch` (also at dane/greatdane-node-lazy.patch).
   * It adds `RES_LOADING` / `RES_FETCH_FAILED`. For an owned name not READY, `/gd/tlsa` returns:
     `{"host":..,"status":"loading","height":..,"peer_height":..,"rcode":"SERVFAIL","ede":14|22,"phase":"fetching"|"fetch_failed","retry_ms":1000}`
   * It never returns `unowned`/`no_tlsa`/`bad_record` for such a name. `unowned` stays namespace-only, and is reliable once `namespace_synced` is true.
4. **CONNECT** (passthrough): it blocks up to the same wait (3 s default). If still not ready, it replies `503 Service Unavailable` with
   `Retry-After: 1` and `X-GreatDANE-Status: loading`, never a 404. Ready → normal 200 splice.
5. **Status event:** the patch appends `"lazy":0|1,"namespace_synced":true|false,"zones_cached":N,"zones_loading":N,"zones_failed":N`
   to the stdio `{"event":"status"}` line. The fields are append-only, so old readers are unaffected.
6. **Max blocking:** dnsd `--lazy-wait-ms` (default 3,000 ms, hard cap 9,000). greatdane-node /gd/tlsa and CONNECT
   `GREATDANE_NODE_LAZY_WAIT_MS` (default 3,000, cap 9,000). A cold fetch from a responsive peer completes in ~25–50 ms
   on loopback (see the numbers below), so the wait is only reached when peers are slow, absent or bad. That leaves Dane ≥7 s of its 10 s budget to retry.
7. **Status endpoints.**
   * dnsd ctl socket (`--ctl <path>`, local, no key):
     * `LAZY` → one line `+OK lazy= ready= tip= peer_tip= ns_synced= peers= cached= bytes= zready= loading= failed= queued= hits= misses= ...`
     * `ZONE <name...>` → per name `owned= state=absent|loading|ready|failed|unowned|invalid age= bytes=`
     * `PREFETCH <name...>` → `+OK queued=N of M` (prefetch hook; C API `dns_lazy_prefetch`)
     * `NAMES [prefix|-] [after|-] [limit]`
     * `DIGEST <name...>`
   * greatdane-node: `/gd/tlsa` itself is the per-name status, and the status event carries the totals.
* **Name list for suggestions:** this is namespace-only and works unchanged in lazy mode, via greatdane-node's existing
  `GET /gd/names?prefix=&offset=&limit=` (idx_db_names on the namespace db). dnsd also has ctl `NAMES` / C `dns_chain_names`.
* **Integration note:** the Dane node vendors an OLDER dns/ (its dns_net.c is 363 lines). To use lazy mode it must vendor
  this branch's `dogenet-dns/src` (dns_net.c, dns_lazy.c/h, dnsd_core.c/h, dns_wire.c/h, dns_chain.c/h) and
  `namespace-indexer/src/sync.c` + `indexer.h` (`idx_serve_wake_fd`). The patch then compiles: the only unresolved
  symbols in a syntax check against the old tree were `sp_state_owner` and `idx_serve_wake_fd`, both provided by this branch.

## 9. Measured (final binary bin/dnsd-lazy-59930e20 = branch 92677c7; all inside `unshare -rn`)
**Setup:** boot test (tests/boot.out, tests/boot/result.json). Two full seeds hold 60,000 zones, and each new node dials both.
The namespace db (19.5 MB) is pre-folded and identical for full and lazy. Chain-fold time is the same in both modes and is not part of these numbers.

| | full F | lazy Z |
|---|---|---|
| ready to answer | all 60k zones at 1,364 s | 5.25 s (namespace only) |
| bytes in / out | 22.5 MB / 17.4 MB to finish zones | 161 KB / 352 B by ready |
| bytes over the 1,430 s run | 22.9 MB in / 17.7 MB out | 8.6 MB in / 80 KB out (*) |
| RSS | 32.2 MB | 20.4 MB (Ze, max 32 names: 16.7 MB) |
| CPU | 27.9 s | 1.3 s |
| zone store on disk | 26.0 MB | 4.35 MB with 600 zones; Ze 4.19 MB with 32 (sqlite floor) |

(*) Lazy inbound is mostly unsolicited AE `dnzinv` digest pages that full seeds push to every peer, about 6 KB/s.
Z ignores them. Stopping them needs a lazy service bit, which is a PROTOCOL CHANGE (Q2).

**Query latency** (300 distinct owned names per set, 0 bad answers in every set):
| | cold p50 / p95 / max | warm p50 / p95 |
|---|---|---|
| loopback, during F's bootstrap | 50.5 / 50.9 / 82.1 ms | 0.0 / 0.1 ms |
| loopback, quiet | 50.6 / 52.2 / 85.4 ms | 0.0 / 0.0 ms |
| 40 ms one-way links, during bootstrap | 126.0 / 126.6 / 151.6 ms | 0.0 / 0.1 ms |
| 40 ms one-way links, quiet | 126.3 / 129.6 / 176.5 ms | 0.0 / 0.0 ms |

Before the wake-pipe fix (5d5914e), cold latency was 1,006 / 1,008 ms: the fetch waited for the 1 Hz serve tick.

**Eviction:** Ze has `--lazy-max-names 32` and was queried for 200 names. It ended with 32 cached, 168 evicted, store 32 names, 0 failures.

**Adversarial** (tests/adv.out, 14/14 PASS). Across every case: 0 owned-NXDOMAIN, 0 owned-empty, 0 evil answers.
* forged_content (bad sig) + honest → honest, 26 ms
* forged_key (non-owner signer) + honest → honest, 26 ms
* stale fast + honest slow → v2, 604 ms
* withhold (empty) + honest → honest, 26 ms
* 2 peers drop dnzdat + honest → honest at 2.67 s (2 s ask timeout)
* forged only → EDE 14, then EDE 22, never the forgery
* stale only → v1 served. This is the documented no-commitment limitation.
* no peers → EDE 14, then 22
* withhold only (1 empty peer) → EDE 22, never an empty answer
* 2 empty + honest slow → honest, 607 ms
* digest-pinned stale only → EDE 22, v1 never served
* digest-pinned 2 stale + honest slow → v2, 605 ms
* digest-pinned forged only → EDE 22
* swarm pull-through → 26 ms; warm second lazy node → 26 ms

**Interop:**
* Lazy with the live 8605e98c nodes (tests/interop-lazy.out): PASS.
  * The old mesh converged and the old stores are equal.
  * Z fetched alice, bob and carol correctly, and the lazy owner's zone propagated to the old mesh.
  * A live update to cached alice reached Z in 0.5 ms after the old mesh converged.
  * Z's store holds only the queried names, Z sent 0 dnzinv during a quiet AE period, and wire bad frames = 0.
* Full mode of this branch vs live 8605e98c: mixed / swap / allP all PASS (interop/full-*.out). Bad frames 0, drops 0, stores equal.

**Existing suites** (tests/suites.out, tests/p2p-lazy-unit.out):
* all passed: dogenet-mesh check; state_dns, wire (88), zone (103), dnsd_core (75), dns_chain
* check-loop (3/3); tcp_loris; antispam (36 ok); p2p_test; lazy_test (49/0)
* net_test: 55 ok and the N7 livelock FAIL, which is a known product defect documented in net_test.c and present before this branch
* loop_test_legacy: fails by design

## 10. Zone-digest commitment (SPEC ONLY, nothing built)
**Decision (nowon, Nov 18, 2026, via ITFH): "Definitely keep stuff off chain."** The on-chain option is REJECTED.
Only the off-chain, owner-signed zone-head op (Option 2) stays as the design direction. It is still spec only, not built, and is a
protocol change that needs nowon's sign-off before any implementation ships.

**What exists today, and stays as it is:**
* The verifier side: `dnsnet_zone_digest`, ctl `DIGEST`, the `dns_lazy_set_digest_oracle` hook, and the operator/test stand-in `--lazy-digest-file`.
* Nothing produces a real commitment, and no wire or on-chain change was made for it.

**Digest definition (the same for both options):**
* `D = sha256( sort(op_id_1 .. op_id_n) )` over the zone's live ops, with the clear op included.
* An empty zone is `sha256("")`.
* op_id is the existing `sha256(preimage)`, so D needs no new hashing rules.

### Option 2 (KEPT, spec only): owner-signed zone-head op in the mesh
A new sp_state op kind under a reserved key, `zone-head = {D, n_ops, max_anchor}`, signed by the owner or §2.2 hot key exactly like
other zone ops. It is anchored to a block header, and per-key anchor LWW applies. It rides inside `dnzdat` dumps and relays like any op.

* **For:**
  * No on-chain change and no fees. Edits stay instant, and the owner tool re-signs the head with each edit.
  * A lazy node that receives any head newer than its zone knows the zone is incomplete and keeps asking.
    That defeats a peer serving an old zone together with an old head, if any other peer has the newer head.
  * Small: one extra op per zone (~150 B).
* **Against:**
  * **PROTOCOL CHANGE.** Old nodes must store and relay an op kind they don't understand. Today `sp_state_admit` would reject
    an unknown kind. It would need either a spare record type that old nodes already accept, or a staged rollout where new nodes relay
    it first. It also counts against the 8 KB DNS_BUDGET.
  * Freshness is only "the newest head any honest peer showed us". A peer that withholds BOTH the new head and the new ops
    from a lazy node that asks only that peer still wins. Option 1 does not have this hole.
  * Two heads signed at the same anchor need a tie-break, e.g. the higher n_ops, then the bytes.
* **Effort:** ~1–2 weeks.
  * op kind + admit rule + budget accounting
  * owner tooling re-signs the head on PUT/DEL
  * dnsd gate (the hook exists)
  * mixed-version relay tests

### Option 1: on-chain commitment (REJECTED by nowon, Nov 18, 2026; kept only as a record of why)
Rejected: it changes on-chain formats and puts data on chain. nowon: "Definitely keep stuff off chain." Do not build it.

> The owner puts `{name, D, n_ops, max_anchor}` (≈ 32 + 4 + 4 bytes plus the name) into an on-chain record. It can be a field in the
> existing lease/update carrier tx, or a new small carrier op the indexer folds into the namespace next to owner h160 and lease.
>
> * **For:**
>   * Freshness and completeness become provable. A lazy node knows the CURRENT digest from its own chain fold, so a
>     withheld, stale or partial zone is detected from any single peer. Then ANY source can serve the zone: a lazy cache, a stranger, a CDN, a snapshot.
>   * Snapshots (A6) can be verified per name.
>   * Consensus-ordered, so there are no races between two heads.
> * **Against:**
>   * **On-chain format change.** The indexer fold and every indexer must learn the new field.
>   * Every zone edit costs an on-chain tx and fee, and waits a block (~1 min on Doge) before it is "current". DDNS-style frequent edits get expensive and slow.
>   * The rent formula is frozen, so the cost lands as a tx fee, not rent.
>   * Edits made between commitments are unservable to strict lazy nodes until committed, unless a grace rule is added
>     ("serve the newest owner-signed ops if their anchor is after the commitment"), and that weakens the guarantee.
>   * Chain bloat ≈ 80–100 B per committed edit.
> * **Effort:** ~2–3 weeks.
>   * indexer fold + db column + reorg rollback
>   * dnsd oracle wiring (the hook already exists)
>   * a wallet/CLI path to publish
>   * tests, plus a coordinated indexer upgrade before nodes rely on it
>

**Next step if approved:** Option 2 only. Known limit stays: a peer withholding both the new head and the new ops still wins against a lazy node that asks only that peer, so lazy fetch keeps asking 2+ peers.

## 11. Lazy service bit (BUILT — approved PROTOCOL CHANGE, branch 230efff)

**Wire.** The existing Bitcoin-lineage `version` message, field `services`
(uint64 LE, payload bytes 4..11). A lazy node ORs in **bit 24 = 0x0000000001000000**
(`IDX_SVC_DOGENET_LAZY` in indexer.h, `DNSNET_SVC_LAZY` in dns_net.h). 24..31 is
the experimental range; Dogecoin Core, old DogeNet (8605e98c) and old PepeNet nodes
ignore unknown bits (the DogeNet indexer tests only bit 0, NODE_NETWORK, when picking a sync peer; the lazy bit does not touch it). No new message, no frame
change, nothing on chain. A lazy node logs `services 0x1000000`
(`0x1000400` with a serve store). `--lazy-no-svc-bit` (doge dnsd) /
`GREATDANE_NODE_LAZY_NO_SVC_BIT=1` (node) turn it off — A/B test only.

**Behaviour of a node on this branch (full or seed) toward a peer with the bit**
(services read from the peer's version: inbound payload, outbound handshake):
- sends it NO anti-entropy inventory pages — neither the page at connect nor the
  periodic AE_PERIOD_S (60 s) pages (`lz_peer_up`, `lz_ae_skip` counters; LAZY ctl
  `lazy_peers_seen=` `ae_skipped=`).
- still sends: live relays (dnzinv for a changed name — the lazy cache's
  invalidation path), dnzdat answers to its dnzget (fetch + pull-through), chain
  sync / headers / addr exactly as before.
- a lazy node still ignores AE pages from OLD peers (they keep sending them; it
  drops dnzinv for untracked names without pulling) — so old↔new is correct,
  just not cheaper.

**Interop:** old full ↔ new lazy: old ignores the bit, pages as before, lazy
drops them (correct, ~6 KB/s as before). new full ↔ new lazy: no AE pages.
new lazy → old full: same as first case. Mixed meshes: per-link.

**Measured (doge, 1,405 s, two new seeds with 60k zones each, 600 cold names
fetched in both arms):** with bit 291,474 B in (207 B/s; 132 B/s after the first
300 s), 0 dnzinv; without bit 8,822,450 B in (6,278 B/s), 3,072 dnzinv frames.
−96.7 % bytes in (30×). Cold p50/p95 identical (50.6/51.0 vs 50.6/50.9 ms
loopback; 50.8/51.5 vs 50.7/51.5 ms set B), 0 bad answers, 0 bad frames; seeds
skipped 22–23 AE pages each.

## 12. greatdane-node build compat (Best In Show, PepeNet desktop 35047fd)

Overlaying dogenet-dns/src + DogeNet sync.c/indexer.h onto the PepeNet desktop
tree is wrong: its dns/ and indexer/ are a different lineage (dns_rec_* take the
coin magic[2], indexer has idx_coin_onchain_magic / serve_conn_misbehave /
snapshot import, dns_net has PepeNet zget pacing + ECDSA budget + misbehave
strikes). The branch now ships `dogenet-dns/docs/lazy/greatdane-node-lazy-35047fd.patch`:
one `git apply` onto 35047fd, no overlay, all PepeNet APIs unchanged; the lazy
layer is ported into the tree's own dns_net.c (lazy zgets obey P3 pacing; an
ECDSA-throttled partial dump is "incomplete", never a vote). See
docs/lazy/README-greatdane-node.md for the file list.
