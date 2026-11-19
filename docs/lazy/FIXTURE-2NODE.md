# Isolated 2-node lazy fixture (seed + lazy greatdane-node) for Dane

Script: [`fixture/fixture-2node.py`](fixture/fixture-2node.py). One full PepeNet **seed** (`dns/dnsd` from the
patched tree) holds two owner-signed zones; one **lazy greatdane-node** (namespace only, no zones) fetches them
on demand over the existing `dnzget`/`dnzdat` messages. Everything runs inside ONE `unshare -rn` namespace on
loopback, so nothing touches the host's ports (15353/8443/8444/8445), its network, or `~/.pepenet`.

| name          | chain state                       | zone on the seed                                                        | expected |
|---------------|-----------------------------------|-------------------------------------------------------------------------|----------|
| `gdgood.pepe` | owned (fixture key), lease far out | `A 203.0.113.10`, `_443._tcp TLSA 3 1 1 <SPKI sha256 of origin.crt>`   | `/gd/tlsa` loading (EDE 14) -> ok; cert MATCHES the TLSA |
| `gdbad.pepe`  | owned (same key)                  | `A 203.0.113.10`, `_443._tcp TLSA 3 1 1 <SPKI sha256 of another key>`  | loading -> ok; cert does NOT match (Dane must refuse) |
| `gdnone.pepe` | not in the namespace              | none                                                                    | `unowned` |

The chain db is synthetic but real-schema (the tree's own `indexer/src/db.c` SCHEMA): blocks 0..1000
(height > 0), `names` rows with full SmState fields (`seller`/`buyer` = `zeroblob(20)`, prices/legs 0), epochs.
The seed and the node get byte-identical copies. The HTTPS origin listens on `203.0.113.10:443` (TEST-NET-3,
added to `lo` inside the namespace; the node refuses to dial loopback/RFC 1918 origins) and serves one
self-signed EC cert (SAN `gdgood.pepe`, `gdbad.pepe`) for both names.

## Build (patched pepenet-desktop 35047fd tree, v3 patch)

```sh
git -C <tree> checkout 35047fd && git -C <tree> apply greatdane-node-lazy-35047fd.patch
cmake -S <tree> -B <tree>/build -DCMAKE_BUILD_TYPE=Release && make -C <tree>/build greatdane-node
# the seed: dns/Makefile at 35047fd lists no indexer dbcheck.c/snapshot.c (pre-existing), so pass them:
make -C <tree>/dns dnsd 'IDX_SRC=$(addprefix $(IDXSRC)/,attrib.c adapter.c oracle_feed.c db.c chain.c base58.c sync.c pow.c serve_store.c txcheck.c mempool.c net_policy.c dbcheck.c snapshot.c) $(SHIM)'
```

## Run

```sh
unshare -rn sh -c 'ip link set lo up && python3 fixture-2node.py --tree <tree> [--node <greatdane-node>] [--seed <dnsd>] [--out /tmp/gd-fixture-2node] [--hold 600]'
```

Needs python3 and the `openssl` CLI. The owner key is derived from a fixed test seed (sha256, like the
harness `astool key`); hash160 uses hashlib ripemd160 or a built-in pure-python fallback.

What it does, in order:
1. makes the origin cert, a second unrelated key, and their SPKI sha256s (`openssl x509 -pubkey | pkey -outform DER | sha256`);
2. writes the chain db (seed) and clones it to `<out>/node/pep/pep.db`;
3. publishes `gdgood` then `gdbad` with `dnsd --key <hex> --name <n> --zone <file>` (one short run each, same store),
   then starts the seed (`--listen 34001 --no-sync --coin pep`);
4. starts the origin on `203.0.113.10:443`;
5. starts `greatdane-node --only pep --ephemeral-ports --dane-api --stdio --lazy --lazy-cache-dir <out>/node/lazycache
   --lazy-wait-ms 0` with `PEPENET_DNS_PEER=127.0.0.1:34001` (its only mesh peer) and `--seeds 127.0.0.1:9` (no chain peer);
6. checks, through the node's PAC/proxy port (from its `ready` event):
   * first `/gd/tlsa?host=gdgood.pepe` -> `{"status":"loading","ede":14,...}`, then `ok` with the published TLSA;
   * `CONNECT gdgood.pepe:443` -> `200`, TLS handshake (no verification), SPKI sha256 of the served cert == TLSA data;
   * same for `gdbad.pepe`: `ok`, but the served cert's SPKI sha256 != TLSA data (the DANE-fail case);
   * `gdnone.pepe` -> `unowned`; status `namespace_synced` true.
7. `--hold N` keeps seed + node + origin up for N s so Dane can be pointed at `http://127.0.0.1:<pac>/proxy.pac`
   (run Dane inside the same namespace, e.g. `nsenter`/a shell started from the same `unshare`).

Exit 0 = every check passed. Logs: `<out>/node.err`, `<out>/seed*.err`; certs and zones are in `<out>`.

## Proof run (Nov 18, 2026, clean 35047fd + v3 patch, Release build, inside `unshare -rn`)

```
TLSA good=343c60ee…3c363d84 bad=06b03e15…8058fd9b
  PASS gdgood.pepe first /gd/tlsa -> loading (EDE 14)
  PASS gdgood.pepe settles to ok in 3.02s with the published TLSA (addr 203.0.113.10, port 443, 3 1 1)
  PASS gdgood.pepe CONNECT through the node: HTTP/1.1 200 Connection established
  PASS gdgood.pepe: origin cert SPKI sha256 MATCHES TLSA 3 1 1 (DANE ok)
  PASS gdbad.pepe first /gd/tlsa -> loading (EDE 14)
  PASS gdbad.pepe settles to ok in 2.02s with the published TLSA
  PASS gdbad.pepe CONNECT through the node: HTTP/1.1 200 Connection established
  PASS gdbad.pepe: origin cert SPKI sha256 does NOT match TLSA 3 1 1 (Dane must refuse)
  PASS gdnone.pepe -> unowned
  PASS status namespace_synced true (basis peers, height 1000, peers 1)
RESULT PASS []
```

The ~2-3 s to `ok` is the node seating its one mesh peer after start (the script queries 2 s after `ready`);
once the peer is up a cold fetch completes in ~100 ms on loopback.
