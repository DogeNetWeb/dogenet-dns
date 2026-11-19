#!/usr/bin/env python3
"""fixture-2node.py — isolated 2-node lazy fixture for Dane (see ../FIXTURE-2NODE.md).

One full PepeNet seed (dns/dnsd from the patched tree) holding two signed zones, and one lazy
greatdane-node (namespace only, no zones) that fetches them on demand. Everything runs on loopback
INSIDE `unshare -rn`, so nothing touches the host's ports (15353/8443/8444/8445) or ~/.pepenet.

  gdgood.pepe  owned, zone: A 203.0.113.10 + _443._tcp TLSA 3 1 1 <sha256 of the fixture cert's SPKI>  (matches)
  gdbad.pepe   owned, zone: A 203.0.113.10 + _443._tcp TLSA 3 1 1 <sha256 of a DIFFERENT key>        (mismatch)
  gdnone.pepe  unowned
A local HTTPS origin on 203.0.113.10:443 serves the fixture cert for both names. 203.0.113.10 is a TEST-NET-3
(documentation) address the script adds to the namespace's lo: the node refuses to dial loopback/RFC1918 origins.

Usage (inside the namespace):
  unshare -rn sh -c 'ip link set lo up && python3 fixture-2node.py --tree <patched 35047fd tree> [--out DIR] [--hold SECONDS]'
  --node / --seed override the binaries (default <tree>/build*/greatdane-node, <tree>/dns/dnsd).
  --hold N keeps both nodes + the origin up for N s after the checks (print the PAC/proxy ports, point Dane at them).
Needs: python3, openssl CLI, hashlib ripemd160 (OpenSSL legacy provider) — the key's hash160 is computed in pure python
otherwise. Exit 0 = every check passed."""
import argparse, glob, hashlib, json, os, select, shutil, socket, sqlite3, ssl, subprocess, sys, threading, time

ap = argparse.ArgumentParser()
ap.add_argument("--tree", required=True); ap.add_argument("--node"); ap.add_argument("--seed")
ap.add_argument("--out", default="/tmp/gd-fixture-2node"); ap.add_argument("--hold", type=int, default=0)
a = ap.parse_args()
TREE = os.path.abspath(a.tree)
NODE = a.node or next((p for p in sorted(glob.glob(TREE + "/build*/greatdane-node")) if os.access(p, os.X_OK)), None)
SEED = a.seed or TREE + "/dns/dnsd"
DBC = TREE + "/indexer/src/db.c"
for p, what in ((NODE, "greatdane-node (build it, or pass --node)"), (SEED, "dns/dnsd (make -C dns dnsd, or pass --seed)"), (DBC, "indexer/src/db.c")):
    if not p or not os.path.exists(p): sys.exit("missing " + what)
OUT = os.path.abspath(a.out); shutil.rmtree(OUT, ignore_errors=True); os.makedirs(OUT + "/node/pep")
SEED_P2P, SEED_DNS, NODE_LISTEN, TIP = 34001, 25301, 34002, 1000
ORIGIN_IP = "203.0.113.10"   # TEST-NET-3; added to lo inside the namespace
if os.path.exists("/proc/self/ns/net") and subprocess.run(["ip", "addr", "add", ORIGIN_IP + "/32", "dev", "lo"], capture_output=True).returncode not in (0, 2):
    sys.exit("cannot add %s to lo — run inside `unshare -rn`" % ORIGIN_IP)

# ── key (same derivation as the harness astool: priv = sha256(seed), re-hash until valid) ──
P = 2**256 - 2**32 - 977; N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def ec_add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    l = (3 * p[0] * p[0] * pow(2 * p[1], -1, P)) % P if p == q else ((q[1] - p[1]) * pow(q[0] - p[0], -1, P)) % P
    x = (l * l - p[0] - q[0]) % P; return (x, (l * (p[0] - x) - p[1]) % P)
def ec_mul(k, pt=G):
    r = None
    while k:
        if k & 1: r = ec_add(r, pt)
        pt = ec_add(pt, pt); k >>= 1
    return r
def ripemd160(b):
    try: return hashlib.new("ripemd160", b).digest()
    except ValueError: pass
    # pure-python fallback (RIPEMD-160 reference algorithm)
    import struct
    r1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    r2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    s1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    s2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    K1 = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]; K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]
    M = 0xFFFFFFFF
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & M
    def f(j, x, y, z):
        return [x ^ y ^ z, (x & y) | (~x & z), (x | ~y) ^ z, (x & z) | (y & ~z), x ^ (y | ~z)][j // 16] & M
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = b + b"\x80" + b"\0" * ((55 - len(b)) % 64) + struct.pack("<Q", len(b) * 8)
    for i in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[i:i + 64]); al, bl, cl, dl, el = h; ar, br, cr, dr, er = h
        for j in range(80):
            t = (rol((al + f(j, bl, cl, dl) + X[r1[j]] + K1[j // 16]) & M, s1[j]) + el) & M
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + f(79 - j, br, cr, dr) + X[r2[j]] + K2[j // 16]) & M, s2[j]) + er) & M
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & M; h[1] = (h[2] + dl + er) & M; h[2] = (h[3] + el + ar) & M
        h[3] = (h[4] + al + br) & M; h[4] = (h[0] + bl + cr) & M; h[0] = t
    return struct.pack("<5I", *h)
def key(seed):
    d = hashlib.sha256(seed.encode()).digest()
    while not (0 < int.from_bytes(d, "big") < N): d = hashlib.sha256(d).digest()
    x, y = ec_mul(int.from_bytes(d, "big")); pub = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return d.hex(), ripemd160(hashlib.sha256(pub).digest())
PRIV, H160 = key("gd-fixture-2node-owner")

# ── TLS material: the origin's cert, and an unrelated key for the mismatching TLSA ──
def run(cmd): return subprocess.run(cmd, check=True, capture_output=True)
def spki_sha256(pem_path, is_cert=True):
    pub = run(["openssl", "x509" if is_cert else "pkey", "-in", pem_path, "-pubout" if not is_cert else "-pubkey", "-noout"] if is_cert
              else ["openssl", "pkey", "-in", pem_path, "-pubout"]).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub, check=True, capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()
run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2",
     "-subj", "/CN=gdgood.pepe", "-addext", "subjectAltName=DNS:gdgood.pepe,DNS:gdbad.pepe",
     "-keyout", OUT + "/origin.key", "-out", OUT + "/origin.crt"])
run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", OUT + "/other.key"])
GOOD = spki_sha256(OUT + "/origin.crt"); BAD = spki_sha256(OUT + "/other.key", is_cert=False)
assert GOOD != BAD

# ── synthetic chain db (schema = the tree's own indexer SCHEMA) ──
def schema_from(db_c):
    import re
    s = open(db_c).read(); i = s.index("SCHEMA ="); body = re.sub(r"//[^\n]*", "", s[i:s.index(";\n", i)])
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', body))
def mkchain(path):
    db = sqlite3.connect(path); db.executescript(schema_from(DBC)); now = int(time.time())
    db.executemany("INSERT INTO blocks(height,hash,time,coinbase,bytes,bits) VALUES(?,?,?,?,?,?)",
                   [(h, hashlib.sha256(b"fixture-blk%d" % h).digest(), now - 60 * (TIP - h), 0, 0, 0) for h in range(TIP + 1)])
    db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('height',?)", (str(TIP),))
    for n in ("gdgood", "gdbad"):
        db.execute("INSERT OR REPLACE INTO names(name,owner,owner_type,lease_expiry,st) VALUES(?,?,0,?,0)", (n, H160, 1 << 40))
        db.execute("INSERT OR REPLACE INTO epochs(name,start_height,owner,owner_type) VALUES(?,?,?,0)", (n, 1, H160))
    # full SmState rows: the indexer loads seller/buyer as exact 20-byte blobs
    db.execute("UPDATE names SET seller=zeroblob(20), buyer=zeroblob(20), seller_type=0, price=0, offer_expiry=0, "
               "burn_leg=0, pay_leg=0, reserve_expiry=0")
    db.commit(); db.close()
mkchain(OUT + "/seed-chain.db")
src = sqlite3.connect(OUT + "/seed-chain.db"); dst = sqlite3.connect(OUT + "/node/pep/pep.db"); src.backup(dst); dst.close(); src.close()

# ── seed: publish both signed zones into its store, then serve them ──
def zone(name, tlsa):
    p = "%s/zone-%s.txt" % (OUT, name); open(p, "w").write("@ A 300 %s\n_443._tcp TLSA 300 3 1 1 %s\n" % (ORIGIN_IP, tlsa)); return p
def store_rows(name):
    try:
        d = sqlite3.connect(OUT + "/seed-zones.db", timeout=5); r = d.execute("SELECT count(*) FROM st_rows WHERE name=?", (name,)).fetchone()[0]; d.close(); return r
    except sqlite3.Error: return 0
def seed(name=None, zf=None, log="seed"):
    args = [SEED, "--db", OUT + "/seed-chain.db", "--store", OUT + "/seed-zones.db", "--coin", "pep", "--listen", str(SEED_P2P),
            "--no-sync", "--dns-port", str(SEED_DNS), "--peer", "127.0.0.1:9"]
    if name: args += ["--key", PRIV, "--name", name, "--zone", zf]
    return subprocess.Popen(args, stdout=open("%s/%s.out" % (OUT, log), "a"), stderr=open("%s/%s.err" % (OUT, log), "a"))
for n, t in (("gdgood", GOOD), ("gdbad", BAD)):
    p = seed(n, zone(n, t), "seed-publish-" + n); t0 = time.time()
    while store_rows(n) < 2 and time.time() - t0 < 10: time.sleep(0.2)
    p.terminate(); p.wait(10)
    if store_rows(n) < 2: sys.exit("seed did not publish %s (see %s/seed-publish-%s.err)" % (n, OUT, n))
seedp = seed()

# ── HTTPS origin on ORIGIN_IP:443 (fine inside the user+net namespace) ──
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(OUT + "/origin.crt", OUT + "/origin.key")
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind((ORIGIN_IP, 443)); ls.listen(16)
def origin():
    while True:
        try: c, _ = ls.accept()
        except OSError: return
        def one(c):
            try:
                s = ctx.wrap_socket(c, server_side=True); s.recv(4096)
                body = b"gd fixture origin\n"
                s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body)); s.close()
            except (OSError, ssl.SSLError): c.close()
        threading.Thread(target=one, args=(c,), daemon=True).start()
threading.Thread(target=origin, daemon=True).start()

# ── the lazy node ──
env = dict(os.environ, PEPENET_DNS_PEER="127.0.0.1:%d" % SEED_P2P, PEPENET_DNS_LISTEN=str(NODE_LISTEN), GREATDANE_NODE_SYNC_GRACE_S="8")
env.pop("GREATDANE_NODE_LAZY", None)
node = subprocess.Popen([NODE, "--data", OUT + "/node", "--only", "pep", "--ephemeral-ports", "--dane-api", "--stdio",
                         "--seeds", "127.0.0.1:9", "--lazy", "--lazy-cache-dir", OUT + "/node/lazycache", "--lazy-wait-ms", "0"],
                        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open(OUT + "/node.err", "w"), text=True)
events = []; lock = threading.Lock(); ready = {}
def reader():
    for line in node.stdout:
        with lock: events.append(line.strip())
        if '"event":"ready"' in line: ready.update(json.loads(line))
threading.Thread(target=reader, daemon=True).start()
t0 = time.time()
while not ready and time.time() - t0 < 20: time.sleep(0.1)
if not ready: sys.exit("node never printed its ready event (see %s/node.err)" % OUT)
PAC = ready["pac"]
def http(raw, timeout=12):
    s = socket.create_connection(("127.0.0.1", PAC), timeout); s.sendall(raw.encode()); b = b""
    while True:
        d = s.recv(4096)
        if not d: break
        b += d
    s.close(); return b.decode(errors="replace")
def tlsa(host): return json.loads(http("GET /gd/tlsa?host=%s HTTP/1.1\r\nHost: x\r\n\r\n" % host).partition("\r\n\r\n")[2])
def connect_cert(host):
    """CONNECT host:443 through the node, TLS-handshake WITHOUT verification (Dane does the DANE check), return SPKI sha256."""
    s = socket.create_connection(("127.0.0.1", PAC), 12)
    s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode()); hd = b""
    while b"\r\n\r\n" not in hd:
        d = s.recv(1); 
        if not d: break
        hd += d
    status = hd.decode(errors="replace").split("\r\n")[0]
    if " 200" not in status: s.close(); return status, None
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    t = c.wrap_socket(s, server_hostname=host); der = t.getpeercert(binary_form=True); t.close()
    pem = ssl.DER_cert_to_PEM_cert(der); p = OUT + "/peer-%s.crt" % host; open(p, "w").write(pem)
    return status, spki_sha256(p)
fails = []; report = []
def check(ok, what):
    report.append(("PASS " if ok else "FAIL ") + what)
    if not ok: fails.append(what)
time.sleep(2)   # let the node seat its mesh peer
for host, want in (("gdgood.pepe", GOOD), ("gdbad.pepe", BAD)):
    first = tlsa(host); t1 = time.time(); r = first
    while r.get("status") == "loading" and time.time() - t1 < 15: time.sleep(0.1); r = tlsa(host)
    check(first.get("status") == "loading" and first.get("ede") == 14, "%s first /gd/tlsa -> loading (EDE 14): %s" % (host, first.get("status")))
    data = (r.get("tlsa") or [{}])[0].get("data", "")
    check(r.get("status") == "ok" and data == want, "%s settles to ok in %.2fs with the published TLSA (got %s)" % (host, time.time() - t1, json.dumps(r)[:300]))
    st, spki = connect_cert(host)
    check(spki is not None, "%s CONNECT through the node: %s" % (host, st))
    if host.startswith("gdgood"): check(spki == data, "gdgood.pepe: origin cert SPKI sha256 MATCHES TLSA 3 1 1 (DANE ok)")
    else: check(spki is not None and spki != data, "gdbad.pepe: origin cert SPKI sha256 does NOT match TLSA 3 1 1 (Dane must refuse)")
check(tlsa("gdnone.pepe").get("status") == "unowned", "gdnone.pepe -> unowned")
node.stdin.write('{"cmd":"status"}\n'); node.stdin.flush(); time.sleep(1)
with lock: st = [json.loads(e) for e in events if '"event":"status"' in e]
s = st[-1] if st else {}
check(s.get("namespace_synced") is True, "status namespace_synced true (basis %s, height %s, peers %s)" % (s.get("namespace_sync_basis"), s.get("height"), s.get("peers_out", 0) + s.get("peers_in", 0)))
print("fixture: out=%s node pac/proxy port=%d seed p2p=%d seed dns=%d" % (OUT, PAC, SEED_P2P, SEED_DNS))
print("TLSA good=%s bad=%s" % (GOOD, BAD))
for l in report: print("  " + l)
if a.hold:
    print("holding %d s (Dane: PAC http://127.0.0.1:%d/proxy.pac, /gd/tlsa on the same port)" % (a.hold, PAC)); sys.stdout.flush(); time.sleep(a.hold)
node.stdin.close()
try: node.wait(10)
except subprocess.TimeoutExpired: node.kill()
seedp.terminate(); seedp.wait(10); ls.close()
print("RESULT", "PASS" if not fails else "FAIL", fails); sys.exit(1 if fails else 0)
