# dogenet-dns — DNS over the dogenet namespace.
#
# dnsd is a first-class CHAIN peer: it speaks the host chain's P2P protocol on the
# chain port and the DNS mesh rides that same wire as dnz* commands (peer-discovery
# slice 3) — no separate mesh port. So the binary embeds the canonical sync engine
# (../namespace-indexer: idx_serve + indexer_main) alongside dogenet-mesh's
# anchor-ordered state store (sp_state) and the DNS overlay (dns_state/dns_net).
#
# ONE protocol pin, one truth: everything compiles against the INDEXER'S protocol
# submodule (namespace-indexer/protocol), and dogenet-mesh's modules are compiled
# FROM SOURCE against it (never the prebuilt libdogenetnet.a, which bundles its
# own hash/secp objects from a different protocol pin). This mirrors the
# dogenet-desktop CMake composition, which proves the symbol graph links. The
# quoted-"secp256k1.h" own-dir-first dance (protocol-sm shim vs vendored libsecp)
# is handled by the per-group include sets below (INC_IDX has libsecp for its ANGLE
# includes; INC_MESH/INC_DNS do not, so their quoted include resolves to the shim).
#
# The standalone codec/store test keeps a lighter composition (no indexer) —
# see state_dns_test.

CC      ?= cc
CFLAGS  ?= -std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Wshadow

# ── sibling repos (relative, as the dogenet repo family does) ────────────────
MESHDIR := ../dogenet-mesh
IDX     := ../namespace-indexer

# the single protocol pin (the indexer's) + its vendored libsecp + secp shim
SMDIR    := $(IDX)/protocol/impls/c/src
IDXSRC   := $(IDX)/src
SECP_I   := $(IDX)/vendor/secp256k1/include
SHIM     := $(IDX)/protocol/shim/secp_shim.c
IDXSECP  := $(IDX)/build/secp/lib/libsecp256k1.a

LIBS := -lsqlite3 -lpthread

# ── source groups (each compiled with its own include set into build/<grp>) ────
# protocol-sm engine (mirror indexer Makefile ENGINE_CORE + ENGINE_CURVE)
ENGINE_SRC := $(addprefix $(SMDIR)/,fold.c decode.c oracle.c digest.c state.c \
              lease.c market.c claim.c trade.c bitmap.c preblock.c sha256.c \
              ripemd160.c gen.c harness.c ecmh.c)
# indexer chain sources (minus its CLI main.c / test_chain.c) + secp shim
IDX_SRC    := $(addprefix $(IDXSRC)/,attrib.c adapter.c oracle_feed.c db.c chain.c \
              base58.c sync.c pow.c serve_store.c txcheck.c mempool.c) $(SHIM)
# dogenet-mesh facade, from source (sp_* crypto/view/wire/state)
MESH_SRC   := $(addprefix $(MESHDIR)/src/,crypto.c view.c wire.c state.c)
# the DNS overlay + the dnsd driver
DNS_SRC    := src/dns_state.c src/dns_chain.c src/dns_net.c src/zone.c \
              src/dns_wire.c src/dnsd_core.c src/dnsd.c

INC_IDX  := -I$(IDXSRC) -I$(SECP_I) -I$(SMDIR)
INC_MESH := -I$(MESHDIR)/include -I$(SMDIR)
INC_DNS  := -Isrc -I$(MESHDIR)/include -I$(SMDIR) -I$(IDXSRC)

all: dnsd dns-cli

# compile a source group into build/<grp>/<basename>.o (no basename clashes within
# a group; distinct dirs keep e.g. mesh/view.c and indexer objects apart).
define COMPILE_GROUP
	@mkdir -p build/$(1)
	@for f in $(2); do \
	  o=build/$(1)/$$(basename $$f .c).o; \
	  $(CC) $(CFLAGS) $(3) -c $$f -o $$o || exit 1; \
	done
	@touch build/$(1).stamp
endef

build/idx.stamp: $(ENGINE_SRC) $(IDX_SRC)
	$(call COMPILE_GROUP,idx,$(ENGINE_SRC) $(IDX_SRC),$(INC_IDX))
build/mesh.stamp: $(MESH_SRC)
	$(call COMPILE_GROUP,mesh,$(MESH_SRC),$(INC_MESH))
build/dns.stamp: $(DNS_SRC) $(wildcard src/*.h)
	$(call COMPILE_GROUP,dns,$(DNS_SRC),$(INC_DNS))

# link objects directly (order-independent — every .o is pulled unconditionally),
# so the dns↔mesh↔indexer back-references don't need archive grouping.
dnsd: build/idx.stamp build/mesh.stamp build/dns.stamp $(IDXSECP)
	$(CC) $(CFLAGS) -o $@ build/idx/*.o build/mesh/*.o build/dns/*.o $(IDXSECP) $(LIBS)

# vendored libsecp comes from the indexer's own pinned submodule (built by its make)
$(IDXSECP):
	$(MAKE) -C $(IDX) build/secp/lib/libsecp256k1.a

# tiny dependency-free control client (apex validation is server-side)
dns-cli: src/dns-cli.c
	$(CC) $(CFLAGS) -o $@ $<

# ── standalone codec/store proof (lighter composition: no indexer needed) ─────
# Tests the DNS packing + LWW admission + gossip framing in isolation, with a
# fake chain oracle — not the chain-wire node. Links the shared mesh's prebuilt
# lib (it bundles sp_state + the hash/secp shim), same as the old codec tests.
NETLIB   := $(MESHDIR)/libdogenetnet.a
TEST_SRC := test/state_dns_test.c src/dns_state.c src/dns_net.c src/zone.c src/dns_wire.c
INC_TEST := -Isrc -I$(MESHDIR)/include

$(NETLIB):
	$(MAKE) -C $(MESHDIR)

state_dns_test: $(TEST_SRC) $(wildcard src/*.h) $(NETLIB) $(IDXSECP)
	$(CC) $(CFLAGS) $(INC_TEST) -o $@ $(TEST_SRC) $(NETLIB) $(IDXSECP) -lsqlite3

# check also runs the TCP slow-loris liveness test against the built dnsd
# (loopback; run under `unshare -rn`, the test brings lo up itself).
check: state_dns_test dnsd
	./state_dns_test
	python3 test/tcp_loris_test.py ./dnsd

clean:
	rm -rf build dnsd dns-cli state_dns_test

.PHONY: all check clean

# ── focused proofs: the wire parser, the zone parser, the resolver core ──────
# wire_test links NOTHING but src/dns_wire.c — it is a pure adversarial-decode
# harness (round-trip property test + malicious-packet battery + truncation and
# mutation fuzz behind a guard page and an alarm() watchdog), so it needs no
# store, no mesh and no chain. zone_test adds zone.c and the sp_state key codec;
# dnsd_core_test adds the resolver core and answers queries against an in-memory
# store — both on state_dns_test's light composition (the mesh lib + the
# indexer's vendored secp), never the indexer sources.
WIRE_SRC := test/wire_test.c src/dns_wire.c
ZONE_SRC := test/zone_test.c src/zone.c src/dns_wire.c src/dns_state.c
CORE_SRC := test/dnsd_core_test.c src/dnsd_core.c src/dns_state.c src/zone.c src/dns_wire.c

wire_test: $(WIRE_SRC) $(wildcard src/*.h)
	$(CC) $(CFLAGS) -Isrc -o $@ $(WIRE_SRC)

zone_test: $(ZONE_SRC) $(wildcard src/*.h) $(NETLIB) $(IDXSECP)
	$(CC) $(CFLAGS) $(INC_TEST) -o $@ $(ZONE_SRC) $(NETLIB) $(IDXSECP) -lsqlite3

dnsd_core_test: $(CORE_SRC) $(wildcard src/*.h) $(NETLIB) $(IDXSECP)
	$(CC) $(CFLAGS) $(INC_TEST) -o $@ $(CORE_SRC) $(NETLIB) $(IDXSECP) -lsqlite3

# Everything, including the existing codec/store proof. Each binary prints its
# own "N ok, M failed" line and exits non-zero on any FAIL; check-all runs them
# all before reporting, so one failure never hides the rest.
check-all: check wire_test zone_test dnsd_core_test
	@rc=0; for t in wire_test zone_test dnsd_core_test; do \
	  echo "=== $$t ==="; ./$$t || rc=1; echo; done; \
	  if [ $$rc -ne 0 ]; then echo "check-all: FAILURES above"; else echo "check-all: all passed"; fi; \
	  exit $$rc

# A longer adversarial soak over several seeds (~2M decodes per seed).
check-fuzz: wire_test
	@for s in 1 7 42 999 20260726 123456789; do \
	  echo "=== wire_test seed $$s ==="; WIRE_SEED=$$s WIRE_FUZZ_X=25 ./wire_test | tail -1 || exit 1; \
	done

clean-tests:
	rm -f wire_test zone_test dnsd_core_test net_test

.PHONY: check-all check-fuzz clean-tests

# ── the adversarial gossip suite (src/dns_net.c) ─────────────────────────────
# Deliberately OUTSIDE check-all: its last section proves a real convergence
# defect (two nodes whose 8 KB budgets are both full of different records
# ping-pong inv→get→dat forever, because on_zdat answers a no-change dump with
# another inv), so it exits non-zero. Folding it into check-all would make the
# green suite red for a reason that is not a regression — the same split
# dogenet-tls uses for check-deep.
#
#   make check-gossip     peer table, hostile frames, 200k-mutation fuzz,
#                         inv/get/dat semantics, the hold queue, convergence
NET_SRC := test/net_test.c src/dns_net.c src/dns_state.c src/zone.c src/dns_wire.c

net_test: $(NET_SRC) $(wildcard src/*.h) $(NETLIB) $(IDXSECP)
	$(CC) $(CFLAGS) $(INC_TEST) -o $@ $(NET_SRC) $(NETLIB) $(IDXSECP) -lsqlite3

check-gossip: net_test
	./net_test

.PHONY: check-gossip

# two-node no-change-reply loop test: dns_net.c compiled twice (A_/B_ symbols,
# faked time()) — a patched pair, and both mixed pairs (one side built with
# DNSNET_RL_SLOTS=0, i.e. today's behaviour). Wire-neutral rate limit.
LOOP_REN = $(foreach f,init up msg down tick announce peers,-Ddnsnet_$(f)=$(1)_dnsnet_$(f))
LOOP_LIB = test/loop_test.c src/dns_state.c src/zone.c src/dns_wire.c $(NETLIB) $(IDXSECP) -lsqlite3
define LOOP_BIN
$(1): test/loop_test.c src/dns_net.c $(wildcard src/*.h) $(NETLIB) $(IDXSECP)
	@mkdir -p build/loop
	$(CC) $(CFLAGS) $(INC_TEST) $$(call LOOP_REN,A) -Dtime=ft_time $(2) -c src/dns_net.c -o build/loop/$(1)_A.o
	$(CC) $(CFLAGS) $(INC_TEST) $$(call LOOP_REN,B) -Dtime=ft_time $(3) -c src/dns_net.c -o build/loop/$(1)_B.o
	$(CC) $(CFLAGS) $(INC_TEST) '-DCHAIN_CRYPTO_H="dogenet/crypto.h"' $(if $(2),-DLOOP_A_LEGACY) $(if $(3),-DLOOP_B_LEGACY) -o $$@ build/loop/$(1)_A.o build/loop/$(1)_B.o $(LOOP_LIB)
endef
$(eval $(call LOOP_BIN,loop_test,,))
$(eval $(call LOOP_BIN,loop_test_mixAB,,-DDNSNET_RL_SLOTS=0))
$(eval $(call LOOP_BIN,loop_test_mixBA,-DDNSNET_RL_SLOTS=0,))
$(eval $(call LOOP_BIN,loop_test_legacy,-DDNSNET_RL_SLOTS=0,-DDNSNET_RL_SLOTS=0))

check-loop: loop_test loop_test_mixAB loop_test_mixBA
	./loop_test && ./loop_test_mixAB && ./loop_test_mixBA

# today's behaviour (no limiter on either side): expected to FAIL
check-loop-legacy: loop_test_legacy
	! ./loop_test_legacy

.PHONY: check-loop

# lease gate on chain MTP (no indexer sources: dns_chain.c + sqlite only)
dns_chain_test: test/dns_chain_test.c src/dns_chain.c src/dns_chain.h
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE -Isrc -I$(MESHDIR)/include -o $@ test/dns_chain_test.c src/dns_chain.c -lsqlite3
