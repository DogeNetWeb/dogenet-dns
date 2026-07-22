# pepenet-dns — DNS over the pepenet namespace.
#
# dnsd is a first-class CHAIN peer: it speaks the host chain's P2P protocol on the
# chain port and the DNS mesh rides that same wire as dnz* commands (peer-discovery
# slice 3) — no separate mesh port. So the binary embeds the canonical sync engine
# (../namespace-indexer: idx_serve + indexer_main) alongside pepenet-mesh's
# anchor-ordered state store (sp_state) and the DNS overlay (dns_state/dns_net).
#
# ONE protocol pin, one truth: everything compiles against the INDEXER'S protocol
# submodule (namespace-indexer/protocol), and pepenet-mesh's modules are compiled
# FROM SOURCE against it (never the prebuilt libpepenetnet.a, which bundles its
# own hash/secp objects from a different protocol pin). This mirrors the
# pepenet-desktop CMake composition, which proves the symbol graph links. The
# quoted-"secp256k1.h" own-dir-first dance (protocol-sm shim vs vendored libsecp)
# is handled by the per-group include sets below (INC_IDX has libsecp for its ANGLE
# includes; INC_MESH/INC_DNS do not, so their quoted include resolves to the shim).
#
# The standalone codec/store test keeps a lighter composition (no indexer) —
# see state_dns_test.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wshadow

# ── sibling repos (relative, as the pepenet repo family does) ────────────────
MESHDIR := ../pepenet-mesh
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
# pepenet-mesh facade, from source (sp_* crypto/view/wire/state)
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
NETLIB   := $(MESHDIR)/libpepenetnet.a
TEST_SRC := test/state_dns_test.c src/dns_state.c src/dns_net.c src/zone.c src/dns_wire.c
INC_TEST := -Isrc -I$(MESHDIR)/include

$(NETLIB):
	$(MAKE) -C $(MESHDIR)

state_dns_test: $(TEST_SRC) $(wildcard src/*.h) $(NETLIB) $(IDXSECP)
	$(CC) $(CFLAGS) $(INC_TEST) -o $@ $(TEST_SRC) $(NETLIB) $(IDXSECP) -lsqlite3

check: state_dns_test
	./state_dns_test

clean:
	rm -rf build dnsd dns-cli state_dns_test

.PHONY: all check clean
