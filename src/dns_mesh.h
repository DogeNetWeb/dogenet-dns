/* dns_mesh.h — coin-agnostic include of the shared mesh headers.
 *
 * The DNS layer is shared by the DogeNet tree (dogenet-mesh, include dir
 * dogenet/) and the PepeNet / greatdane-node tree (mesh, include dir
 * pepenet/). Every src/ file includes this instead of naming one coin's dir.
 * Force one with -DDNS_MESH_DOGENET or -DDNS_MESH_PEPENET; otherwise the
 * header that is on the include path wins (dogenet first). */
#ifndef DNS_MESH_H
#define DNS_MESH_H

#if defined(DNS_MESH_PEPENET)
#  include "pepenet/state.h"
#  include "pepenet/wire.h"
#  include "pepenet/crypto.h"
#elif defined(DNS_MESH_DOGENET)
#  include "dogenet/state.h"
#  include "dogenet/wire.h"
#  include "dogenet/crypto.h"
#elif defined(__has_include)
#  if __has_include("dogenet/state.h")
#    include "dogenet/state.h"
#    include "dogenet/wire.h"
#    include "dogenet/crypto.h"
#  elif __has_include("pepenet/state.h")
#    include "pepenet/state.h"
#    include "pepenet/wire.h"
#    include "pepenet/crypto.h"
#  else
#    error "dns_mesh.h: neither dogenet/state.h nor pepenet/state.h is on the include path"
#  endif
#else
#  include "dogenet/state.h"
#  include "dogenet/wire.h"
#  include "dogenet/crypto.h"
#endif

#endif
