/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * set_bodies.inc - the canonical ordered list of generic per-set implementation
 * bodies, plus the parameter table they compile against.
 *
 * Single source of truth for "what makes up one set's implementation", used two
 * ways, both requiring SYNDROME_LAMBDA and SYNDROME_N0 to be defined first:
 *   1. Production: each per-set wrapper (sets/syn_<lambda>_<n0>.c) includes this,
 *      then defines the exported vtable over the now-static bodies.
 *   2. Tests: each per-set test binary force-includes this (-include) with
 *      -DSYNDROME_LAMBDA / -DSYNDROME_N0, so the test TU carries its own static
 *      copy of the algorithm and can call the internal selftests / seams
 *      directly (the shared DRBG + bit vectors still come from libtalos_syndrome).
 *
 * Order matters only for readability (headers declare everything up front): core
 * arithmetic, then code, decoder, PKE, KEM, opener.  Paths are relative to this
 * file (sets/), so it works from any include site.
 */
#include "set_params.h"

#include "../core/gf2x_impl.inc"
#include "../core/sample_impl.inc"
#include "../code/qcmdpc_impl.inc"
#include "../code/synmap_impl.inc"
#include "../decoder/threshold_impl.inc"
#include "../decoder/bitflip_impl.inc"
#include "../pke/niederreiter_impl.inc"
#include "../kem/kem_impl.inc"
#include "../opener/argus_impl.inc"
