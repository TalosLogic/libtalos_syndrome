/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * set_internal.h - per-set internal declarations (parameter-dependent).
 *
 * NOT a standalone translation unit: included only from a per-set wrapper TU
 * (sets/syn_<lambda>_<n0>.c) or from an *_impl.inc body pulled into one, after
 * SYNDROME_LAMBDA / SYNDROME_N0 are #defined and set_params.h has materialized
 * the size macros.  Declares the circulant arithmetic (gf2x) and fixed-weight
 * sampler as `static`, so each set compiles its own internal-linkage copy sized
 * by that set's constants -- the whole point of the per-set build.  The DRBG and
 * bit vectors it builds on are parameter-free and come from core.h (shared).
 */
#ifndef SYNDROME_SET_INTERNAL_H
#define SYNDROME_SET_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "core.h"       /* syndrome_drbg + bit vectors (shared, extern) */
#include "set_params.h" /* SYNDROME_P/V/T/N and the size macros         */

/*
 * Ring element = length-p bit vector packed little-endian into 64-bit limbs:
 * the coefficient of x^i is bit (i % 64) of limb (i / 64); the unused high bits
 * of the top limb are kept zero (canonical).  load/store convert to and from the
 * external little-endian byte packing (SYNDROME_BLOCK_BYTES).  add and mul are
 * constant-time over secret contents; mul is a carry-less product reduced
 * modulo x^p - 1.  The bodies are thin wrappers over the shared ichor gf2x ring
 * (<ichor/gf2x.h>); see core/gf2x_impl.inc.
 */
#define SYNDROME_GF2X_LIMBS ((SYNDROME_P + 63) / 64)

static void syndrome_gf2x_load(uint64_t *, const uint8_t *);
static void syndrome_gf2x_store(uint8_t *, const uint64_t *);
static void syndrome_gf2x_add(uint64_t *, const uint64_t *, const uint64_t *);
static void syndrome_gf2x_mul(uint64_t *, const uint64_t *, const uint64_t *);

/*
 * out = in rotated left by a SECRET amount k (out = in * x^k in R, i.e.
 * out[m] = in[(m - k) mod p]).  k is taken mod p, so k in [0, p] is accepted
 * and k == p is the identity.  Constant-time in both in (secret contents) and
 * k (secret amount): a fixed log2(p)-step barrel of rotate-by-2^i passes, each
 * selected by bit i of k through an arithmetic mask, so no branch or memory
 * index depends on k.  out may alias in.
 *
 * The decoder's counter path wants v[m] = s[(m + p_k) mod p] for a secret
 * support offset p_k; obtain it as syndrome_gf2x_rotl_var(v, s, p - p_k).
 */
static void syndrome_gf2x_rotl_var(uint64_t *, const uint64_t *, uint32_t);

/*
 * r = a^{-1} in R, for a unit a (odd-weight H block).  Constant-time in a
 * (Itoh-Tsujii; the chain depends only on the public p).  r must not alias a.
 * Returns 0 on success, -1 if a is not invertible (keygen resamples).
 */
static int syndrome_gf2x_inv(uint64_t *, const uint64_t *);

/*
 * Constant-time fixed-weight sampling (no secret-dependent control flow, no
 * secret-indexed memory access).
 *
 * fixed_weight(idx, w, n, rng): w distinct indices in [0, n), drawn (in draw
 * order) by the shared libtalos_ichor overlay Fisher-Yates; this wrapper only
 * expands the DRBG into the sampler tape (one lambda+64-bit draw per index, so
 * the residual bias sits below 2^-lambda).  scatter(vec, nbytes, idx, w, n):
 * obliviously set the w listed bits into a dense little-endian bit vector
 * (order-independent).
 */
static int syndrome_sample_fixed_weight(uint32_t *, uint32_t, uint32_t,
                                        syndrome_drbg *);
static void syndrome_sample_scatter(uint8_t *, size_t, const uint32_t *,
                                    uint32_t, uint32_t);

static int syndrome_gf2x_selftest(void);
static int syndrome_sample_selftest(void);

#endif /* SYNDROME_SET_INTERNAL_H */
