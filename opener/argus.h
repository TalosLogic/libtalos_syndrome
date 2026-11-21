/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * argus.h - internal signer-side seam for Argus (test / reference only).
 *
 * In production the signer seals its identity to the opener IN-CIRCUIT (the
 * voleith ring-signature proof); libtalos_syndrome's public surface is the
 * opener side only (syndrome_argus_open, talos_syndrome.h).  This header exposes
 * the *software twin* of that sealing step so the (seal -> open) round-trip can
 * be tested end-to-end without the proof, and so the voleith in-circuit gadget
 * has a byte-exact KAT reference for the K = H(support(e)) framing (DESIGN.md
 * §6.1/§6.2).  It is the faest-ref-style software twin pattern, not a shipped
 * standalone PKE -- the OTP DEM carries no integrity on its own, so callers
 * outside a verifying proof use the general KEM (syndrome_kem_*) instead.
 *
 * Not part of the public surface; ordinary consumers use talos_syndrome.h.
 */
#ifndef SYNDROME_ARGUS_H
#define SYNDROME_ARGUS_H

#include <stddef.h>
#include <stdint.h>

#include <ichor/pool.h> /* ichor_pool_t (threaded open; NULL = serial) */

#include "set_internal.h" /* syndrome_drbg (via core.h) and the SYNDROME_* sizes */

/*
 * syndrome_argus_seal_derand: produce a tracing tag from an explicit DRBG.
 *
 * Samples a fresh weight-t error e from rng, computes the syndrome s = M*e^T
 * under the opener public key pk, derives K = H(support(e)) with the §6.2 KDF,
 * and writes tag = prim_id || s || (identity XOR K), of length
 * 1 + SYNDROME_ARGUS_TAG_BYTES(identity_len) (the leading byte is the compiled
 * ARGUS_DS_PRIM_ID).  identity_len must be in
 * [1, SYNDROME_ARGUS_ID_MAX_BYTES].  The caller owns rng's lifecycle.  Returns 0
 * on success, negative on bad arguments or sampling failure.
 *
 * The fresh-e-per-call rule (§4.2) is what keeps the one-time pad sound; the
 * derand seam lets the KAT harness drive sealing deterministically from a fixed
 * seed, mirroring syndrome_kem_encap_derand.
 */
static int syndrome_argus_seal_derand(uint8_t *tag,
                                      const uint8_t pk[SYNDROME_PK_BYTES],
                                      const uint8_t *identity,
                                      size_t identity_len, syndrome_drbg *rng);

/*
 * syndrome_argus_open: opener side (the public surface).  The public entrypoint
 * (talos_syndrome.h) dispatches here through the per-set vtable.  Returns
 * SYNDROME_ARGUS_OK (0) on a successful open, else a negative typed status.
 */
static int syndrome_argus_open_impl(uint8_t *identity_out, size_t identity_len,
                                    const uint8_t *tag, size_t tag_len,
                                    const uint8_t sk[SYNDROME_SK_BYTES]);

/*
 * Threaded open: syndrome_argus_open_impl with an optional ichor pool (NULL =
 * serial).  A non-NULL pool parallelises the internal decode; the recovered
 * identity and status are byte-identical for any pool.
 */
static int syndrome_argus_open_impl_ex(uint8_t *identity_out,
                                       size_t identity_len, const uint8_t *tag,
                                       size_t tag_len,
                                       const uint8_t sk[SYNDROME_SK_BYTES],
                                       ichor_pool_t *pool);

/*
 * argus_tail: the post-decode Argus work split out of syndrome_argus_open_impl
 * (support extraction, K = H(support(e')), OTP decrypt under the constant-time
 * validity mask vmask, and the branchless open status).  Declared here so the
 * dudect harness can measure this tail in isolation from the decoder, which has
 * its own target; production code reaches it only through
 * syndrome_argus_open_impl.  vmask is 0xFFFFFFFF when the tag is openable and 0
 * otherwise (the low bit selects OK vs EUNOPENABLE); eb holds the n0 recovered
 * error blocks.
 */
static int argus_tail(uint8_t *identity_out, size_t identity_len,
                      const uint8_t *dem,
                      const uint8_t eb[][SYNDROME_BLOCK_BYTES], uint32_t vmask);

#endif /* SYNDROME_ARGUS_H */
