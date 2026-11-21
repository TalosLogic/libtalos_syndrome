/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kem.h - internal KEM seam (Layer 5).
 *
 * Derandomized entrypoints.  The public syndrome_kem_keypair / encap
 * (talos_syndrome.h) draw system entropy, seed an AES-CTR DRBG, and delegate to
 * these; exposing the DRBG lets the KAT harness drive keygen+encap
 * deterministically from a fixed seed.  This is the FIPS 203
 * KeyGen_internal / Encaps_internal split, adapted: our H sampling is a
 * rejection loop over a DRBG (variable randomness consumption), so the coins are
 * an explicit DRBG handle rather than FIPS 203's fixed-length (d, z) / m.
 *
 * Not part of the public surface; ordinary consumers use talos_syndrome.h.
 */
#ifndef SYNDROME_KEM_H
#define SYNDROME_KEM_H

#include <stdint.h>

#include <ichor/pool.h> /* ichor_pool_t (threaded decap; NULL = serial) */

#include "set_internal.h" /* syndrome_drbg (via core.h) and the SYNDROME_* sizes */

/*
 * syndrome_kem_keypair_derand: keypair from an explicit DRBG.  Consumes rng for
 * the QC-MDPC keygen (with internal resampling on a non-invertible block) and
 * the implicit-rejection secret sigma.  The caller owns rng's lifecycle.
 * Returns 0 on success, negative on keygen failure.
 */
static int syndrome_kem_keypair_derand(uint8_t pk[SYNDROME_PK_BYTES],
                                       uint8_t sk[SYNDROME_SK_BYTES],
                                       syndrome_drbg *rng);

/*
 * syndrome_kem_encap_derand: encapsulation from an explicit DRBG.  Consumes rng
 * for the fresh weight-t error.  The caller owns rng's lifecycle.  Returns 0 on
 * success, negative on sampling failure.
 */
static int syndrome_kem_encap_derand(uint8_t ct[SYNDROME_CT_BYTES],
                                     uint8_t k[SYNDROME_SS_BYTES],
                                     const uint8_t pk[SYNDROME_PK_BYTES],
                                     syndrome_drbg *rng);

/*
 * syndrome_kem_decap: FO decapsulation with constant-time implicit rejection.
 * The public entrypoint (talos_syndrome.h) dispatches here through the per-set
 * vtable; never an error/decode-failure oracle.  Returns 0 always.
 */
static int syndrome_kem_decap_impl(uint8_t k[SYNDROME_SS_BYTES],
                                   const uint8_t ct[SYNDROME_CT_BYTES],
                                   const uint8_t sk[SYNDROME_SK_BYTES]);

/*
 * Threaded decap: syndrome_kem_decap_impl with an optional ichor pool (NULL =
 * serial).  A non-NULL pool parallelises the internal decode; the shared secret
 * is byte-identical for any pool.
 */
static int syndrome_kem_decap_impl_ex(uint8_t k[SYNDROME_SS_BYTES],
                                      const uint8_t ct[SYNDROME_CT_BYTES],
                                      const uint8_t sk[SYNDROME_SK_BYTES],
                                      ichor_pool_t *pool);

/*
 * syndrome_kem_pubkey_from_sk_impl: recompute the public key M from a serialized
 * secret key alone (M_b = H_{n0-1}^{-1} H_b), for the Proteus seed API
 * (DESIGN.md §5).  Deserializes and validates the H index lists (a boundary
 * check on an untrusted sk: every index < p) and returns negative on a malformed
 * sk (out-of-range index or a non-invertible last block).  Dispatched through the
 * per-set vtable.
 */
static int
syndrome_kem_pubkey_from_sk_impl(uint8_t pk[SYNDROME_PK_BYTES],
                                 const uint8_t sk[SYNDROME_SK_BYTES]);

#endif /* SYNDROME_KEM_H */
