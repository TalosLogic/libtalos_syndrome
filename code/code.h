/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * code.h - internal interface for Layer 2 (code/).
 *
 * QC-MDPC code: private sparse parity-check matrix H and the public
 * systematic matrix M = H_{n0-1}^{-1} H, plus syndrome computation.
 * Consumers of this header must also include core.h (gives the parameter
 * macros, syndrome_drbg, and the gf2x/sample API).
 */
#ifndef SYNDROME_CODE_H
#define SYNDROME_CODE_H

#include <stddef.h>
#include <stdint.h>

#include "set_internal.h" /* gf2x/sample (static), sizes, and (via core.h) drbg */

/*
 * In-memory private key for the QC-MDPC Niederreiter scheme.
 *
 * Stores the support (set-bit positions) of each row of the private
 * parity-check matrix H.  H has n0 circulant blocks of weight v; since
 * p < 2^16, each position fits in 16 bits.  The decoder works directly
 * from these index lists in constant-time inner loops (no dense expansion
 * in the hot path).
 */
typedef struct {
    uint16_t cols[SYNDROME_N0][SYNDROME_V]; /* bit positions of each H block */
} syndrome_qcmdpc_sk;

/*
 * syndrome_qcmdpc_keygen: sample a fresh QC-MDPC key pair.
 *
 * Writes the private key into *sk (the weight-v index lists for each H
 * block) and the public key into pk[SYNDROME_PK_BYTES] (the single
 * systematic block M_0 = H_1^{-1} H_0 packed little-endian).
 *
 * All randomness is drawn from rng, which the caller initialises.
 *
 * Constant-time discipline: sampling and all circulant arithmetic are
 * data-independent.  The sole data-dependent control flow is the keygen
 * resample loop: if the freshly-sampled H_1 block is not invertible in
 * R = F_2[x]/(x^p-1), its indices and dense representation are discarded
 * and a new sample is drawn.  This mirrors RSA prime-generation: the
 * branch depends only on freshly-sampled secret key material -- not on any
 * attacker-observable quantity, since keygen is not an oracle.  Non-
 * invertibility is a negligible-probability event (weight-v odd-weight
 * elements are almost always units).
 *
 * Returns 0 on success, negative on RNG or allocation failure.
 */
static int syndrome_qcmdpc_keygen(syndrome_qcmdpc_sk *, uint8_t *,
                                  syndrome_drbg *);

/*
 * syndrome_synmap_encode: public syndrome (ciphertext)
 * s = sum_{i<n0-1} m[i]*e[i] + e[n0-1] in R.
 *
 * s is the output limb array (length SYNDROME_GF2X_LIMBS); m is the systematic
 * public-key blocks (SYNDROME_N0 - 1 rows) and e the error-vector blocks
 * (SYNDROME_N0 rows), each a ring element of length SYNDROME_GF2X_LIMBS.  s must
 * not alias any row of m or e.
 */
static void syndrome_synmap_encode(uint64_t *,
                                   const uint64_t (*)[SYNDROME_GF2X_LIMBS],
                                   const uint64_t (*)[SYNDROME_GF2X_LIMBS]);

/*
 * syndrome_synmap_private: private syndrome sp = h1*s in R, the input the
 * bit-flip decoder consumes.
 *
 * sp is the output limb array; h1 and s are inputs.  sp may alias s but
 * must not alias h1.
 */
static void syndrome_synmap_private(uint64_t *, const uint64_t *,
                                    const uint64_t *);

static int syndrome_qcmdpc_selftest(void);
static int syndrome_synmap_selftest(void);

#endif /* SYNDROME_CODE_H */
