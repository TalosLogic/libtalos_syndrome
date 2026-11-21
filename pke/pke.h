/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * pke.h - internal interface for Layer 4 (pke/).
 *
 * QC-MDPC Niederreiter PKE (Fig. 1, ePrint 2025/1043): keygen, encrypt
 * (ciphertext s = M*e^T), decrypt (private syndrome s' = H_{n0-1}*s, then the
 * 3-iteration bit-flipping decode).  The KEM layer (kem/) is built on this;
 * consumers never see it directly.  Pulls in code.h for the private-key type
 * and the gf2x/sample API, and decoder.h for the decode primitive.
 */
#ifndef SYNDROME_PKE_H
#define SYNDROME_PKE_H

#include <stdint.h>

#include "code.h"
#include "decoder.h"

/*
 * syndrome_pke_keygen: sample a Niederreiter key pair (Fig. 1 KeyGeneration).
 *
 * Thin wrapper over the QC-MDPC keygen: writes the private H index lists into
 * *sk and the systematic public block M_0 = H_1^{-1} H_0 into pk
 * (SYNDROME_PK_BYTES).  Returns 0 on success, negative on RNG or allocation
 * failure.
 */
static int syndrome_pke_keygen(syndrome_qcmdpc_sk *, uint8_t *,
                               syndrome_drbg *);

/*
 * syndrome_pke_encrypt: Niederreiter encryption (Fig. 1).
 *
 * Computes the ciphertext syndrome s = M*e^T = sum_{i<n0-1} m_i*e_i + e_{n0-1}
 * in R from the systematic public key pk (SYNDROME_PK_BYTES) and the n0
 * weight-split blocks e[0..n0-1] of the weight-t error (SYNDROME_N0-row array of
 * ring elements, each length SYNDROME_GF2X_LIMBS).  Writes the packed syndrome
 * into ct (SYNDROME_CT_BYTES).  Pure circulant arithmetic: data-independent and
 * constant-time over the secret error.
 */
static void syndrome_pke_encrypt(uint8_t *, const uint8_t *,
                                 const uint64_t (*)[SYNDROME_GF2X_LIMBS]);

/*
 * syndrome_pke_decrypt: Niederreiter decryption (Fig. 1).
 *
 * Expands the private H from sk, forms the private syndrome s' = H_{n0-1}*s
 * from the ciphertext ct (SYNDROME_CT_BYTES), and runs the bit-flipping
 * decoder.  Writes the recovered error blocks e[0..n0-1] (SYNDROME_N0-row array
 * of ring elements) and sets *ok to 1 on a successful decode, else 0.
 *
 * Constant-time across success and failure: e and *ok are always written with
 * data-independent control flow.  The Fig. 1 "return bottom on failure" step is
 * NOT taken here -- the KEM layer realises it through constant-time implicit
 * rejection, so decrypt is never a decode-failure oracle.
 */
static void syndrome_pke_decrypt(uint64_t (*)[SYNDROME_GF2X_LIMBS], int *,
                                 const syndrome_qcmdpc_sk *, const uint8_t *,
                                 ichor_pool_t *);

static int syndrome_niederreiter_selftest(void);

#endif /* SYNDROME_PKE_H */
