/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * syndrome.c - syndrome maps: public s = M * e^T and the private decoder
 * input s' = H_{n0-1} * s.
 *
 * For n0 = 2:
 *   encode:  s  = M_0*e_0 + e_1  in R = F_2[x]/(x^p-1)
 *   private: s' = H_1*s           in R
 *
 * The invariant tying the two maps to keygen (H_1*M_0 = H_0) gives:
 *   s' = H_1*(M_0*e_0 + e_1) = H_0*e_0 + H_1*e_1
 *
 * The (M, s) byte layout produced by encode() is the shared contract with
 * libtalos_voleith and must stay stable once frozen.
 */
#include <stdint.h>
#include <string.h>

#include <ichor/util.h>

#include "code.h"

/*
 * build_dense_from_cols: scatter a weight-v uint16_t index list into a fresh
 * BLOCK_BYTES byte buffer buf, then load it into the limb array r.  buf must
 * be zeroed on entry.
 */
static void
build_dense_from_cols(uint64_t *r, uint8_t *buf, const uint16_t *cols,
                      uint32_t w)
{
    uint32_t idx[SYNDROME_V];
    uint32_t i;

    for (i = 0; i < w; i++)
        idx[i] = (uint32_t)cols[i];
    syndrome_sample_scatter(buf, SYNDROME_BLOCK_BYTES, idx, w, SYNDROME_P);
    syndrome_gf2x_load(r, buf);

    /* idx holds the secret H-block support; wipe it (buf is the caller's). */
    ichor_secure_zero(idx, sizeof(idx));
}

void
syndrome_synmap_encode(uint64_t *s, const uint64_t m[][SYNDROME_GF2X_LIMBS],
                       const uint64_t e[][SYNDROME_GF2X_LIMBS])
{
    uint64_t tmp[SYNDROME_GF2X_LIMBS];
    uint32_t i;

    /* s = e[n0-1]; then s += sum_{i<n0-1} m[i]*e[i] (XOR accumulate). */
    memcpy(s, e[SYNDROME_N0 - 1], SYNDROME_GF2X_LIMBS * sizeof(uint64_t));
    for (i = 0; i < (uint32_t)(SYNDROME_N0 - 1); i++) {
        syndrome_gf2x_mul(tmp, m[i], e[i]);
        syndrome_gf2x_add(s, s, tmp);
    }

    /* tmp held a secret m[i]*e[i] product; wipe it.  (s is the public
     * ciphertext output.) */
    ichor_secure_zero(tmp, sizeof(tmp));
}

void
syndrome_synmap_private(uint64_t *sp, const uint64_t *h1, const uint64_t *s)
{
    syndrome_gf2x_mul(sp, h1, s);
}

int
syndrome_synmap_selftest(void)
{
    /*
     * Fixed 48-byte seed (bytes 0x00..0x2f), matching the NIST PQC KAT
     * convention used throughout the test suite.
     */
    static const uint8_t seed[48] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };

    syndrome_drbg rng;
    syndrome_qcmdpc_sk sk;
    uint8_t pk[SYNDROME_PK_BYTES];

    /* Dense H blocks and the public systematic M blocks (n0-1 of them). */
    uint8_t hbuf[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t m[SYNDROME_N0 - 1][SYNDROME_GF2X_LIMBS];

    /* Error-vector blocks (arbitrary fixed bit patterns). */
    uint8_t ebuf[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];

    /* Syndrome temporaries. */
    uint64_t s[SYNDROME_GF2X_LIMBS];
    uint64_t sp[SYNDROME_GF2X_LIMBS];

    /* Expected s' = sum_b H_b*e_b. */
    uint64_t tmp[SYNDROME_GF2X_LIMBS];
    uint64_t expected[SYNDROME_GF2X_LIMBS];

    /* Zero-message sanity: encode with e[0..n0-2]=0 should equal e[n0-1]. */
    uint64_t e_zero[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t s_zero[SYNDROME_GF2X_LIMBS];

    uint32_t i, b;
    int ret = -1;

    syndrome_drbg_init(&rng, seed);

    if (syndrome_qcmdpc_keygen(&sk, pk, &rng) != 0)
        goto done;

    /* Reconstruct dense H_b from the private index lists. */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        memset(hbuf[b], 0, SYNDROME_BLOCK_BYTES);
        build_dense_from_cols(h[b], hbuf[b], sk.cols[b], SYNDROME_V);
    }

    /* Load the n0-1 systematic M blocks from the public key. */
    for (b = 0; b < (uint32_t)(SYNDROME_N0 - 1); b++)
        syndrome_gf2x_load(m[b], pk + b * (size_t)SYNDROME_BLOCK_BYTES);

    /*
     * Build n0 deterministic arbitrary ring elements e[b] by setting a handful
     * of bits at fixed, block-dependent positions in [0, p).  They need not
     * have any particular weight; the invariant holds for all inputs.  The
     * per-block offset keeps the patterns distinct so the test is not
     * degenerate.  SYNDROME_P >= 7829 for all sets, so the positions are in
     * range.
     */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(ebuf[b], 0, SYNDROME_BLOCK_BYTES);
    {
        static const uint32_t base_pos[6] = {0, 63, 255, 767, 2047, 6143};
        uint32_t j;

        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            for (j = 0; j < 6; j++) {
                uint32_t pos = (base_pos[j] + b) % (uint32_t)SYNDROME_P;

                ebuf[b][pos >> 3] |= (uint8_t)(1u << (pos & 7u));
            }
    }
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        syndrome_gf2x_load(e[b], ebuf[b]);

    /* --- Main invariant: s' = sum_b H_b*e_b ----------------------------- */

    syndrome_synmap_encode(s, m, e);
    syndrome_synmap_private(sp, h[SYNDROME_N0 - 1], s);

    /* Compute expected = sum_b H_b*e_b directly. */
    memset(expected, 0, sizeof(expected));
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        syndrome_gf2x_mul(tmp, h[b], e[b]);
        syndrome_gf2x_add(expected, expected, tmp);
    }

    for (i = 0; i < (uint32_t)SYNDROME_GF2X_LIMBS; i++) {
        if (sp[i] != expected[i])
            goto done;
    }

    /* --- Sanity: encode with all message blocks zero == e[n0-1] --------- */

    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(e_zero[b], 0, SYNDROME_GF2X_LIMBS * sizeof(uint64_t));
    memcpy(e_zero[SYNDROME_N0 - 1], e[SYNDROME_N0 - 1],
           SYNDROME_GF2X_LIMBS * sizeof(uint64_t));
    syndrome_synmap_encode(s_zero, m, e_zero);

    for (i = 0; i < (uint32_t)SYNDROME_GF2X_LIMBS; i++) {
        if (s_zero[i] != e[SYNDROME_N0 - 1][i])
            goto done;
    }

    ret = 0;

done:
    syndrome_drbg_clear(&rng);
    ichor_secure_zero(&sk, sizeof(sk));
    ichor_secure_zero(h, sizeof(h));
    ichor_secure_zero(m, sizeof(m));
    ichor_secure_zero(hbuf, sizeof(hbuf));
    ichor_secure_zero(e, sizeof(e));
    ichor_secure_zero(ebuf, sizeof(ebuf));
    ichor_secure_zero(s, sizeof(s));
    ichor_secure_zero(sp, sizeof(sp));
    ichor_secure_zero(tmp, sizeof(tmp));
    ichor_secure_zero(expected, sizeof(expected));
    ichor_secure_zero(e_zero, sizeof(e_zero));
    ichor_secure_zero(s_zero, sizeof(s_zero));
    ichor_secure_zero(pk, sizeof(pk));
    return ret;
}
