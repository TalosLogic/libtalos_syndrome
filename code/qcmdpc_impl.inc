/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * qcmdpc.c - QC-MDPC key material: sample private sparse H (weight-v rows),
 * form public systematic M = H_{n0-1}^{-1} H.
 *
 * The private parity-check matrix H has n0 circulant blocks H_0..H_{n0-1}, each
 * of weight v (odd, so the element is a unit in R = F_2[x]/(x^p-1)).  The last
 * block H_{n0-1} is the one inverted; the public systematic matrix has n0-1
 * non-identity blocks:
 *
 *   M_b = H_{n0-1}^{-1} * H_b  in R,   b = 0 .. n0-2
 *
 * so pk = M_0 || .. || M_{n0-2} (n0-1 SYNDROME_BLOCK_BYTES blocks, each
 * little-endian).  The trailing identity block of M is implicit and not stored.
 * For n0 = 2 this is the single block M_0 = H_1^{-1} H_0, and the DRBG draw order
 * (H_0 then H_1) is preserved, so the frozen n0=2 wire vectors do not move.
 *
 * Invariant used by the selftest: H_{n0-1} * M_b = H_b for every b.
 */
#include <stdint.h>
#include <string.h>

#include <ichor/util.h>

#include "code.h"

/*
 * build_dense: scatter the weight-v index list cols[w] into a fresh
 * SYNDROME_BLOCK_BYTES byte buffer buf, then load it into the limb array r.
 * buf is caller-supplied scratch; it is zeroed on entry by the caller and
 * must be zeroed by the caller after use.
 */
static void
build_dense(uint64_t *r, uint8_t *buf, const uint16_t *cols, uint32_t w)
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

int
syndrome_qcmdpc_keygen(syndrome_qcmdpc_sk *sk, uint8_t *pk, syndrome_drbg *rng)
{
    /* Dense numerator blocks H_0..H_{n0-2} (kept fixed across resamples). */
    uint64_t h[SYNDROME_N0 - 1][SYNDROME_GF2X_LIMBS];
    /* Dense last block H_{n0-1}, its inverse, and one systematic product. */
    uint64_t hlast[SYNDROME_GF2X_LIMBS];
    uint64_t inv[SYNDROME_GF2X_LIMBS];
    uint64_t m[SYNDROME_GF2X_LIMBS];
    /* Byte-level scatter scratch buffer (secret). */
    uint8_t buf[SYNDROME_BLOCK_BYTES];
    /* Index list for one sampled block. */
    uint32_t idx[SYNDROME_V];
    uint32_t b, i;
    int ret;

    /*
     * Sample the n0-1 numerator blocks H_0..H_{n0-2} (weight v over p) and keep
     * their dense forms; these stay fixed if the last block must be resampled.
     * For n0 = 2 this draws exactly H_0, matching the old draw order.
     */
    for (b = 0; b < (uint32_t)(SYNDROME_N0 - 1); b++) {
        ret = syndrome_sample_fixed_weight(idx, SYNDROME_V, SYNDROME_P, rng);
        if (ret != 0)
            goto fail;
        for (i = 0; i < (uint32_t)SYNDROME_V; i++)
            sk->cols[b][i] = (uint16_t)idx[i];
        memset(buf, 0, sizeof(buf));
        syndrome_sample_scatter(buf, SYNDROME_BLOCK_BYTES, idx, SYNDROME_V,
                                SYNDROME_P);
        syndrome_gf2x_load(h[b], buf);
    }

    /*
     * Sample the last block H_{n0-1} and compute its inverse.  If it is not
     * invertible in R (a negligible-probability event for odd-weight elements),
     * discard it and resample.  This is the only data-dependent branch in
     * keygen; it depends solely on ephemeral fresh key material -- the same
     * situation as RSA prime generation -- and is not observable by any attacker
     * who does not already know the private key.
     */
    for (;;) {
        ret = syndrome_sample_fixed_weight(idx, SYNDROME_V, SYNDROME_P, rng);
        if (ret != 0)
            goto fail;
        memset(buf, 0, sizeof(buf));
        syndrome_sample_scatter(buf, SYNDROME_BLOCK_BYTES, idx, SYNDROME_V,
                                SYNDROME_P);
        syndrome_gf2x_load(hlast, buf);

        /* syndrome_gf2x_inv requires output not aliasing input. */
        ret = syndrome_gf2x_inv(inv, hlast);
        if (ret == 0)
            break; /* invertible; proceed */

        /* Non-invertible: wipe the last block and try again. */
        ichor_secure_zero(hlast, sizeof(hlast));
    }

    /* Store H_{n0-1} support. */
    for (i = 0; i < (uint32_t)SYNDROME_V; i++)
        sk->cols[SYNDROME_N0 - 1][i] = (uint16_t)idx[i];

    /* Public systematic blocks M_b = H_{n0-1}^{-1} * H_b, b = 0..n0-2. */
    for (b = 0; b < (uint32_t)(SYNDROME_N0 - 1); b++) {
        syndrome_gf2x_mul(m, inv, h[b]);
        syndrome_gf2x_store(pk + b * (size_t)SYNDROME_BLOCK_BYTES, m);
    }

    ret = 0;
    goto out;

fail:
    /*
     * On failure, wipe sk->cols so the caller does not observe a partially
     * initialised private key.
     */
    ichor_secure_zero(sk->cols, sizeof(sk->cols));
    ret = -1;

out:
    /* Wipe all secret intermediates regardless of success or failure. */
    ichor_secure_zero(h, sizeof(h));
    ichor_secure_zero(hlast, sizeof(hlast));
    ichor_secure_zero(inv, sizeof(inv));
    ichor_secure_zero(m, sizeof(m));
    ichor_secure_zero(buf, sizeof(buf));
    ichor_secure_zero(idx, sizeof(idx));
    return ret;
}

int
syndrome_qcmdpc_selftest(void)
{
    /*
     * Fixed 48-byte seed for the DRBG, matching the NIST PQC KAT convention
     * (bytes 0x00..0x2f).
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
    uint8_t pk2[SYNDROME_PK_BYTES];
    uint8_t buf[SYNDROME_BLOCK_BYTES];
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t m[SYNDROME_GF2X_LIMBS];
    uint64_t check[SYNDROME_GF2X_LIMBS];
    uint32_t i, b;
    int ret = -1;

    syndrome_drbg_init(&rng, seed);

    if (syndrome_qcmdpc_keygen(&sk, pk, &rng) != 0)
        goto done;

    /* --- Weight checks -------------------------------------------------- */

    /*
     * Reconstruct every dense H_b from its index list and verify that each
     * block has exactly weight SYNDROME_V.
     */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        memset(buf, 0, sizeof(buf));
        build_dense(h[b], buf, sk.cols[b], SYNDROME_V);
        if (syndrome_bitvec_weight(buf, SYNDROME_P) != (size_t)SYNDROME_V)
            goto done;
    }

    /* --- Invariant: H_{n0-1} * M_b = H_b for every public block b ------- */

    for (b = 0; b < (uint32_t)(SYNDROME_N0 - 1); b++) {
        syndrome_gf2x_load(m, pk + b * (size_t)SYNDROME_BLOCK_BYTES);
        syndrome_gf2x_mul(check, h[SYNDROME_N0 - 1], m);
        for (i = 0; i < (uint32_t)SYNDROME_GF2X_LIMBS; i++)
            if (check[i] != h[b][i])
                goto done;
    }

    /* --- Determinism: same seed -> same pk ------------------------------ */

    syndrome_drbg_init(&rng, seed);
    {
        syndrome_qcmdpc_sk sk2;
        int kr = syndrome_qcmdpc_keygen(&sk2, pk2, &rng);

        ichor_secure_zero(&sk2, sizeof(sk2));
        if (kr != 0)
            goto done;
    }
    if (memcmp(pk, pk2, SYNDROME_PK_BYTES) != 0)
        goto done;

    ret = 0;

done:
    syndrome_drbg_clear(&rng);
    ichor_secure_zero(&sk, sizeof(sk));
    ichor_secure_zero(h, sizeof(h));
    ichor_secure_zero(m, sizeof(m));
    ichor_secure_zero(check, sizeof(check));
    ichor_secure_zero(buf, sizeof(buf));
    ichor_secure_zero(pk, sizeof(pk));
    ichor_secure_zero(pk2, sizeof(pk2));
    return ret;
}
