/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * niederreiter.c - QC-MDPC Niederreiter PKE (Fig. 1, ePrint 2025/1043).
 *
 * keygen -> (sk = {H}, pk = {M_0}); encrypt(pk, e) -> s = M*e^T = m0*e0 + e1;
 * decrypt(sk, s) -> s' = H_1*s = h0*e0 + h1*e1, then BitFlippingDecoder(H, s').
 *
 * The private syndrome identity makes decrypt a thin composition: with the
 * systematic public block m0 = H_1^{-1} H_0, multiplying the ciphertext by h1
 * cancels the inverse, h1*(m0*e0 + e1) = h0*e0 + h1*e1, which is exactly the
 * relation the decoder inverts.
 *
 * Constant-time: all circulant arithmetic, the sparse-to-dense H expansion,
 * and the decode are data-independent.  decrypt never branches on decode
 * success; it always writes e0, e1 and a *ok flag, leaving implicit rejection
 * to the KEM layer.  Secret intermediates (the dense H blocks and the private
 * syndrome) are secure-zeroed before return.
 */
#include <stdint.h>
#include <string.h>

#include <ichor/util.h>

#include "pke.h"

/*
 * expand_block - reconstruct a dense H block (ring element) from its sparse
 * weight-v support list.  Mirrors the sampler's oblivious scatter so the
 * placement is data-independent; the scratch buffers are secret (they reveal
 * H) and are secure-zeroed before return.
 */
static void
expand_block(uint64_t *h, const uint16_t *cols)
{
    uint8_t buf[SYNDROME_BLOCK_BYTES];
    uint32_t idx[SYNDROME_V];
    uint32_t i;

    for (i = 0; i < (uint32_t)SYNDROME_V; i++)
        idx[i] = (uint32_t)cols[i];
    syndrome_sample_scatter(buf, SYNDROME_BLOCK_BYTES, idx, SYNDROME_V,
                            SYNDROME_P);
    syndrome_gf2x_load(h, buf);

    ichor_secure_zero(buf, sizeof(buf));
    ichor_secure_zero(idx, sizeof(idx));
}

int
syndrome_pke_keygen(syndrome_qcmdpc_sk *sk, uint8_t *pk, syndrome_drbg *rng)
{
    return syndrome_qcmdpc_keygen(sk, pk, rng);
}

void
syndrome_pke_encrypt(uint8_t *ct, const uint8_t *pk,
                     const uint64_t e[][SYNDROME_GF2X_LIMBS])
{
    uint64_t m[SYNDROME_N0 - 1][SYNDROME_GF2X_LIMBS];
    uint64_t s[SYNDROME_GF2X_LIMBS];
    uint32_t i;

    /* Load the n0-1 systematic public blocks from pk. */
    for (i = 0; i < (uint32_t)(SYNDROME_N0 - 1); i++)
        syndrome_gf2x_load(m[i], pk + i * (size_t)SYNDROME_BLOCK_BYTES);
    syndrome_synmap_encode(s, m, e);
    syndrome_gf2x_store(ct, s);

    /* m is public and s is the ciphertext itself; nothing secret to clear. */
}

void
syndrome_pke_decrypt(uint64_t e[][SYNDROME_GF2X_LIMBS], int *ok,
                     const syndrome_qcmdpc_sk *sk, const uint8_t *ct)
{
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t s[SYNDROME_GF2X_LIMBS];
    uint64_t sp[SYNDROME_GF2X_LIMBS];
    uint32_t b;

    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        expand_block(h[b], sk->cols[b]);

    syndrome_gf2x_load(s, ct);
    /* sp = h_{n0-1}*s = sum_b h_b*e_b (the private syndrome the decoder inverts). */
    syndrome_synmap_private(sp, h[SYNDROME_N0 - 1], s);

    syndrome_bitflip_decode(e, ok, h, sk->cols, sp);

    ichor_secure_zero(h, sizeof(h));
    ichor_secure_zero(sp, sizeof(sp));
    /* s is the public ciphertext; no need to clear it. */
}

/* ========================================================================
 * Self-test (docs/TESTING.md): full encrypt/decrypt round-trip through the
 * public M, exercising the M_0 = H_1^{-1} H_0 relation and the private-
 * syndrome map in addition to the decoder.
 * ======================================================================== */

int
syndrome_niederreiter_selftest(void)
{
    /* Fixed 48-byte seed (bytes 0x00..0x2f), the NIST PQC KAT convention. */
    static const uint8_t seed[48] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    };

    syndrome_drbg rng;
    syndrome_qcmdpc_sk sk;
    uint8_t pk[SYNDROME_PK_BYTES];
    uint8_t ct[SYNDROME_CT_BYTES];

    /* Weight-t error over n = n0*p, split into n0 dense blocks. */
    uint32_t eidx[SYNDROME_T];
    uint8_t ebuf[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];

    /* Recovered error blocks from decrypt. */
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];

    uint32_t i, b;
    int ok;
    int ret = -1;

    syndrome_drbg_init(&rng, seed);

    if (syndrome_pke_keygen(&sk, pk, &rng) != 0)
        goto done;

    if (syndrome_sample_fixed_weight(eidx, SYNDROME_T, SYNDROME_N, &rng) != 0)
        goto done;

    /* Split at the p boundary: index j lands in block j/p at position j%p. */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(ebuf[b], 0, SYNDROME_BLOCK_BYTES);
    for (i = 0; i < (uint32_t)SYNDROME_T; i++) {
        uint32_t j = eidx[i];
        uint32_t blk = j / (uint32_t)SYNDROME_P;
        uint32_t pos = j % (uint32_t)SYNDROME_P;

        ebuf[blk][pos >> 3] |= (uint8_t)(1u << (pos & 7u));
    }
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        syndrome_gf2x_load(e[b], ebuf[b]);

    /* Encrypt through the public key, decrypt through the private key. */
    syndrome_pke_encrypt(ct, pk, e);
    syndrome_pke_decrypt(r, &ok, &sk, ct);

    if (ok != 1)
        goto done;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        for (i = 0; i < (uint32_t)SYNDROME_GF2X_LIMBS; i++)
            if (r[b][i] != e[b][i])
                goto done;

    ret = 0;

done:
    syndrome_drbg_clear(&rng);
    ichor_secure_zero(&sk, sizeof(sk));
    ichor_secure_zero(eidx, sizeof(eidx));
    ichor_secure_zero(ebuf, sizeof(ebuf));
    ichor_secure_zero(e, sizeof(e));
    ichor_secure_zero(r, sizeof(r));
    ichor_secure_zero(pk, sizeof(pk));
    ichor_secure_zero(ct, sizeof(ct));
    return ret;
}
