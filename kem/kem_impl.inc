/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kem.c - KEM-DEM with an IND-CCA FO-style transform (Layer 5).
 *
 * Implements the per-set KEM ops: syndrome_kem_keypair_derand,
 * syndrome_kem_encap_derand, syndrome_kem_decap, over the Niederreiter PKE of
 * pke/ (the entropy-drawing public wrappers live in the dispatch layer,
 * syndrome.c).  The transform is the
 * HHK T/U-with-implicit-rejection FO variant (docs/DESIGN.md §4.1-4.7);
 * the concrete instantiation pinned here:
 *
 *   - KDF/hash: SHAKE-256 for every parameter set (>= lambda security, one
 *     code path), squeezing SYNDROME_SS_BYTES.
 *   - Domain separation: a distinct one-byte prefix per use (pk hash, accept
 *     KDF, reject KDF) absorbed first.
 *   - Shared secret (accept): K = SHAKE256(DS_K || e || s || hpk), with the
 *     error e bound as the dense blocks e0 || e1, the ciphertext s = ct, and
 *     hpk = SHAKE256(DS_PKHASH || M) a cached public-key hash (§4.3).
 *   - Implicit rejection (reject): K = SHAKE256(DS_REJECT || sigma || s) with a
 *     per-key uniform secret sigma; no pk hash (sigma already separates keys,
 *     matching the ML-KEM implicit-rejection shape).  §4.6.
 *   - Re-encryption check (§4.4/§4.5): realized by the decoder's ok flag.  ok is
 *     "residual private syndrome is zero", i.e. h0*e0' + h1*e1' == s'; since
 *     h1 is a unit this is exactly M*e'^T == s, so no M is stored in sk and no
 *     inversion is redone.  A constant-time wt(e') == t check is added so the
 *     accepted error is the genuine weight-t vector and not another syndrome
 *     preimage.
 *
 * Secret-key byte layout (private; SYNDROME_SK_BYTES): H | sigma | hpk, where H
 * is the n0 weight-v index lists packed little-endian (16 bits per index).
 *
 * Constant-time discipline: decap runs one data-independent path; decode
 * success vs failure is never branched on -- the accept/reject choice is a
 * single constant-time byte select, so decap is not a decode-failure oracle.
 */
#include <stdint.h>
#include <string.h>

#include <ichor/hash.h>
#include <ichor/util.h>

#include "kem.h"
#include "pke.h"

/* One-byte domain-separation prefixes (absorbed first into each SHAKE call). */
#define SYNDROME_DS_PKHASH 0x01
#define SYNDROME_DS_K 0x02
#define SYNDROME_DS_REJECT 0x03

/* Byte offsets of the three fields inside the serialized secret key. */
#define SK_H_BYTES (SYNDROME_N0 * SYNDROME_V * 2)
#define SK_OFF_H 0
#define SK_OFF_SIGMA (SK_OFF_H + SK_H_BYTES)
#define SK_OFF_HPK (SK_OFF_SIGMA + SYNDROME_SS_BYTES)

/*
 * ct_eq_zero_mask - 0xFF if x == 0, else 0x00, with data-independent control
 * flow (no branch on the secret x).
 */
static uint8_t
ct_eq_zero_mask(uint64_t x)
{
    uint64_t nz;

    nz = (x | (uint64_t)(0 - x)) >> 63; /* 1 if x != 0, else 0 */
    return (uint8_t)(nz - 1);           /* 0x00 if x != 0, 0xFF if x == 0 */
}

/* hpk = SHAKE256(DS_PKHASH || M).  M (pk) is public; the hash is too. */
static void
compute_hpk(uint8_t hpk[SYNDROME_PKHASH_BYTES], const uint8_t *pk)
{
    ichor_hash_ctx_t h;
    uint8_t ds = SYNDROME_DS_PKHASH;

    ichor_shake256_init(&h);
    ichor_shake256_absorb(&h, &ds, 1);
    ichor_shake256_absorb(&h, pk, SYNDROME_PK_BYTES);
    ichor_shake256_squeeze(&h, hpk, SYNDROME_PKHASH_BYTES);
    ichor_hash_ctx_clear(&h);
}

/*
 * accept_kdf - K = SHAKE256(DS_K || e[0] || .. || e[n0-1] || ct || hpk).  The
 * dense error blocks eb are secret, so the sponge state is cleared after
 * squeeze.  Blocks are absorbed in ascending order (e[0] first), so for n0=2
 * this is byte-identical to the old e0 || e1 order.
 */
static void
accept_kdf(uint8_t k[SYNDROME_SS_BYTES],
           const uint8_t eb[][SYNDROME_BLOCK_BYTES], const uint8_t *ct,
           const uint8_t *hpk)
{
    ichor_hash_ctx_t h;
    uint8_t ds = SYNDROME_DS_K;
    uint32_t b;

    ichor_shake256_init(&h);
    ichor_shake256_absorb(&h, &ds, 1);
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        ichor_shake256_absorb(&h, eb[b], SYNDROME_BLOCK_BYTES);
    ichor_shake256_absorb(&h, ct, SYNDROME_CT_BYTES);
    ichor_shake256_absorb(&h, hpk, SYNDROME_PKHASH_BYTES);
    ichor_shake256_squeeze(&h, k, SYNDROME_SS_BYTES);
    ichor_hash_ctx_clear(&h);
}

/*
 * Split a weight-t index list over [0, n) into the n0 dense p-bit blocks eb
 * (the wire packing), splitting at the p boundaries, in constant time.
 *
 * The index list is the secret error support, so neither the branch nor the
 * memory offset may depend on an index value.  Each block b is therefore filled
 * by syndrome_sample_scatter, which compares every output position against
 * every index (oblivious placement, like keygen's H expansion).  Block b is
 * addressed by subtracting b*p from every index: a genuine block-b index lands
 * in [0, p), while an index from any other block falls outside [0, p) (either
 * >= p or wrapped to a large uint32) and matches no position there.
 */
static void
errblocks_from_indices(uint8_t eb[][SYNDROME_BLOCK_BYTES], const uint32_t *idx,
                       uint32_t w)
{
    uint32_t idx_b[SYNDROME_T];
    uint32_t i, b;

    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        uint32_t base = b * (uint32_t)SYNDROME_P;

        for (i = 0; i < w; i++)
            idx_b[i] = idx[i] - base;
        syndrome_sample_scatter(eb[b], SYNDROME_BLOCK_BYTES, idx_b, w,
                                SYNDROME_P);
    }
    ichor_secure_zero(idx_b, sizeof(idx_b));
}

int
syndrome_kem_keypair_derand(uint8_t pk[SYNDROME_PK_BYTES],
                            uint8_t sk[SYNDROME_SK_BYTES], syndrome_drbg *rng)
{
    syndrome_qcmdpc_sk qsk;
    uint8_t sigma[SYNDROME_SS_BYTES];
    uint8_t hpk[SYNDROME_PKHASH_BYTES];
    size_t off;
    uint32_t b, j;
    int ret = -1;

    if (syndrome_pke_keygen(&qsk, pk, rng) != 0)
        goto done;

    /* Per-key implicit-rejection secret and cached public-key hash. */
    if (syndrome_drbg_generate(rng, sigma, sizeof(sigma)) != 0)
        goto done;
    compute_hpk(hpk, pk);

    /* Serialize sk = H | sigma | hpk; H as little-endian 16-bit indices. */
    off = SK_OFF_H;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        for (j = 0; j < (uint32_t)SYNDROME_V; j++) {
            uint16_t c = qsk.cols[b][j];

            sk[off++] = (uint8_t)(c & 0xffu);
            sk[off++] = (uint8_t)(c >> 8);
        }
    }
    memcpy(sk + SK_OFF_SIGMA, sigma, SYNDROME_SS_BYTES);
    memcpy(sk + SK_OFF_HPK, hpk, SYNDROME_PKHASH_BYTES);

    ret = 0;

done:
    ichor_secure_zero(&qsk, sizeof(qsk));
    ichor_secure_zero(sigma, sizeof(sigma));
    /* hpk is public; pk/sk are the caller's outputs. */
    return ret;
}

int
syndrome_kem_encap_derand(uint8_t ct[SYNDROME_CT_BYTES],
                          uint8_t k[SYNDROME_SS_BYTES],
                          const uint8_t pk[SYNDROME_PK_BYTES],
                          syndrome_drbg *rng)
{
    uint32_t eidx[SYNDROME_T];
    uint8_t eb[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint8_t hpk[SYNDROME_PKHASH_BYTES];
    uint32_t b;
    int ret = -1;

    /* Fresh weight-t error every call (D2/D5; mandatory for anonymity). */
    if (syndrome_sample_fixed_weight(eidx, SYNDROME_T, SYNDROME_N, rng) != 0)
        goto done;

    errblocks_from_indices(eb, eidx, SYNDROME_T);
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        syndrome_gf2x_load(e[b], eb[b]);

    /* ct = s = M * e^T. */
    syndrome_pke_encrypt(ct, pk, e);

    /* K = SHAKE256(DS_K || e || s || hpk). */
    compute_hpk(hpk, pk);
    accept_kdf(k, eb, ct, hpk);

    ret = 0;

done:
    ichor_secure_zero(eidx, sizeof(eidx));
    ichor_secure_zero(eb, sizeof(eb));
    ichor_secure_zero(e, sizeof(e));
    return ret;
}

int
syndrome_kem_decap_impl(uint8_t k[SYNDROME_SS_BYTES],
                        const uint8_t ct[SYNDROME_CT_BYTES],
                        const uint8_t sk[SYNDROME_SK_BYTES])
{
    syndrome_qcmdpc_sk qsk;
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint8_t eb[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint8_t k_real[SYNDROME_SS_BYTES];
    uint8_t k_reject[SYNDROME_SS_BYTES];
    ichor_hash_ctx_t h;
    const uint8_t *sigma = sk + SK_OFF_SIGMA;
    const uint8_t *hpk = sk + SK_OFF_HPK;
    uint8_t ds_reject = SYNDROME_DS_REJECT;
    uint8_t valid, padmask, noncanon;
    unsigned padbits;
    size_t off, w;
    uint32_t b, j, i;
    uint32_t sk_bad = 0; /* OR of (H index >= p); folds to implicit rejection */
    int ok = 0;

    /* Deserialize the private H index lists. */
    off = SK_OFF_H;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        for (j = 0; j < (uint32_t)SYNDROME_V; j++) {
            uint16_t c = (uint16_t)(sk[off] | ((uint16_t)sk[off + 1] << 8));

            qsk.cols[b][j] = c;
            /* Fold an out-of-range column (malformed sk) into implicit rejection
             * below, branch-free: (p-1-c) borrows iff c >= p. */
            sk_bad |= ((uint32_t)SYNDROME_P - 1u - (uint32_t)c) >> 31;
            off += 2;
        }
    }

    /* Decode: ok == "residual private syndrome zero" == (M*e'^T == s). */
    syndrome_pke_decrypt(r, &ok, &qsk, ct);
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        syndrome_gf2x_store(eb[b], r[b]);

    /*
     * Reject a non-canonical ciphertext (padding bits of the top byte set):
     * the ring expects canonical input, and ML-KEM-style we route a malformed
     * ct to implicit rejection rather than decode it.  padbits is 0 only if p
     * is a multiple of 8 (not the case for the shipped sets), where padmask is
     * 0 and the check is a no-op.
     */
    padbits = (unsigned)(8 * SYNDROME_BLOCK_BYTES - SYNDROME_P);
    padmask = (uint8_t)(padbits ? (0xffu << (8 - padbits)) : 0u);
    noncanon = (uint8_t)(ct[SYNDROME_CT_BYTES - 1] & padmask);

    /* valid = canonical AND ok AND wt(e') == t AND sk-in-range, constant-time. */
    w = 0;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        w += syndrome_bitvec_weight(eb[b], SYNDROME_P);
    valid = (uint8_t)(ct_eq_zero_mask((uint64_t)noncanon) &
                      ct_eq_zero_mask((uint64_t)(ok ^ 1)) &
                      ct_eq_zero_mask((uint64_t)w ^ (uint64_t)SYNDROME_T) &
                      ct_eq_zero_mask((uint64_t)sk_bad));

    /* Accept secret and implicit-rejection secret. */
    accept_kdf(k_real, eb, ct, hpk);
    ichor_shake256_init(&h);
    ichor_shake256_absorb(&h, &ds_reject, 1);
    ichor_shake256_absorb(&h, sigma, SYNDROME_SS_BYTES);
    ichor_shake256_absorb(&h, ct, SYNDROME_CT_BYTES);
    ichor_shake256_squeeze(&h, k_reject, SYNDROME_SS_BYTES);
    ichor_hash_ctx_clear(&h);

    /* Constant-time select: no branch on decode validity. */
    for (i = 0; i < (uint32_t)SYNDROME_SS_BYTES; i++)
        k[i] = (uint8_t)((k_real[i] & valid) | (k_reject[i] & (uint8_t)~valid));

    ichor_secure_zero(&qsk, sizeof(qsk));
    ichor_secure_zero(r, sizeof(r));
    ichor_secure_zero(eb, sizeof(eb));
    ichor_secure_zero(k_real, sizeof(k_real));
    ichor_secure_zero(k_reject, sizeof(k_reject));
    return 0; /* never an error oracle: failure is implicit rejection */
}

/*
 * syndrome_kem_pubkey_from_sk_impl - recompute pk = M from sk alone.
 *
 * The public key is a deterministic function of the private H: M_b =
 * H_{n0-1}^{-1} H_b for b in [0, n0-1).  Deserialize the H index lists from sk,
 * expand each dense block, invert the last, and re-derive the systematic blocks.
 *
 * sk is the caller's stored secret and may be malformed/attacker-supplied, so
 * this validates it as a one-shot boundary check: every H index must be < p (an
 * out-of-range index would drive the oblivious scatter past the block), and the
 * last block must be invertible.  Either failing returns -1 with no pk written.
 * All secret intermediates are zeroed on every path.
 */
static int
syndrome_kem_pubkey_from_sk_impl(uint8_t pk[SYNDROME_PK_BYTES],
                                 const uint8_t sk[SYNDROME_SK_BYTES])
{
    uint16_t cols[SYNDROME_N0][SYNDROME_V];
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t inv[SYNDROME_GF2X_LIMBS];
    uint64_t m[SYNDROME_GF2X_LIMBS];
    uint8_t buf[SYNDROME_BLOCK_BYTES];
    uint32_t idx[SYNDROME_V];
    size_t off;
    uint32_t b, i;
    int ret = -1;

    /* Deserialize + bound-check the H index lists (sk = H | sigma | hpk). */
    off = SK_OFF_H;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        for (i = 0; i < (uint32_t)SYNDROME_V; i++) {
            uint16_t c = (uint16_t)(sk[off] | ((uint16_t)sk[off + 1] << 8));

            if (c >= (uint16_t)SYNDROME_P)
                goto done; /* malformed sk: index would overrun the block */
            cols[b][i] = c;
            off += 2;
        }
    }

    /* Expand each dense H_b from its support. */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        for (i = 0; i < (uint32_t)SYNDROME_V; i++)
            idx[i] = cols[b][i];
        memset(buf, 0, sizeof(buf));
        syndrome_sample_scatter(buf, SYNDROME_BLOCK_BYTES, idx, SYNDROME_V,
                                SYNDROME_P);
        syndrome_gf2x_load(h[b], buf);
    }

    /* M_b = H_{n0-1}^{-1} H_b, b in [0, n0-1). */
    if (syndrome_gf2x_inv(inv, h[SYNDROME_N0 - 1]) != 0)
        goto done; /* malformed sk: last block not a unit in R */
    for (b = 0; b < (uint32_t)(SYNDROME_N0 - 1); b++) {
        syndrome_gf2x_mul(m, inv, h[b]);
        syndrome_gf2x_store(pk + b * (size_t)SYNDROME_BLOCK_BYTES, m);
    }

    ret = 0;

done:
    ichor_secure_zero(cols, sizeof(cols));
    ichor_secure_zero(h, sizeof(h));
    ichor_secure_zero(inv, sizeof(inv));
    ichor_secure_zero(m, sizeof(m));
    ichor_secure_zero(buf, sizeof(buf));
    ichor_secure_zero(idx, sizeof(idx));
    return ret;
}
