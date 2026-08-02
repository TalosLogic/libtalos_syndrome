/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bitflip.c - 3-iteration parallel bit-flipping decoder (Algorithm 1,
 * ePrint 2025/1043).
 *
 * Per iteration: for each block b in {0,1} compute the unsatisfied-
 * parity-check count upc[m] = popcount(s AND rotl(h_b, m)) for every
 * position m in [0, p); collect all positions where upc[m] >= threshold
 * into a flip polynomial flip_b; apply flips to the error estimate and
 * update the working syndrome.  Always runs exactly SYNDROME_ITERMAX = 3
 * iterations -- no early exit.  Control flow and memory access are
 * data-independent throughout.
 *
 * Counters use the rotated-syndrome method: for each secret support offset of
 * a block, a constant-time cyclic shift of the working syndrome
 * (syndrome_gf2x_rotl_var) is accumulated into bit-sliced counters, then
 * thresholded, at O(v * log p * p) word operations rather than the dense
 * O(p^2) AND-popcount.  The dense method is retained as compute_flip_dense,
 * the oracle for syndrome_bitflip_diff_selftest.  See
 * DECODER_ROTATED_SYNDROME.md.
 */
#include <stdint.h>
#include <string.h>

#include <ichor/util.h>

#include "decoder.h"
#include "core.h"
#include "code.h"

/*
 * BITFLIP_TOP_BITS: number of valid bits used in the top limb of a ring
 * element.  BITFLIP_TOP_MASK: mask for those bits (keeps the limb
 * canonical after a left shift spills into the unused region).
 */
#define BITFLIP_TOP_BITS (SYNDROME_P - 64u * (SYNDROME_GF2X_LIMBS - 1u))
#define BITFLIP_TOP_MASK                                                       \
    ((BITFLIP_TOP_BITS) >= 64u ? ~UINT64_C(0)                                  \
                               : ((UINT64_C(1) << (BITFLIP_TOP_BITS)) - 1u))

/*
 * Bit-sliced flip counters (rotated-syndrome path, DECODER_ROTATED_SYNDROME.md).
 * BITFLIP_CTR_PLANES ring elements together hold one counter per bit position:
 * plane p carries bit p of every position's count.  Sized to the number of bits
 * in V (the largest a per-position count can reach), so counts never overflow.
 */
#define BITFLIP_CTR_PLANES                                                     \
    ((SYNDROME_V) < 128u   ? 7u                                                \
     : (SYNDROME_V) < 256u ? 8u                                                \
     : (SYNDROME_V) < 512u ? 9u                                                \
                           : 10u)
_Static_assert((1u << (BITFLIP_CTR_PLANES)) > (unsigned)SYNDROME_V,
               "bit-sliced counter planes too few for column weight V");

/*
 * rotl1 - cyclic left-rotate a p-bit ring element by 1 position (multiply
 * by x in R = F_2[x]/(x^p-1)).  The carry out of bit p-1 wraps to bit 0.
 * Input and output must be canonical (top limb masked).
 */
static void
rotl1(uint64_t *v)
{
    const size_t L = SYNDROME_GF2X_LIMBS;
    uint64_t carry = (v[L - 1] >> (BITFLIP_TOP_BITS - 1u)) & 1u;
    size_t i;

    for (i = L - 1; i > 0; i--)
        v[i] = (v[i] << 1) | (v[i - 1] >> 63);
    v[0] = (v[0] << 1) | carry;
    v[L - 1] &= BITFLIP_TOP_MASK;
}

/*
 * popcount64 - branchless SWAR population count of a 64-bit word.
 *
 * Runs the same fixed sequence of shifts, masks, and adds for every input, with
 * no table lookup, no branch, and no multiply, so it is constant-time over the
 * (secret) word on any target with constant-time shift and add.  We roll it by
 * hand rather than call __builtin_popcountll because the builtin's lowering is
 * target-dependent (a single POPCNT on some CPUs, but potentially a table on
 * others), which would put a data-dependent timing path back into the decoder's
 * secret inner loop.  The multiply-based SWAR variant is avoided for the same
 * reason: a 64-bit multiply is not constant-time on every core.  Mirrors the
 * hand-rolled popcount8 in core/bitvec.c.
 */
static uint32_t
popcount64(uint64_t x)
{
    x = x - ((x >> 1) & UINT64_C(0x5555555555555555));
    x = (x & UINT64_C(0x3333333333333333)) +
        ((x >> 2) & UINT64_C(0x3333333333333333));
    x = (x + (x >> 4)) & UINT64_C(0x0f0f0f0f0f0f0f0f);
    x = x + (x >> 8);
    x = x + (x >> 16);
    x = x + (x >> 32);
    return (uint32_t)(x & 0x7fu);
}

/*
 * and_popcount - return popcount(a AND b) over all limbs of two canonical
 * ring elements.  Both inputs are SECRET during decode (the working private
 * syndrome and a rotation of a secret H block), and the count feeds a
 * branch-free threshold compare (ct_ge) and a public-index flip write.  With the
 * branchless popcount64 above, the whole data path is constant-time by
 * construction, with no dependence on a compiler builtin's per-target lowering.
 */
static uint32_t
and_popcount(const uint64_t *a, const uint64_t *b)
{
    uint32_t c = 0;
    size_t i;

    for (i = 0; i < SYNDROME_GF2X_LIMBS; i++)
        c += popcount64(a[i] & b[i]);
    return c;
}

/*
 * ct_ge - branch-free: returns 1 if a >= b, else 0.  Both values must be
 * less than 2^31 so the subtraction does not overflow the sign bit for
 * non-secret operands.
 */
static unsigned
ct_ge(uint32_t a, uint32_t b)
{
    return 1u - (((a - b) >> 31) & 1u);
}

/*
 * ct_is_zero - branch-free: returns 1 if the ring element v is the zero
 * polynomial, else 0.  Ors all limbs and checks whether any bit is set.
 */
static int
ct_is_zero(const uint64_t *v)
{
    uint64_t acc = 0;
    size_t i;

    for (i = 0; i < SYNDROME_GF2X_LIMBS; i++)
        acc |= v[i];
    return (int)(1u ^ (unsigned)((acc | (0u - acc)) >> 63));
}

/*
 * bitflip_ctr_add - add a 1-bit-per-position addend into the bit-sliced
 * counters: for every position m, ctr[*][m] += bit m of `add`.  Ripple-carry
 * across the planes with pure XOR/AND over whole ring elements.  The counters
 * are sized (BITFLIP_CTR_PLANES) so the running maximum V never overflows, so
 * the carry out of the top plane is always zero.  Control flow and memory
 * access depend only on the public constants BITFLIP_CTR_PLANES and LIMBS, so
 * this is constant-time over the (secret) counter and addend contents.
 */
static void
bitflip_ctr_add(uint64_t ctr[][SYNDROME_GF2X_LIMBS], const uint64_t *add)
{
    uint64_t carry[SYNDROME_GF2X_LIMBS];
    unsigned p;
    size_t j;

    memcpy(carry, add, sizeof(carry));
    for (p = 0; p < BITFLIP_CTR_PLANES; p++) {
        for (j = 0; j < SYNDROME_GF2X_LIMBS; j++) {
            uint64_t cout = ctr[p][j] & carry[j]; /* carry out of plane p */

            ctr[p][j] ^= carry[j]; /* sum bit of plane p */
            carry[j] = cout;
        }
    }
    /* carry is all-zero here by the no-overflow sizing; wipe the scratch (it
     * held a shifted copy of the secret syndrome on entry). */
    ichor_secure_zero(carry, sizeof(carry));
}

/*
 * bitflip_ctr_ge - flip[m] = 1 iff the bit-sliced counter at position m is
 * >= the threshold th, else 0.  MSB-first scan tracking, per position, whether
 * the counter is still strictly-less-than-undecided; ge is the complement of
 * "decided less".  th is PUBLIC (the fixed per-iteration threshold), so
 * branching on its bits is not a side channel; the scan is data-independent
 * over the secret counter contents.  Output is canonical (padding masked).
 */
static void
bitflip_ctr_ge(uint64_t *flip, uint64_t ctr[][SYNDROME_GF2X_LIMBS], unsigned th)
{
    uint64_t undecided[SYNDROME_GF2X_LIMBS]; /* still equal on higher planes */
    uint64_t lt[SYNDROME_GF2X_LIMBS];        /* decided strictly less        */
    size_t j;
    int p;

    for (j = 0; j < SYNDROME_GF2X_LIMBS; j++) {
        undecided[j] = ~UINT64_C(0);
        lt[j] = 0;
    }
    undecided[SYNDROME_GF2X_LIMBS - 1] &= BITFLIP_TOP_MASK;

    for (p = (int)BITFLIP_CTR_PLANES - 1; p >= 0; p--) {
        if ((th >> (unsigned)p) & 1u) {
            /* th bit 1: counter bit 0 => less; counter bit 1 => still equal. */
            for (j = 0; j < SYNDROME_GF2X_LIMBS; j++) {
                lt[j] |= undecided[j] & ~ctr[p][j];
                undecided[j] &= ctr[p][j];
            }
        } else {
            /* th bit 0: counter bit 1 => greater (leaves undecided, not less). */
            for (j = 0; j < SYNDROME_GF2X_LIMBS; j++)
                undecided[j] &= ~ctr[p][j];
        }
    }

    /* ge = not(less), restricted to valid positions. */
    for (j = 0; j < SYNDROME_GF2X_LIMBS; j++)
        flip[j] = ~lt[j];
    flip[SYNDROME_GF2X_LIMBS - 1] &= BITFLIP_TOP_MASK;

    ichor_secure_zero(undecided, sizeof(undecided));
    ichor_secure_zero(lt, sizeof(lt));
}

/*
 * compute_flip_dense - the original dense reference: for each position m in
 * [0, p), set flip bit m iff popcount(s AND rotl(hb, m)) >= th.  It rotates hb
 * incrementally (rot starts at rotl(hb, 0), rotl1 per step) and the flip index
 * m is a public loop counter.  Retained only as the independent oracle for
 * syndrome_bitflip_diff_selftest; it is not on any production path (the
 * production decoder uses the rotated-syndrome compute_flip below).  See
 * DECODER_ROTATED_SYNDROME.md.
 */
static void
compute_flip_dense(uint64_t *flip, const uint64_t *s, const uint64_t *hb,
                   unsigned th)
{
    uint64_t rot[SYNDROME_GF2X_LIMBS];
    uint32_t m;

    memcpy(rot, hb, SYNDROME_GF2X_LIMBS * sizeof(uint64_t));
    memset(flip, 0, SYNDROME_GF2X_LIMBS * sizeof(uint64_t));

    for (m = 0; m < (uint32_t)SYNDROME_P; m++) {
        uint32_t upc = and_popcount(s, rot);
        uint64_t bit = (uint64_t)ct_ge(upc, (uint32_t)th);

        flip[m >> 6] |= bit << (m & 63u);

        rotl1(rot);
    }

    ichor_secure_zero(rot, sizeof(rot));
}

/*
 * compute_counters - accumulate one block's unsatisfied-parity-check counts
 * into the bit-sliced counters: ctr[m] = sum over the block's support offsets
 * p_k of s[(m + p_k) mod p], which equals popcount(s AND rotl(hb, m)) but is
 * built without a per-position popcount.  For each secret support offset p_k it
 * adds the cyclic shift v[m] = s[(m + p_k) mod p] = rotl_var(s, p - p_k) into
 * the counters.  The loop bound V is public; the offset is secret but only
 * drives the constant-time rotation, so control flow and memory access are
 * data-independent.  See DECODER_ROTATED_SYNDROME.md.
 */
static void
compute_counters(uint64_t ctr[][SYNDROME_GF2X_LIMBS], const uint64_t *s,
                 const uint16_t *supp)
{
    uint64_t v[SYNDROME_GF2X_LIMBS];
    unsigned k;

    memset(ctr, 0,
           (size_t)BITFLIP_CTR_PLANES * SYNDROME_GF2X_LIMBS * sizeof(uint64_t));
    for (k = 0; k < (unsigned)SYNDROME_V; k++) {
        /* v[m] = s[(m + supp[k]) mod p]; supp[k] in [0, p), so p - supp[k] is
         * in [1, p] and supp[k] == 0 gives the identity rotation. */
        syndrome_gf2x_rotl_var(v, s, (uint32_t)SYNDROME_P - (uint32_t)supp[k]);
        bitflip_ctr_add(ctr, v);
    }

    ichor_secure_zero(v, sizeof(v));
}

/*
 * compute_flip - production flip for one block: accumulate the bit-sliced
 * counters from the block's sparse support, then threshold them.  Produces the
 * identical flip to compute_flip_dense (see syndrome_bitflip_diff_selftest) at
 * O(V * log p) rotations instead of O(p) popcounts.  The flip index is a public
 * position; no secret index is used.
 */
static void
compute_flip(uint64_t *flip, const uint64_t *s, const uint16_t *supp,
             unsigned th)
{
    uint64_t ctr[BITFLIP_CTR_PLANES][SYNDROME_GF2X_LIMBS];

    compute_counters(ctr, s, supp);
    bitflip_ctr_ge(flip, ctr, th);

    ichor_secure_zero(ctr, sizeof(ctr));
}

/*
 * syndrome_bitflip_decode - fixed 3-iteration parallel bit-flipping decoder
 * (Algorithm 1, ePrint 2025/1043).
 *
 * Recovers the weight-t error blocks e[0..n0-1] from the private syndrome s,
 * the n0 sparse H-block supports supp[0..n0-1] (each V column positions, used
 * to build the flip counters), and the matching dense H blocks h[0..n0-1] (used
 * for the syndrome update).  Sets *ok to 1 if the residual syndrome is zero
 * after all iterations (successful decode), else 0.
 *
 * The private syndrome satisfies s = sum_b h[b]*e[b].  The decoder inverts
 * this relation by accumulating flips into each e[b] while zeroing the
 * syndrome.
 *
 * Constant-time discipline: exactly SYNDROME_ITERMAX = 3 iterations run
 * every call (no early exit); all loop bounds are public constants (n0 is a
 * compile-time constant, so the block loop is not a secret branch); every
 * array index is a public loop counter or limb index (no secret-derived
 * offset); the only data-dependent value produced is *ok, which the KEM
 * layer consumes through constant-time implicit rejection.
 */
void
syndrome_bitflip_decode(uint64_t e[][SYNDROME_GF2X_LIMBS], int *ok,
                        const uint64_t h[][SYNDROME_GF2X_LIMBS],
                        const uint16_t supp[][SYNDROME_V], const uint64_t *s_in)
{
    uint64_t s[SYNDROME_GF2X_LIMBS];
    uint64_t flip[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t tmp[SYNDROME_GF2X_LIMBS];
    unsigned iter;
    uint32_t b;

    /* Initialise working syndrome (copy) and error estimates (zero). */
    memcpy(s, s_in, SYNDROME_GF2X_LIMBS * sizeof(uint64_t));
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(e[b], 0, SYNDROME_GF2X_LIMBS * sizeof(uint64_t));

    for (iter = 1; iter <= SYNDROME_ITERMAX; iter++) {
        unsigned th = syndrome_threshold(iter);

        /*
         * Step 1: compute flip polynomials for every block from the SAME
         * syndrome (parallel bit-flip: flips within an iteration are based on
         * the syndrome not yet updated by flips in this iteration).
         */
        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            compute_flip(flip[b], s, supp[b], th);

        /* Step 2: update error estimates e[b] ^= flip[b]. */
        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            syndrome_gf2x_add(e[b], e[b], flip[b]);

        /* Step 3: update working syndrome s ^= sum_b h[b]*flip[b]. */
        for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
            syndrome_gf2x_mul(tmp, h[b], flip[b]);
            syndrome_gf2x_add(s, s, tmp);
        }
    }

    /* Success iff the residual syndrome is zero.  Branch-free. */
    *ok = ct_is_zero(s);

    /* Secure-zero all secret stack buffers before returning. */
    ichor_secure_zero(s, sizeof(s));
    ichor_secure_zero(flip, sizeof(flip));
    ichor_secure_zero(tmp, sizeof(tmp));
}

int
syndrome_bitflip_selftest(void)
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

    /* Dense H blocks reconstructed from sk. */
    uint8_t hbuf[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];

    /* Weight-t error vector split into n0 blocks. */
    uint32_t eidx[SYNDROME_T];
    uint8_t ebuf[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];

    /* Private syndrome s = sum_b h[b]*e[b] (decoder input). */
    uint64_t stmp[SYNDROME_GF2X_LIMBS];
    uint64_t s[SYNDROME_GF2X_LIMBS];

    /* Recovered error blocks from the decoder. */
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];

    /* Zero-error sanity: s=0 should decode to all-zero error, ok=1. */
    uint64_t szero[SYNDROME_GF2X_LIMBS];
    uint64_t rz[SYNDROME_N0][SYNDROME_GF2X_LIMBS];

    uint32_t i, b;
    int ok;
    int ret = -1;

    syndrome_drbg_init(&rng, seed);

    /* Step 1: generate a fresh key pair. */
    if (syndrome_qcmdpc_keygen(&sk, pk, &rng) != 0)
        goto done;

    /* Step 2: reconstruct dense h[b] from the private index lists. */
    {
        uint32_t idx[SYNDROME_V];

        for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
            memset(hbuf[b], 0, SYNDROME_BLOCK_BYTES);
            for (i = 0; i < (uint32_t)SYNDROME_V; i++)
                idx[i] = (uint32_t)sk.cols[b][i];
            syndrome_sample_scatter(hbuf[b], SYNDROME_BLOCK_BYTES, idx,
                                    SYNDROME_V, SYNDROME_P);
            syndrome_gf2x_load(h[b], hbuf[b]);
        }
        ichor_secure_zero(idx, sizeof(idx));
    }

    /*
     * Step 3: sample a weight-t error over n = n0*p positions and split into
     * n0 dense blocks.  Index j lands in block j/p at position j%p.  This
     * split does not need to be constant-time (test code only).
     */
    if (syndrome_sample_fixed_weight(eidx, SYNDROME_T, SYNDROME_N, &rng) != 0)
        goto done;

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

    /*
     * Step 4: compute the private syndrome s = sum_b h[b]*e[b].
     * This is the input the decoder inverts.
     */
    memset(s, 0, sizeof(s));
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        syndrome_gf2x_mul(stmp, h[b], e[b]);
        syndrome_gf2x_add(s, s, stmp);
    }

    /* Step 5: run the decoder. */
    syndrome_bitflip_decode(r, &ok, h, sk.cols, s);

    /* Step 6: ok must be 1 and the recovered error must match exactly. */
    if (ok != 1)
        goto done;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        for (i = 0; i < (uint32_t)SYNDROME_GF2X_LIMBS; i++)
            if (r[b][i] != e[b][i])
                goto done;

    /*
     * Step 7: sanity -- zero error vector.  s=0 decodes to all-zero error with
     * ok=1 (the zero polynomial is the trivial fixed point of the decoder).
     */
    memset(szero, 0, sizeof(szero));
    syndrome_bitflip_decode(rz, &ok, h, sk.cols, szero);

    if (ok != 1)
        goto done;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        for (i = 0; i < (uint32_t)SYNDROME_GF2X_LIMBS; i++)
            if (rz[b][i] != 0)
                goto done;

    ret = 0;

done:
    syndrome_drbg_clear(&rng);
    ichor_secure_zero(&sk, sizeof(sk));
    ichor_secure_zero(hbuf, sizeof(hbuf));
    ichor_secure_zero(h, sizeof(h));
    ichor_secure_zero(eidx, sizeof(eidx));
    ichor_secure_zero(ebuf, sizeof(ebuf));
    ichor_secure_zero(e, sizeof(e));
    ichor_secure_zero(stmp, sizeof(stmp));
    ichor_secure_zero(s, sizeof(s));
    ichor_secure_zero(r, sizeof(r));
    ichor_secure_zero(szero, sizeof(szero));
    ichor_secure_zero(rz, sizeof(rz));
    ichor_secure_zero(pk, sizeof(pk));
    return ret;
}

/*
 * syndrome_bitflip_ctr_selftest - unit test for the bit-sliced counter add and
 * the threshold compare, cross-checked against a closed-form reference.
 *
 * Construction: add the all-ones (valid) mask `base` times, then add a fixed
 * subset mask B `full - base` times.  Every position in B then holds count
 * `full` (= V, the maximum), every other valid position holds `base`.  Both the
 * recovered per-plane bits and the >= th mask have exact closed forms in terms
 * of B and the two counts, so the check needs no large per-position scratch.
 */
static int
syndrome_bitflip_ctr_selftest(void)
{
    const size_t L = SYNDROME_GF2X_LIMBS;
    uint64_t ctr[BITFLIP_CTR_PLANES][SYNDROME_GF2X_LIMBS];
    uint64_t valid[SYNDROME_GF2X_LIMBS];
    uint64_t B[SYNDROME_GF2X_LIMBS];
    uint64_t flip[SYNDROME_GF2X_LIMBS];
    const unsigned base = 3u;                   /* count on ~B positions      */
    const unsigned full = (unsigned)SYNDROME_V; /* count on B positions (max) */
    unsigned p, c;
    size_t j;
    int ret = -1;

    /* valid = every position set, padding clear. */
    for (j = 0; j < L; j++)
        valid[j] = ~UINT64_C(0);
    valid[L - 1] &= BITFLIP_TOP_MASK;

    /* B = a fixed non-trivial subset (roughly half the positions). */
    for (j = 0; j < L; j++)
        B[j] = UINT64_C(0xA5A5A5A5A5A5A5A5);
    B[L - 1] &= BITFLIP_TOP_MASK;

    memset(ctr, 0, sizeof(ctr));
    for (c = 0; c < base; c++)
        bitflip_ctr_add(ctr, valid);
    for (c = 0; c < full - base; c++)
        bitflip_ctr_add(ctr, B);

    /* Each plane: ctr[p] = (bit_p(full) ? B : 0) | (bit_p(base) ? valid&~B : 0). */
    for (p = 0; p < BITFLIP_CTR_PLANES; p++) {
        unsigned fb = (full >> p) & 1u;
        unsigned bb = (base >> p) & 1u;

        for (j = 0; j < L; j++) {
            uint64_t want = (fb ? B[j] : 0) | (bb ? (valid[j] & ~B[j]) : 0);

            if (ctr[p][j] != want)
                goto done;
        }
    }

    /* Threshold: flip = (full>=th ? B : 0) | (base>=th ? valid&~B : 0). */
    {
        static const unsigned ths[] = {0u, base, base + 1u, full};
        size_t ti;

        for (ti = 0; ti < sizeof(ths) / sizeof(ths[0]); ti++) {
            unsigned th = ths[ti];
            uint64_t fmask = (full >= th) ? ~UINT64_C(0) : 0;
            uint64_t bmask = (base >= th) ? ~UINT64_C(0) : 0;

            bitflip_ctr_ge(flip, ctr, th);
            for (j = 0; j < L; j++) {
                uint64_t want = (B[j] & fmask) | ((valid[j] & ~B[j]) & bmask);

                if (flip[j] != want)
                    goto done;
            }
        }
    }

    ret = 0;

done:
    ichor_secure_zero(ctr, sizeof(ctr));
    ichor_secure_zero(B, sizeof(B));
    ichor_secure_zero(flip, sizeof(flip));
    return ret;
}

/*
 * syndrome_bitflip_diff_selftest - differential oracle for the rotated-syndrome
 * counter path.  For several random (support, working-syndrome) pairs it checks
 * two things against the dense reference, where hb is the dense block matching
 * the support:
 *   1. the production bit-sliced counters (compute_counters) equal the dense
 *      popcount(s AND rotl(hb, m)) at EVERY position m.  Per-position equality
 *      over the full sweep is a complete proof that the two counter methods
 *      agree, hence every threshold decision, flip, and decode agrees;
 *   2. the production compute_flip equals compute_flip_dense at each of the real
 *      per-iteration thresholds (end-to-end through the threshold compare).
 * The fixed KAT vectors are the coarse correctness anchor; this is the dense
 * one.  See DECODER_ROTATED_SYNDROME.md.
 */
static int
syndrome_bitflip_diff_selftest(void)
{
    /* Distinct 48-byte seed (0x30..0x5f) so this draws its own stream. */
    static const uint8_t seed[48] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    };
    const unsigned trials = 8u;
    syndrome_drbg rng;
    uint32_t supp32[SYNDROME_V];
    uint16_t supp[SYNDROME_V];
    uint8_t sbuf[SYNDROME_BLOCK_BYTES];
    uint8_t hbuf[SYNDROME_BLOCK_BYTES];
    uint64_t s[SYNDROME_GF2X_LIMBS];
    uint64_t hb[SYNDROME_GF2X_LIMBS];
    uint64_t rot[SYNDROME_GF2X_LIMBS];
    uint64_t ctr[BITFLIP_CTR_PLANES][SYNDROME_GF2X_LIMBS];
    uint64_t fnew[SYNDROME_GF2X_LIMBS];
    uint64_t fref[SYNDROME_GF2X_LIMBS];
    unsigned trial;
    int ret = -1;

    syndrome_drbg_init(&rng, seed);

    for (trial = 0; trial < trials; trial++) {
        uint32_t i, m;
        unsigned it;

        /* Random support (V distinct positions) + random working syndrome. */
        if (syndrome_sample_fixed_weight(supp32, SYNDROME_V, SYNDROME_P,
                                         &rng) != 0)
            goto done;
        for (i = 0; i < (uint32_t)SYNDROME_V; i++)
            supp[i] = (uint16_t)supp32[i];
        if (syndrome_drbg_generate(&rng, sbuf, sizeof(sbuf)) != 0)
            goto done;
        syndrome_gf2x_load(s, sbuf);

        /* Dense hb matching the support, for the oracle. */
        syndrome_sample_scatter(hbuf, SYNDROME_BLOCK_BYTES, supp32, SYNDROME_V,
                                SYNDROME_P);
        syndrome_gf2x_load(hb, hbuf);

        /* Check 1: production counters vs dense popcount at every position. */
        compute_counters(ctr, s, supp);
        memcpy(rot, hb, sizeof(rot));
        for (m = 0; m < (uint32_t)SYNDROME_P; m++) {
            uint32_t want = and_popcount(s, rot);
            uint32_t got = 0;
            unsigned pl;

            for (pl = 0; pl < BITFLIP_CTR_PLANES; pl++)
                got |= (uint32_t)((ctr[pl][m >> 6] >> (m & 63u)) & 1u) << pl;
            if (got != want)
                goto done;
            rotl1(rot);
        }

        /* Check 2: production flip vs dense flip at the real thresholds. */
        for (it = 1; it <= SYNDROME_ITERMAX; it++) {
            unsigned th = syndrome_threshold(it);

            compute_flip(fnew, s, supp, th);
            compute_flip_dense(fref, s, hb, th);
            for (i = 0; i < (uint32_t)SYNDROME_GF2X_LIMBS; i++)
                if (fnew[i] != fref[i])
                    goto done;
        }
    }

    ret = 0;

done:
    syndrome_drbg_clear(&rng);
    ichor_secure_zero(supp32, sizeof(supp32));
    ichor_secure_zero(supp, sizeof(supp));
    ichor_secure_zero(sbuf, sizeof(sbuf));
    ichor_secure_zero(hbuf, sizeof(hbuf));
    ichor_secure_zero(s, sizeof(s));
    ichor_secure_zero(hb, sizeof(hb));
    ichor_secure_zero(rot, sizeof(rot));
    ichor_secure_zero(ctr, sizeof(ctr));
    ichor_secure_zero(fnew, sizeof(fnew));
    ichor_secure_zero(fref, sizeof(fref));
    return ret;
}
