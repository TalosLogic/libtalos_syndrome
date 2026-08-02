/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sample.c - constant-time fixed-weight sampling: weight-t error e and
 * odd-weight private polynomials h_i (weight v).
 *
 * fixed_weight draws w distinct indices in [0, n).  The draw itself is the
 * shared, constant-time overlay Fisher-Yates in libtalos_ichor
 * (ichor_sample_fixed_weight), a pure function of a random tape; this wrapper
 * expands the DRBG into that tape with the SAME per-index draw width and order
 * the former inline sampler used (w generate() calls of lambda+64 bits each),
 * so the sampled index list is byte-identical to before the sampler was
 * factored out: the KEM/seed KATs and the Proteus key derivation are unchanged.
 * ichor's Lemire reduction drives the residual bias below 2^-lambda per draw.
 * scatter places the listed bits into a dense vector obliviously: it builds each
 * 64-bit output word by OR-ing in, for every index, a precomputed single-bit
 * mask gated on whether that index falls in the current word.  scatter is
 * order-independent, so the draw order the shared sampler returns does not
 * affect e or H.
 *
 * Constant-time: no secret-dependent branches and no secret-indexed memory.
 * The tape and the resulting index list are secret (they define e and H); the
 * tape is secure-zeroed before return and the caller owns the output.
 *
 * Performance note: scatter is word-parallel, O(w * n/64): it iterates output
 * words, not bits, so each index is compared once per 64-bit word rather than
 * once per bit.  The shared sampler is pinned byte-identical to a reference
 * full-array shuffle by tests/test_sample_equiv.c (many seeds and shapes) and by
 * the fixed-seed digest in tests/test_sample_kat.c.
 */
#include <string.h>

#include <ichor/gf2x.h>
#include <ichor/sample.h>
#include <ichor/util.h>

#include "set_internal.h"

/*
 * Maximum weight requested in any single call within a set: the weight-t error
 * draw (encap/seal) or the weight-v H-block draw (keygen).  Bounds the O(w)
 * overlay scratch in syndrome_sample_fixed_weight; a larger w is rejected rather
 * than overrun it.
 */
#define SYNDROME_SAMPLE_MAXW (SYNDROME_T > SYNDROME_V ? SYNDROME_T : SYNDROME_V)

/*
 * Per-index tape draw width in bytes: lambda + 64 bits, widened over the bare
 * range word so ichor's Lemire reduction drives the residual bias far below
 * 2^-lambda for every set (24 bytes at lambda 128, 40 at 256).  This wrapper
 * draws exactly this many DRBG bytes per index, matching the byte layout
 * ichor_sample_fixed_weight expects (== ichor_sample_draw_bytes(lambda)).
 */
#define SYNDROME_SAMPLE_DRAW_BYTES ((SYNDROME_LAMBDA + 64) / 8)

int
syndrome_sample_fixed_weight(uint32_t *idx, uint32_t w, uint32_t n,
                             syndrome_drbg *rng)
{
    /*
     * Expand the DRBG into the ichor sampler tape: one SYNDROME_SAMPLE_DRAW_BYTES
     * draw per index, in order.  This reproduces the exact DRBG consumption of
     * the former inline sampler (w generate() calls of the same width), so the
     * drawn index list is byte-identical and no key or KAT moves.  The tape is
     * sized for the largest weight in this set; only the low w*db bytes are used.
     */
    uint8_t tape[SYNDROME_SAMPLE_MAXW * SYNDROME_SAMPLE_DRAW_BYTES];
    const size_t db = SYNDROME_SAMPLE_DRAW_BYTES;
    uint32_t i;
    int ret = -1;

    if (w > n || w > (uint32_t)SYNDROME_SAMPLE_MAXW)
        return -1;

    for (i = 0; i < w; i++)
        if (syndrome_drbg_generate(rng, tape + (size_t)i * db, db) != 0)
            goto done;

    /*
     * ichor draws w distinct indices in [0, n) from the tape, returned in draw
     * order (the overlay Fisher-Yates and Lemire reduction live in the shared,
     * dudect-gated sampler).  scatter is order-independent, so draw order is the
     * canonical form here; a consumer that hashes the sparse list as an ordered
     * list would sort first (syndrome's own KDF path re-derives ascending from
     * the dense error instead).
     */
    if (ichor_sample_fixed_weight(idx, w, n, SYNDROME_LAMBDA, tape,
                                  (size_t)w * db) != 0)
        goto done;
    ret = 0;

done:
    ichor_secure_zero(tape, sizeof tape);
    return ret;
}

/*
 * Oblivious sparse -> dense scatter: now a thin wrapper over the shared,
 * constant-time word-parallel scatter in libtalos_ichor (ichor_gf2x_scatter).
 * base 0 and span n scatter the full support into a length-n dense vector,
 * bit-identical to the previous in-tree implementation (which this de-duplicates
 * against the opener's copy in libtalos_voleith), so the sampler KATs
 * (tests/test_sample_kat.c) and the shuffle-equivalence vectors
 * (tests/test_sample_equiv.c) pin it unchanged.
 *
 * Precondition (the bound the sampler already enforces): w <=
 * SYNDROME_SAMPLE_MAXW (<= ICHOR_GF2X_MAX_WEIGHT).
 */
void
syndrome_sample_scatter(uint8_t *vec, size_t nbytes, const uint32_t *idx,
                        uint32_t w, uint32_t n)
{
    ichor_gf2x_scatter(vec, nbytes, idx, w, 0u, n);
}

/* ========================================================================
 * Self-test (docs/TESTING.md)
 * ======================================================================== */

/* All w indices distinct and in [0, n)?  Non-CT; test-only. */
static int
all_distinct_in_range(const uint32_t *idx, uint32_t w, uint32_t n)
{
    uint32_t i, j;

    for (i = 0; i < w; i++) {
        if (idx[i] >= n)
            return 0;
        for (j = i + 1; j < w; j++)
            if (idx[i] == idx[j])
                return 0;
    }
    return 1;
}

static void
seed_fill(uint8_t seed[48], uint8_t base)
{
    int i;

    for (i = 0; i < 48; i++)
        seed[i] = (uint8_t)(base + i);
}

int
syndrome_sample_selftest(void)
{
    /* Buffer large enough for a length-N dense vector. */
    uint8_t vec[(SYNDROME_N + 7) / 8];
    /*
     * Index scratch: sized to SYNDROME_SAMPLE_MAXW (max(t, v)) so it holds either
     * a weight-t error draw or a weight-v H-block draw.  For the n0=5 sets v > t
     * (e.g. lambda-256 n0=5: v=165, t=113), unlike the n0=2 sets where t > v.
     */
    uint32_t a[SYNDROME_SAMPLE_MAXW], b[SYNDROME_SAMPLE_MAXW];
    syndrome_drbg rng, rng2;
    uint8_t seed[48], seed2[48];
    uint32_t i;

    seed_fill(seed, 0);
    seed_fill(seed2, 1);

    /* Weight-t error over the full length n = N. */
    syndrome_drbg_init(&rng, seed);
    if (syndrome_sample_fixed_weight(a, SYNDROME_T, SYNDROME_N, &rng) != 0)
        return -1;
    if (!all_distinct_in_range(a, SYNDROME_T, SYNDROME_N))
        return -1;

    /* scatter reproduces exactly t set bits, and each index lands. */
    syndrome_sample_scatter(vec, (SYNDROME_N + 7) / 8, a, SYNDROME_T,
                            SYNDROME_N);
    if (syndrome_bitvec_weight(vec, SYNDROME_N) != SYNDROME_T)
        return -1;
    for (i = 0; i < SYNDROME_T; i++)
        if (syndrome_bitvec_test(vec, a[i]) != 1)
            return -1;

    /* Odd-weight H block: weight v over n = p. */
    syndrome_drbg_init(&rng, seed);
    if (syndrome_sample_fixed_weight(a, SYNDROME_V, SYNDROME_P, &rng) != 0)
        return -1;
    if (!all_distinct_in_range(a, SYNDROME_V, SYNDROME_P))
        return -1;

    /* Determinism: identical seed -> identical index list. */
    syndrome_drbg_init(&rng, seed);
    syndrome_drbg_init(&rng2, seed);
    if (syndrome_sample_fixed_weight(a, SYNDROME_T, SYNDROME_N, &rng) != 0 ||
        syndrome_sample_fixed_weight(b, SYNDROME_T, SYNDROME_N, &rng2) != 0)
        return -1;
    if (memcmp(a, b, SYNDROME_T * sizeof a[0]) != 0)
        return -1;

    /* Distinct seed -> different list (overwhelming probability). */
    syndrome_drbg_init(&rng2, seed2);
    if (syndrome_sample_fixed_weight(b, SYNDROME_T, SYNDROME_N, &rng2) != 0)
        return -1;
    if (memcmp(a, b, SYNDROME_T * sizeof a[0]) == 0)
        return -1;

    return 0;
}
