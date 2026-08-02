/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_sample_equiv.c - differential equivalence gate for the fixed-weight
 * sampler.
 *
 * syndrome_sample_fixed_weight now delegates its draw to the shared
 * libtalos_ichor overlay Fisher-Yates (this wrapper only expands the DRBG into
 * the sampler tape).  The result must stay BYTE-IDENTICAL to the historical
 * inline sampler: it feeds the KEM/seed KATs and the Proteus key derivation, so
 * any change in the sampled index list would silently move every key.  This test
 * embeds an independent length-n array Fisher-Yates as a ground-truth oracle and
 * asserts the two produce identical index lists (in draw order) over many DRBG
 * seeds and many (w, n) shapes -- including the small-n cases (frequent
 * self-swaps j == i and repeated overrides of one tail slot) that the single
 * fixed-seed digest in test_sample_kat.c would rarely exercise.  It guards the
 * DRBG->tape glue and the shared reduction together.
 *
 * Force-includes sets/set_bodies.inc for SYNDROME_SAMPLE_DRAW_BYTES and the
 * shared sampler; the reference carries its OWN copy of the Lemire reduction
 * (ref_reduce/ref_load32) so it stays independent of the code under test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "talos_syndrome.h"

/*
 * Independent copy of the widened Lemire reduction: the reference must not
 * borrow the code under test.  Reproduces ichor_sample_fixed_weight's per-index
 * mapping, floor(draw * range / 2^(8*DRAW_BYTES)) accumulated over 32-bit limbs
 * low-to-high, so seeding both from the same DRBG and comparing outputs is a
 * faithful equivalence check.
 */
static uint32_t
ref_load32(const uint8_t b[4])
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static uint32_t
ref_reduce(const uint8_t buf[SYNDROME_SAMPLE_DRAW_BYTES], uint32_t range)
{
    uint64_t carry = 0;
    int i;

    for (i = 0; i < SYNDROME_SAMPLE_DRAW_BYTES / 4; i++)
        carry = (uint64_t)ref_load32(buf + 4 * i) * range + (carry >> 32);

    return (uint32_t)(carry >> 32);
}

/* 0xFFFFFFFF if a == b, else 0 (branch-free).  Reference-local copy: the shared
 * scatter now lives in ichor, so this reference does not borrow library code. */
static uint32_t
ct_eq32(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t nz = (x | (0u - x)) >> 31; /* 1 if x != 0, else 0 */

    return nz - 1u;
}

/*
 * Reference: a length-n masked Fisher-Yates as the ground-truth oracle.
 * Consumes the DRBG identically to the wrapper (one SYNDROME_SAMPLE_DRAW_BYTES
 * draw per step through ref_reduce), returning the drawn set in draw order.
 */
static int
sample_ref(uint32_t *idx, uint32_t w, uint32_t n, syndrome_drbg *rng)
{
    uint32_t *pos;
    uint32_t i;

    if (w > n)
        return -1;
    pos = calloc(n, sizeof(uint32_t));
    if (pos == NULL)
        return -1;
    for (i = 0; i < n; i++)
        pos[i] = i;

    for (i = 0; i < w; i++) {
        uint8_t buf[SYNDROME_SAMPLE_DRAW_BYTES];
        uint32_t range = n - i;
        uint32_t j, k;

        if (syndrome_drbg_generate(rng, buf, sizeof buf) != 0) {
            free(pos);
            return -1;
        }
        j = i + ref_reduce(buf, range);

        for (k = i; k < n; k++) {
            uint32_t m = ct_eq32(k, j);
            uint32_t pk = pos[k];
            uint32_t pi = pos[i];
            uint32_t diff = m & (pk ^ pi);

            pos[k] = pk ^ diff;
            pos[i] = pi ^ diff;
        }
        idx[i] = pos[i];
    }

    free(pos);
    return 0;
}

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond)
        pass_count++;
    else
        printf("  FAIL: %s\n", name);
}

/* Distinctness + range backstop on the live output (non-CT; test-only). */
static int
distinct_in_range(const uint32_t *idx, uint32_t w, uint32_t n)
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

/* Distinct from the sampler selftest's seed_fill (force-included via
 * set_bodies.inc); named uniquely to avoid the clash, and mixes the base in
 * more so successive seeds are not near-identical. */
static void
equiv_seed_fill(uint8_t seed[48], uint32_t base)
{
    int i;

    for (i = 0; i < 48; i++)
        seed[i] = (uint8_t)(base * 31u + (uint32_t)i * 7u + 0x5au);
}

/*
 * Run the reference and the live sampler on the same seed for `seeds` distinct
 * seeds; return 1 iff every run produced identical return codes and, on success,
 * byte-identical, distinct, in-range output.
 */
static int
equiv_case(uint32_t w, uint32_t n, uint32_t seeds)
{
    uint32_t a[SYNDROME_SAMPLE_MAXW];
    uint32_t b[SYNDROME_SAMPLE_MAXW];
    uint32_t s;

    if (w > (uint32_t)SYNDROME_SAMPLE_MAXW)
        return 0; /* case-table bug: overlay scratch too small for this w */

    for (s = 0; s < seeds; s++) {
        syndrome_drbg r1, r2;
        uint8_t seed[48];
        int rc_ref, rc_new;

        equiv_seed_fill(seed, s);
        syndrome_drbg_init(&r1, seed);
        syndrome_drbg_init(&r2, seed);

        rc_ref = sample_ref(a, w, n, &r1);
        rc_new = syndrome_sample_fixed_weight(b, w, n, &r2);

        syndrome_drbg_clear(&r1);
        syndrome_drbg_clear(&r2);

        if (rc_ref != rc_new)
            return 0;
        if (rc_new == 0) {
            if (memcmp(a, b, (size_t)w * sizeof a[0]) != 0)
                return 0;
            if (!distinct_in_range(b, w, n))
                return 0;
        }
    }
    return 1;
}

int
main(void)
{
    /*
     * {w, n, seeds}.  The two real-parameter shapes use fewer seeds (the O(w*n)
     * reference is expensive at full p); the cheap small-n shapes use many, to
     * hammer the collision / self-swap / repeated-override paths that stress the
     * overlay resolution.
     */
    static const uint32_t cases[][3] = {
        {SYNDROME_T, SYNDROME_N, 16}, /* encap error draw            */
        {SYNDROME_V, SYNDROME_P, 16}, /* keygen H-block draw         */
        {SYNDROME_V, SYNDROME_V, 64}, /* full permutation at weight v */
        {1, SYNDROME_P, 64},          /* minimal weight              */
        {2, 3, 512},
        {3, 4, 512},
        {4, 4, 512}, /* full perm, small: many self-swaps late */
        {8, 8, 512},
        {16, 16, 256},
        {10, 50, 256},
        {32, 40, 128},
    };
    const size_t ncases = sizeof cases / sizeof cases[0];
    size_t c;
    char name[64];

    printf("sample equivalence: overlay shuffle vs reference array shuffle\n");

    for (c = 0; c < ncases; c++) {
        uint32_t w = cases[c][0], n = cases[c][1], seeds = cases[c][2];

        snprintf(name, sizeof name, "equiv w=%u n=%u (%u seeds)", w, n, seeds);
        check(name, equiv_case(w, n, seeds));
    }

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
