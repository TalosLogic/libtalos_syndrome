/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_ctr_merge.c - unit test for syndrome_ctr_merge (decoder/ctr_merge.c).
 *
 * syndrome_ctr_merge sums two bit-sliced counters.  It backs the reduction of a
 * threaded compute_counters: each worker accumulates a slice of the support into
 * a private counter with syndrome_ctr_add, then the partials are merged.  The
 * contract this test pins is that the merged result is byte-identical to
 * accumulating every vector serially into one counter, for any partition of the
 * input and any merge order.  Both routines are generic over (planes, limbs), so
 * this test is set-agnostic and picks its own small sizes.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ctr_dispatch.h"

#define PLANES 8u /* holds counts 0..255, so up to 255 added vectors */
#define LIMBS 10u
#define NVEC 150u /* < 2^PLANES, so no position overflows PLANES planes */
#define CTR_WORDS (PLANES * LIMBS)

static int fail_count = 0;

static void
check(const char *name, int cond)
{
    if (!cond) {
        printf("  FAIL: %s\n", name);
        fail_count++;
    }
}

/* Deterministic xorshift64; the merge is pure integer math, so no crypto RNG. */
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t
xorshift64(void)
{
    uint64_t x = rng_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

/* The NVEC random 0/1-per-position vectors (each a LIMBS-word ring element). */
static uint64_t vecs[NVEC][LIMBS];

/* Reference counter: every vector accumulated serially into one counter. */
static uint64_t ref[CTR_WORDS];

/*
 * Build the merged counter for a given partition (chunk sizes summing to NVEC):
 * accumulate each chunk's vectors into a private counter with syndrome_ctr_add,
 * then fold the chunks together with syndrome_ctr_merge (chunk 0 is the running
 * accumulator; if reverse is set, fold the chunks in reverse order).  Compare
 * the result byte-for-byte against the reference.
 */
static void
run_partition(const char *name, const unsigned *sizes, unsigned nchunks,
              int reverse)
{
    uint64_t chunk[NVEC][CTR_WORDS]; /* one counter per chunk (nchunks used) */
    uint64_t acc[CTR_WORDS];
    unsigned c, off;

    /* Accumulate each chunk's vectors into its own counter. */
    off = 0;
    for (c = 0; c < nchunks; c++) {
        unsigned i;

        memset(chunk[c], 0, sizeof(chunk[c]));
        for (i = 0; i < sizes[c]; i++)
            syndrome_ctr_add(chunk[c], vecs[off + i], PLANES, LIMBS);
        off += sizes[c];
    }
    check("partition covers exactly NVEC vectors", off == NVEC);

    /* Fold the chunk counters together. */
    if (reverse) {
        memcpy(acc, chunk[nchunks - 1u], sizeof(acc));
        for (c = nchunks - 1u; c-- > 0;)
            syndrome_ctr_merge(acc, chunk[c], PLANES, LIMBS);
    } else {
        memcpy(acc, chunk[0], sizeof(acc));
        for (c = 1; c < nchunks; c++)
            syndrome_ctr_merge(acc, chunk[c], PLANES, LIMBS);
    }

    check(name, memcmp(acc, ref, sizeof(acc)) == 0);
}

int
main(void)
{
    unsigned i, j, bit;

    /* Random vectors. */
    for (i = 0; i < NVEC; i++)
        for (j = 0; j < LIMBS; j++)
            vecs[i][j] = xorshift64();

    /* Reference: serial accumulation into one counter. */
    memset(ref, 0, sizeof(ref));
    for (i = 0; i < NVEC; i++)
        syndrome_ctr_add(ref, vecs[i], PLANES, LIMBS);

    /*
     * Independent cross-check of the bit-sliced representation: for a sample of
     * positions, decode the reference count (sum of plane bit << plane) and
     * compare to the plain integer popcount of that position across all vectors.
     */
    for (bit = 0; bit < 64u; bit++) {
        unsigned decoded = 0;
        unsigned actual = 0;
        unsigned p;

        for (p = 0; p < PLANES; p++)
            decoded |= (unsigned)((ref[p * LIMBS + 0] >> bit) & 1u) << p;
        for (i = 0; i < NVEC; i++)
            actual += (unsigned)((vecs[i][0] >> bit) & 1u);
        check("bit-sliced count decodes to integer popcount",
              decoded == actual);
    }

    /* Partitions: all must reproduce the reference. */
    {
        const unsigned one[] = {NVEC};
        const unsigned two[] = {75, 75};
        const unsigned three[] = {50, 50, 50};
        const unsigned four[] = {37, 38, 37, 38};
        const unsigned uneven[] = {1, 10, 100, 39};
        const unsigned empties[] = {0, 150, 0};
        unsigned singles[NVEC];

        for (i = 0; i < NVEC; i++)
            singles[i] = 1;

        run_partition("merge: single chunk", one, 1, 0);
        run_partition("merge: 2 even chunks", two, 2, 0);
        run_partition("merge: 3 even chunks", three, 3, 0);
        run_partition("merge: 4 even chunks", four, 4, 0);
        run_partition("merge: uneven chunks", uneven, 4, 0);
        run_partition("merge: empty chunks are identity", empties, 3, 0);
        run_partition("merge: 150 singletons", singles, NVEC, 0);
        run_partition("merge: reverse fold order", four, 4, 1);
        run_partition("merge: reverse fold, singletons", singles, NVEC, 1);
    }

    if (fail_count == 0) {
        printf("test_ctr_merge: all checks passed\n");
        return 0;
    }
    printf("test_ctr_merge: %d check(s) failed\n", fail_count);
    return 1;
}
