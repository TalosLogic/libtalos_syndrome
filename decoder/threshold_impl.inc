/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * threshold.c - per-parameter-set decoder thresholds.
 *
 * Thresholds are pinned per parameter set and tied to the DFR analysis.
 * Changing a parameter set without re-deriving thresholds and re-validating
 * the DFR <= 2^-lambda bound is a security bug.
 */
#include "decoder.h"

/*
 * Pinned per-iteration flip thresholds for the active Long-Term parameter
 * set.  Indexed 0..SYNDROME_ITERMAX-1; caller accesses as thresholds[iter-1].
 *
 * Source: ePrint 2025/1043, Table 2 (Long-Term sets).  One arm per shipped
 * (lambda, n0) in {128, 192, 256} x {2, 3, 4, 5}; the full table of (p, v, t,
 * thresholds, -log2 DFR) is in DESIGN.md §3.  iterMax=3 is fixed by the paper's
 * decoder and thresholds are iteration-indexed only.  The closed-form
 * DFR <= 2^-lambda bound is established and independently recomputed in
 * DESIGN.md §3.2 (every row clears 2^-lambda with margin); the Monte-Carlo
 * decoder-fidelity check in the waterfall regime is test_dfr_mc.c.
 */
#if SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 2
static const unsigned thresholds[SYNDROME_ITERMAX] = {41, 35, 35};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 2
static const unsigned thresholds[SYNDROME_ITERMAX] = {77, 69, 69};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 5
static const unsigned thresholds[SYNDROME_ITERMAX] = {49, 42, 42};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 5
static const unsigned thresholds[SYNDROME_ITERMAX] = {93, 85, 84};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 3
static const unsigned thresholds[SYNDROME_ITERMAX] = {45, 41, 40};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 4
static const unsigned thresholds[SYNDROME_ITERMAX] = {48, 41, 41};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 2
static const unsigned thresholds[SYNDROME_ITERMAX] = {60, 53, 52};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 3
static const unsigned thresholds[SYNDROME_ITERMAX] = {66, 60, 59};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 4
static const unsigned thresholds[SYNDROME_ITERMAX] = {70, 62, 61};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 5
static const unsigned thresholds[SYNDROME_ITERMAX] = {71, 66, 64};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 3
static const unsigned thresholds[SYNDROME_ITERMAX] = {87, 78, 78};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 4
static const unsigned thresholds[SYNDROME_ITERMAX] = {91, 82, 82};
#else
#error "no decoder thresholds for this (SYNDROME_LAMBDA, SYNDROME_N0)"
#endif

/*
 * syndrome_threshold - return the pinned flip threshold for iteration iter.
 *
 * Precondition: iter is in [1, SYNDROME_ITERMAX].  The decoder always calls
 * with a valid, data-independent iteration index, so no runtime branch on
 * secret data is required.
 */
unsigned
syndrome_threshold(unsigned iter)
{
    return thresholds[iter - 1];
}

int
syndrome_threshold_selftest(void)
{
/*
 * Expected threshold triples and invariant bounds for the active param set.
 * Checked against the pinned values and against the sanity invariants:
 *   (a) each th > SYNDROME_V / 2  (majority-style: flip only when most
 *       parity checks involving this bit are unsatisfied),
 *   (b) each th <= SYNDROME_V     (cannot exceed the column weight),
 *   (c) th(1) >= th(2) >= th(3)  (non-increasing sequence).
 */
#if SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 2
    static const unsigned expected[SYNDROME_ITERMAX] = {41, 35, 35};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 2
    static const unsigned expected[SYNDROME_ITERMAX] = {77, 69, 69};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 5
    static const unsigned expected[SYNDROME_ITERMAX] = {49, 42, 42};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 5
    static const unsigned expected[SYNDROME_ITERMAX] = {93, 85, 84};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 3
    static const unsigned expected[SYNDROME_ITERMAX] = {45, 41, 40};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 4
    static const unsigned expected[SYNDROME_ITERMAX] = {48, 41, 41};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 2
    static const unsigned expected[SYNDROME_ITERMAX] = {60, 53, 52};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 3
    static const unsigned expected[SYNDROME_ITERMAX] = {66, 60, 59};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 4
    static const unsigned expected[SYNDROME_ITERMAX] = {70, 62, 61};
#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 5
    static const unsigned expected[SYNDROME_ITERMAX] = {71, 66, 64};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 3
    static const unsigned expected[SYNDROME_ITERMAX] = {87, 78, 78};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 4
    static const unsigned expected[SYNDROME_ITERMAX] = {91, 82, 82};
#else
#error "no decoder thresholds for this (SYNDROME_LAMBDA, SYNDROME_N0)"
#endif

    unsigned i;
    unsigned th;
    unsigned prev;

    /* Check pinned values. */
    for (i = 1; i <= SYNDROME_ITERMAX; i++) {
        if (syndrome_threshold(i) != expected[i - 1])
            return -1;
    }

    /* Sanity invariants that any valid Long-Term parameter set must satisfy. */
    prev = SYNDROME_V + 1; /* sentinel larger than any valid threshold */
    for (i = 1; i <= SYNDROME_ITERMAX; i++) {
        th = syndrome_threshold(i);
        /* (a) majority-style: th > SYNDROME_V / 2 */
        if (th <= (unsigned)SYNDROME_V / 2)
            return -1;
        /* (b) cannot exceed the column weight */
        if (th > (unsigned)SYNDROME_V)
            return -1;
        /* (c) non-increasing sequence */
        if (th > prev)
            return -1;
        prev = th;
    }

    return 0;
}
