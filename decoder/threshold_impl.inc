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
 * Source: ePrint 2025/1043, Table 2 (Long-Term sets).
 *   (lambda 128, n0 2) p=13613 v=69  t=130: th = 41, 35, 35
 *   (lambda 256, n0 2) p=43451 v=135 t=261: th = 77, 69, 69
 *   (lambda 128, n0 5) p=7829  v=83  t=57 : th = 49, 42, 42
 *   (lambda 256, n0 5) p=24733 v=165 t=113: th = 93, 85, 84
 * All four rows are pinned from Table 2; iterMax=3 is fixed by the paper's
 * decoder and thresholds are iteration-indexed only.  The closed-form
 * DFR <= 2^-lambda bound is established in DESIGN.md §3.2 (-log2 DFR =
 * 130.40 / 256.49 for the n0=5 sets); the Monte-Carlo decoder-fidelity check in
 * the waterfall regime is test_dfr_mc.c (subtask 2.4).
 */
#if SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 2
static const unsigned thresholds[SYNDROME_ITERMAX] = {41, 35, 35};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 2
static const unsigned thresholds[SYNDROME_ITERMAX] = {77, 69, 69};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 5
static const unsigned thresholds[SYNDROME_ITERMAX] = {49, 42, 42};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 5
static const unsigned thresholds[SYNDROME_ITERMAX] = {93, 85, 84};
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
