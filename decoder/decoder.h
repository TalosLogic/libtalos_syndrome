/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * decoder.h - internal interface for Layer 3 (decoder/).
 *
 * The exact 3-iteration (iterMax = 3) parallel bit-flipping decoder of
 * Algorithm 1, with thresholds pinned per parameter set.  Control flow is
 * data-independent: a single observed decode failure leaks the private key,
 * so success and failure must be indistinguishable by timing or path.
 */
#ifndef SYNDROME_DECODER_H
#define SYNDROME_DECODER_H

#include "set_internal.h" /* sizes (via set_params.h) + gf2x (static) */

/*
 * Number of bit-flipping iterations (iterMax in Algorithm 1, ePrint
 * 2025/1043).  Fixed at 3; the decoder runs this many iterations with
 * data-independent control flow regardless of syndrome weight.
 */
#define SYNDROME_ITERMAX 3

/*
 * ThresholdChoice for Algorithm 1 (ePrint 2025/1043).  Returns the pinned
 * flip threshold for iteration iter (valid range 1..SYNDROME_ITERMAX) of
 * the active parameter set.  The greedy-optimized design makes the threshold
 * a function of the iteration index only, independent of the syndrome.
 *
 * Values are pinned to the Long-Term DFR analysis (Table 2 of ePrint
 * 2025/1043).  Changing a parameter set without re-deriving thresholds and
 * re-validating DFR <= 2^-lambda is a security bug.
 */
static unsigned syndrome_threshold(unsigned);

/*
 * syndrome_bitflip_decode(e, ok, h, supp, s) runs the fixed 3-iteration
 * parallel bit-flipping decoder (Algorithm 1, ePrint 2025/1043).  Recovers the
 * weight-t error blocks e[0..n0-1] from the private syndrome s, the n0 sparse
 * H-block supports supp[0..n0-1] (each SYNDROME_V column positions, used to
 * build the flip counters), and the matching dense H blocks h[0..n0-1] (dense
 * ring elements, used for the syndrome update); e and h are SYNDROME_N0-row
 * arrays.  *ok is set to 1 on success (residual syndrome zero), else 0.  Control
 * flow is data-independent (fixed iterMax=3, no early exit, no secret branch or
 * secret-indexed access), so decode success/failure is timing-indistinguishable;
 * the KEM layer consumes *ok via constant-time implicit rejection.
 */
static void syndrome_bitflip_decode(uint64_t (*)[SYNDROME_GF2X_LIMBS], int *,
                                    const uint64_t (*)[SYNDROME_GF2X_LIMBS],
                                    const uint16_t (*)[SYNDROME_V],
                                    const uint64_t *);

static int syndrome_bitflip_selftest(void);
static int syndrome_bitflip_ctr_selftest(void);
static int syndrome_bitflip_diff_selftest(void);
static int syndrome_threshold_selftest(void);

#endif /* SYNDROME_DECODER_H */
