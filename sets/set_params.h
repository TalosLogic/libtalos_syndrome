/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * set_params.h - per-(lambda, n0) parameter table (the single source of truth
 * for p, v, t and every derived size).  NOT a standalone translation unit: a
 * per-set wrapper TU (sets/syn_<lambda>_<n0>.c) #defines SYNDROME_LAMBDA and
 * SYNDROME_N0, then #includes this header to materialize the set's constants,
 * then #includes the generic *_impl.inc bodies.  This replaces the old
 * -DSYNDROME_PARAM_SET switch in the public header.
 *
 * p, v, t are FIXED by (lambda, n0) from the ePrint 2025/1043 Long-Term table
 * (DESIGN.md §3.2); they are not independent knobs.
 */
#ifndef SYNDROME_SET_PARAMS_H
#define SYNDROME_SET_PARAMS_H

#if !defined(SYNDROME_LAMBDA) || !defined(SYNDROME_N0)
#error                                                                         \
    "set_params.h requires SYNDROME_LAMBDA and SYNDROME_N0 (set by the wrapper TU)"
#endif

/* ---- Row selection: (lambda, n0) -> p, v, t ------------------------------ */

#if SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 2
#if defined(SYNDROME_TESTONLY_WATERFALL_P)
#define SYNDROME_P SYNDROME_TESTONLY_WATERFALL_P
#else
#define SYNDROME_P 13613
#endif
#define SYNDROME_V 69
#define SYNDROME_T 130

#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 5
/* Pinned from ePrint 2025/1043 Table 2 (n = 39145); thresholds in 2.3, DFR 2.4. */
#if defined(SYNDROME_TESTONLY_WATERFALL_P)
#define SYNDROME_P SYNDROME_TESTONLY_WATERFALL_P
#else
#define SYNDROME_P 7829
#endif
#define SYNDROME_V 83
#define SYNDROME_T 57

#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 2
#define SYNDROME_P 43451
#define SYNDROME_V 135
#define SYNDROME_T 261

#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 5
/* Pinned from ePrint 2025/1043 Table 2 (n = 123665); thresholds 2.3, DFR 2.4. */
#if defined(SYNDROME_TESTONLY_WATERFALL_P)
#define SYNDROME_P SYNDROME_TESTONLY_WATERFALL_P
#else
#define SYNDROME_P 24733
#endif
#define SYNDROME_V 165
#define SYNDROME_T 113

#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 3
/* Pinned from ePrint 2025/1043 Table 2 (n = 30111); thresholds 2.3, DFR 2.4. */
#define SYNDROME_P 10037
#define SYNDROME_V 77
#define SYNDROME_T 83

#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 4
/* Pinned from ePrint 2025/1043 Table 2 (n = 34508); thresholds 2.3, DFR 2.4. */
#define SYNDROME_P 8627
#define SYNDROME_V 81
#define SYNDROME_T 66

#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 2
/* Pinned from ePrint 2025/1043 Table 2 (n = 53626); thresholds 2.3, DFR 2.4. */
#define SYNDROME_P 26813
#define SYNDROME_V 103
#define SYNDROME_T 195

#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 3
/* Pinned from ePrint 2025/1043 Table 2 (n = 59127); thresholds 2.3, DFR 2.4. */
#define SYNDROME_P 19709
#define SYNDROME_V 115
#define SYNDROME_T 124

#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 4
/* Pinned from ePrint 2025/1043 Table 2 (n = 67316); thresholds 2.3, DFR 2.4. */
#define SYNDROME_P 16829
#define SYNDROME_V 121
#define SYNDROME_T 98

#elif SYNDROME_LAMBDA == 192 && SYNDROME_N0 == 5
/* Pinned from ePrint 2025/1043 Table 2 (n = 76865); thresholds 2.3, DFR 2.4. */
#if defined(SYNDROME_TESTONLY_WATERFALL_P)
#define SYNDROME_P SYNDROME_TESTONLY_WATERFALL_P
#else
#define SYNDROME_P 15373
#endif
#define SYNDROME_V 125
#define SYNDROME_T 85

#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 3
/* Pinned from ePrint 2025/1043 Table 2 (n = 96207); thresholds 2.3, DFR 2.4. */
#define SYNDROME_P 32069
#define SYNDROME_V 153
#define SYNDROME_T 165

#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 4
/* Pinned from ePrint 2025/1043 Table 2 (n = 109748); thresholds 2.3, DFR 2.4. */
#define SYNDROME_P 27437
#define SYNDROME_V 161
#define SYNDROME_T 131

#else
#error "no parameter row for this (SYNDROME_LAMBDA, SYNDROME_N0)"
#endif

/*
 * SYNDROME_TESTONLY_WATERFALL_P is a reduced-p statistical-DFR override for the
 * test_dfr_mc waterfall harness (docs/DESIGN.md §3.2).  It is meaningful
 * for the lambda-128 / n0=2 set and for the n0=5 waterfall sets (both lambdas);
 * v, t and the thresholds are unchanged, only p shrinks into the measurable-DFR
 * regime.  Refuse it anywhere else, and in release builds.
 */
#if defined(SYNDROME_TESTONLY_WATERFALL_P)
#if defined(NDEBUG)
#error "SYNDROME_TESTONLY_WATERFALL_P is test-only; refused in NDEBUG builds"
#endif
#if !((SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 2) || SYNDROME_N0 == 5)
#error                                                                         \
    "SYNDROME_TESTONLY_WATERFALL_P: lambda-128 n0=2 or the n0=5 waterfall sets only"
#endif
#endif

/* ---- Derived sizes (formulas, lambda/n0-driven) -------------------------- */

/* Shared-secret width = 2*lambda bits (over-provisioned vs the DRBG cap). */
#define SYNDROME_SS_BYTES (2 * (SYNDROME_LAMBDA / 8))

/* Code length n = n0 * p. */
#define SYNDROME_N (SYNDROME_N0 * SYNDROME_P)

/* Bytes to hold one length-p circulant block (one row), ceil(p / 8). */
#define SYNDROME_BLOCK_BYTES ((SYNDROME_P + 7) / 8)

#define SYNDROME_PKHASH_BYTES (SYNDROME_SS_BYTES)

#define SYNDROME_PK_BYTES                                                      \
    ((SYNDROME_N0 - 1) * SYNDROME_BLOCK_BYTES)   /* systematic M        */
#define SYNDROME_CT_BYTES (SYNDROME_BLOCK_BYTES) /* syndrome s          */
#define SYNDROME_SK_BYTES                                                      \
    ((SYNDROME_N0 * SYNDROME_V * 2) + SYNDROME_SS_BYTES +                      \
     SYNDROME_PKHASH_BYTES) /* H | sigma | hpk */

/* Argus DEM-key width = lambda/8; identity buffer bound = 3*lambda/8. */
#define SYNDROME_ARGUS_KEY_BYTES (SYNDROME_LAMBDA / 8)
#define SYNDROME_ARGUS_ID_MAX_BYTES (3 * (SYNDROME_LAMBDA / 8))

/* tag = prim_id || s || ct: one selector byte, then s, then the DEM ciphertext. */
#define SYNDROME_ARGUS_TAG_BYTES(id_len)                                       \
    (1 + SYNDROME_CT_BYTES + (size_t)(id_len))

#endif /* SYNDROME_SET_PARAMS_H */
