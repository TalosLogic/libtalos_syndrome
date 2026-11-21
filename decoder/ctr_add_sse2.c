/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ctr_add_sse2.c - SSE2 (x86_64) 128-bit backend for the bit-sliced counter
 * accumulate (see ctr_dispatch.h).
 *
 * Compiled with -msse2 per-TU; the rest of the library does not require that
 * flag.  SSE2 is baseline on x86_64, so this backend is selected by compile
 * presence whenever no wider backend applies (see ctr_add.c).  Compiles to an
 * empty object when SYNDROME_HAVE_CTR_SSE2 is not defined.
 *
 * The scalar kernel runs the ripple-carry limb-outer / plane-inner so each limb
 * owns a single carry word down the planes.  Here two adjacent limbs share a
 * 128-bit lane: the two carry chains are independent, so one __m128i carries
 * both down the plane loop with no lane-crossing.  The per-(plane, limb) AND /
 * XOR set is identical to syndrome_ctr_add_scalar, so the output is
 * bit-identical.  planes and limbs are public, so control flow is
 * data-independent.
 */

#ifdef SYNDROME_HAVE_CTR_SSE2

#include "ctr_dispatch.h"

#include <emmintrin.h>

static void
ctr_add_sse2(uint64_t *ctr, const uint64_t *add, unsigned planes, size_t limbs)
{
    size_t j;
    unsigned p;

    /* Limb pairs (j, j + 1): one __m128i holds both independent carry chains. */
    for (j = 0; j + 1u < limbs; j += 2) {
        __m128i carry = _mm_loadu_si128((const __m128i *)(add + j));

        for (p = 0; p < planes; p++) {
            uint64_t *cp = ctr + (size_t)p * limbs + j;
            __m128i c = _mm_loadu_si128((const __m128i *)cp);
            __m128i cout = _mm_and_si128(c, carry); /* carry out of plane p */

            _mm_storeu_si128((__m128i *)cp, _mm_xor_si128(c, carry));
            carry = cout;
        }
    }
    /* Odd trailing limb. */
    for (; j < limbs; j++) {
        uint64_t carry = add[j];

        for (p = 0; p < planes; p++) {
            uint64_t *cp = ctr + (size_t)p * limbs + j;
            uint64_t cout = *cp & carry;

            *cp ^= carry;
            carry = cout;
        }
    }
}

const syndrome_ctr_ops_t syndrome_ctr_ops_sse2 = {
    .ctr_add = ctr_add_sse2,
    .backend_tag = SYNDROME_CTR_BACKEND_SSE2,
    .name = "sse2",
};

#else /* !SYNDROME_HAVE_CTR_SSE2 */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int syndrome_ctr_add_sse2_translation_unit_not_empty;

#endif /* SYNDROME_HAVE_CTR_SSE2 */
