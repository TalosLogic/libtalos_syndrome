/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ctr_add_avx2.c - AVX2 (x86_64) 256-bit backend for the bit-sliced counter
 * accumulate (see ctr_dispatch.h).
 *
 * Compiled with -mavx2 per-TU; the rest of the library does not require that
 * flag.  AVX2 is not baseline on x86_64, so this backend is selected at runtime
 * only when ichor_cpu_features() reports ICHOR_CPU_AVX2 (see ctr_add.c).
 * Compiles to an empty object when SYNDROME_HAVE_CTR_AVX2 is not defined.
 *
 * The 4-limb-wide analog of the SSE2 backend: four adjacent limbs share a
 * 256-bit lane, their carry chains are independent, so one __m256i carries all
 * four down the plane loop with no lane-crossing.  The per-(plane, limb) AND /
 * XOR set is identical to syndrome_ctr_add_scalar, so the output is
 * bit-identical.  planes and limbs are public, so control flow is
 * data-independent.
 */

#ifdef SYNDROME_HAVE_CTR_AVX2

#include "ctr_dispatch.h"

#include <immintrin.h>

static void
ctr_add_avx2(uint64_t *ctr, const uint64_t *add, unsigned planes, size_t limbs)
{
    size_t j;
    unsigned p;

    /* Limb quads (j .. j + 3): one __m256i holds all four carry chains. */
    for (j = 0; j + 3u < limbs; j += 4) {
        __m256i carry = _mm256_loadu_si256((const __m256i *)(add + j));

        for (p = 0; p < planes; p++) {
            uint64_t *cp = ctr + (size_t)p * limbs + j;
            __m256i c = _mm256_loadu_si256((const __m256i *)cp);
            __m256i cout =
                _mm256_and_si256(c, carry); /* carry out of plane p */

            _mm256_storeu_si256((__m256i *)cp, _mm256_xor_si256(c, carry));
            carry = cout;
        }
    }
    /* Up to three trailing limbs. */
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

const syndrome_ctr_ops_t syndrome_ctr_ops_avx2 = {
    .ctr_add = ctr_add_avx2,
    .backend_tag = SYNDROME_CTR_BACKEND_AVX2,
    .name = "avx2",
};

#else /* !SYNDROME_HAVE_CTR_AVX2 */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int syndrome_ctr_add_avx2_translation_unit_not_empty;

#endif /* SYNDROME_HAVE_CTR_AVX2 */
