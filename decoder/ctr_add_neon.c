/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ctr_add_neon.c - NEON (aarch64) 128-bit backend for the bit-sliced counter
 * accumulate (see ctr_dispatch.h).
 *
 * Advanced SIMD is mandatory on ARMv8-A, so no per-TU arch flag is needed and
 * the probe (CMakeLists.txt) restricts SYNDROME_HAVE_CTR_NEON to aarch64.  The
 * backend is still runtime-gated on ICHOR_CPU_NEON (set only on aarch64) in the
 * dispatch, so a 32-bit ARM / other build yields to scalar.  Compiles to an
 * empty object when SYNDROME_HAVE_CTR_NEON is not defined.
 *
 * The 2-limb-wide analog of the SSE2 backend: two adjacent limbs share a
 * 128-bit lane, their carry chains are independent, so one uint64x2_t carries
 * both down the plane loop with no lane-crossing (the accumulate has no shifts,
 * only AND / XOR, so no signed-count games are needed).  The per-(plane, limb)
 * AND / XOR set is identical to syndrome_ctr_add_scalar, so the output is
 * bit-identical.  planes and limbs are public, so control flow is
 * data-independent.
 */

#ifdef SYNDROME_HAVE_CTR_NEON

#include "ctr_dispatch.h"

#include <arm_neon.h>

static void
ctr_add_neon(uint64_t *ctr, const uint64_t *add, unsigned planes, size_t limbs)
{
    size_t j;
    unsigned p;

    /* Limb pairs (j, j + 1): one uint64x2_t holds both carry chains. */
    for (j = 0; j + 1u < limbs; j += 2) {
        uint64x2_t carry = vld1q_u64(add + j);

        for (p = 0; p < planes; p++) {
            uint64_t *cp = ctr + (size_t)p * limbs + j;
            uint64x2_t c = vld1q_u64(cp);
            uint64x2_t cout = vandq_u64(c, carry); /* carry out of plane p */

            vst1q_u64(cp, veorq_u64(c, carry));
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

const syndrome_ctr_ops_t syndrome_ctr_ops_neon = {
    .ctr_add = ctr_add_neon,
    .backend_tag = SYNDROME_CTR_BACKEND_NEON,
    .name = "neon",
};

#else /* !SYNDROME_HAVE_CTR_NEON */

/* ISO C forbids an empty translation unit, and -Wpedantic / -Werror reject
 * one; give the guarded-out build a single harmless declaration. */
typedef int syndrome_ctr_add_neon_translation_unit_not_empty;

#endif /* SYNDROME_HAVE_CTR_NEON */
