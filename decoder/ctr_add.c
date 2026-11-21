/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ctr_add.c - scalar bit-sliced counter accumulate plus the dispatch table for
 * the decoder's hot word loop (see ctr_dispatch.h).
 *
 * The scalar kernel runs the ripple-carry limb-outer / plane-inner: each limb
 * carries a single carry word down the planes, so there is no carry scratch
 * array (no hot-path allocation) and nothing secret to wipe on exit.  The SIMD
 * backends widen the outer limb loop.
 */
#include "ctr_dispatch.h"

#include <ichor/cpu.h>

void
syndrome_ctr_add_scalar(uint64_t *ctr, const uint64_t *add, unsigned planes,
                        size_t limbs)
{
    size_t j;
    unsigned p;

    for (j = 0; j < limbs; j++) {
        uint64_t carry = add[j];

        for (p = 0; p < planes; p++) {
            uint64_t *cp = ctr + (size_t)p * limbs + j;
            uint64_t cout = *cp & carry; /* carry out of plane p */

            *cp ^= carry; /* sum bit of plane p */
            carry = cout;
        }
    }
}

const syndrome_ctr_ops_t syndrome_ctr_ops_scalar = {
    .ctr_add = syndrome_ctr_add_scalar,
    .backend_tag = SYNDROME_CTR_BACKEND_SCALAR,
    .name = "scalar",
};

static _Atomic(const syndrome_ctr_ops_t *) syndrome_ctr_ops = NULL;

void
syndrome_ctr_dispatch_init(void)
{
    if (atomic_load_explicit(&syndrome_ctr_ops, memory_order_acquire) != NULL)
        return;

    const syndrome_ctr_ops_t *pick = NULL;

    /* feat is consulted by the AVX2 and NEON backends; a build with only SSE2
     * (baseline on x86_64) or none compiled in never reads it. */
#if defined(SYNDROME_HAVE_CTR_AVX2) || defined(SYNDROME_HAVE_CTR_NEON)
    uint32_t feat = ichor_cpu_features();
#endif
#if defined(SYNDROME_HAVE_CTR_AVX2)
    if (pick == NULL && (feat & ICHOR_CPU_AVX2))
        pick = &syndrome_ctr_ops_avx2;
#endif
#if defined(SYNDROME_HAVE_CTR_SSE2)
    if (pick == NULL)
        pick = &syndrome_ctr_ops_sse2;
#endif
#if defined(SYNDROME_HAVE_CTR_NEON)
    if (pick == NULL && (feat & ICHOR_CPU_NEON))
        pick = &syndrome_ctr_ops_neon;
#endif

    if (pick == NULL)
        pick = &syndrome_ctr_ops_scalar;

    const syndrome_ctr_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&syndrome_ctr_ops, &expected, pick,
                                            memory_order_release,
                                            memory_order_acquire);
}

static const syndrome_ctr_ops_t *
syndrome_ctr_ops_get(void)
{
    const syndrome_ctr_ops_t *ops =
        atomic_load_explicit(&syndrome_ctr_ops, memory_order_acquire);
    if (ops == NULL) {
        syndrome_ctr_dispatch_init();
        ops = atomic_load_explicit(&syndrome_ctr_ops, memory_order_acquire);
    }
    return ops;
}

void
syndrome_ctr_add(uint64_t *ctr, const uint64_t *add, unsigned planes,
                 size_t limbs)
{
    syndrome_ctr_ops_get()->ctr_add(ctr, add, planes, limbs);
}

#ifdef ICHOR_ENABLE_FORCE_BACKEND
/* Test-only hook: clears the cached ops pointer so the next call re-selects a
 * backend.  Compiled out of release / vendored builds. */
void
syndrome_ctr_dispatch_reset(void)
{
    atomic_store_explicit(&syndrome_ctr_ops, NULL, memory_order_release);
}
#endif /* ICHOR_ENABLE_FORCE_BACKEND */
