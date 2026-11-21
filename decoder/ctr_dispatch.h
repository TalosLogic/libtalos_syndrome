/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ctr_dispatch.h - internal dispatch for the bit-sliced counter accumulate, the
 * decoder's hot per-support-offset word loop (compute_counters in
 * bitflip_impl.inc).
 *
 * Mirrors ichor's gf2x dispatch convention: a one-op table of function
 * pointers, an _Atomic table pointer selected once from ichor_cpu_features(),
 * per-arch backend TUs guarded by SYNDROME_HAVE_CTR_* (each built with its own
 * ISA flags), and a scalar table that is always compiled in as the portable
 * floor.  Every backend produces bit-identical output, so the KATs / goldens
 * hold across backends.
 *
 * Unlike the per-set decoder bodies (compiled once per (lambda, n0) via
 * set_bodies.inc), these kernels are generic over runtime (planes, limbs) and
 * compiled once into libtalos_syndrome, so the ISA-flagged TUs stay off the
 * per-set uniform-flag build and the scalar floor is preserved on every host.
 */
#ifndef SYNDROME_CTR_DISPATCH_H
#define SYNDROME_CTR_DISPATCH_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SYNDROME_CTR_BACKEND_SCALAR = 0,
    SYNDROME_CTR_BACKEND_SSE2,
    SYNDROME_CTR_BACKEND_AVX2,
    SYNDROME_CTR_BACKEND_NEON
} syndrome_ctr_backend_t;

typedef struct {
    void (*ctr_add)(uint64_t *, const uint64_t *, unsigned, size_t);
    syndrome_ctr_backend_t backend_tag;
    const char *name;
} syndrome_ctr_ops_t;

#ifdef SYNDROME_HAVE_CTR_SSE2
extern const syndrome_ctr_ops_t syndrome_ctr_ops_sse2;
#endif
#ifdef SYNDROME_HAVE_CTR_AVX2
extern const syndrome_ctr_ops_t syndrome_ctr_ops_avx2;
#endif
#ifdef SYNDROME_HAVE_CTR_NEON
extern const syndrome_ctr_ops_t syndrome_ctr_ops_neon;
#endif
extern const syndrome_ctr_ops_t syndrome_ctr_ops_scalar;

/*
 * Bit-sliced counter accumulate: for every position m, ctr[*][m] += bit m of
 * `add`, ripple-carry across the `planes` counter planes.  ctr is planes*limbs
 * contiguous (plane stride == limbs); add is one limbs-long ring element.  The
 * scalar kernel is the shared fallback and the bit-identical reference the SIMD
 * kernels are validated against.  planes and limbs are public, so control flow
 * is data-independent (constant-time over the secret counter and addend).
 */
void syndrome_ctr_add_scalar(uint64_t *, const uint64_t *, unsigned, size_t);

/* Dispatched entry: resolves the backend on first use, then forwards. */
void syndrome_ctr_add(uint64_t *ctr, const uint64_t *add, unsigned planes,
                      size_t limbs);

/*
 * Bit-sliced counter merge: acc += add as per-position integer addition of two
 * `planes`-deep bit-sliced counters (acc[*][m] := acc[*][m] + add[*][m] for
 * every position m), a branch-free full-adder rippling across the planes.  Both
 * acc and add are planes*limbs contiguous (plane stride == limbs), same layout
 * as syndrome_ctr_add's ctr.  The final carry out of the top plane is dropped:
 * a caller merges partial counters whose running total is at most the support
 * weight V, which the plane count is sized to hold, so no position overflows.
 * planes and limbs are public, so control flow is data-independent
 * (constant-time over the secret counters).  acc and add must not alias.
 *
 * Used to combine the per-worker partial counters of a threaded
 * compute_counters back into one counter, byte-identically to the serial
 * accumulation (integer addition is associative and commutative, so the merge
 * order and the V-loop partition do not affect the result).
 */
void syndrome_ctr_merge(uint64_t *acc, const uint64_t *add, unsigned planes,
                        size_t limbs);

/* Reads ichor_cpu_features() and selects the backend; called on first use. */
void syndrome_ctr_dispatch_init(void);

/* Resets the cached table pointer (test-only; compiled in only under
 * ICHOR_ENABLE_FORCE_BACKEND). */
#ifdef ICHOR_ENABLE_FORCE_BACKEND
void syndrome_ctr_dispatch_reset(void);
#endif

#endif /* SYNDROME_CTR_DISPATCH_H */
