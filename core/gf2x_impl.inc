/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf2x.c - circulant arithmetic over F_2[x]/(x^p - 1).
 *
 * These per-set static functions are thin wrappers over the shared, runtime-
 * parameterized ring in libtalos_ichor (<ichor/gf2x.h>): the load/store/add/
 * multiply/rotate/invert algorithms (Karatsuba over ichor's dispatched clmul,
 * reduction modulo x^p - 1, constant-time barrel rotate, Itoh-Tsujii inverse)
 * all live there now, so syndrome and voleith share one audited implementation
 * and one dudect/KAT surface.  The wrappers exist only to keep this set's
 * static signatures (set_internal.h) unchanged, so the code/decoder/PKE/KEM/
 * opener call sites need no edits.
 *
 * ichor's ring is fully determined by the public prime p, which is a compile-
 * time constant here (SYNDROME_P).  We fix the ring descriptor once and hand it
 * -- plus the caller-sized element buffers and a single fixed scratch buffer --
 * to ichor on every call.  Nothing is allocated: the scratch is a file-static
 * array sized by the compile-time limb count.
 *
 * Constant-time: unchanged and inherited from ichor.  Every routine has data-
 * independent control flow and no secret-indexed memory access; the multiply
 * schedule, reduction, and rotation barrel depend only on the public p.
 * Inversion (keygen-only) requires ord_p(2) = p - 1, which every QC-MDPC set
 * guarantees.
 */
#include <stdlib.h>
#include <string.h>

#include <ichor/gf2x.h>

#include "set_internal.h"

#define LIMBS SYNDROME_GF2X_LIMBS

/*
 * The reduction reads the high half of the product shifted right by p bits.
 * With p prime (hence odd) the intra-limb shift p mod 64 is never zero, so the
 * companion shift (64 - s) is well-defined.  ichor enforces the same at runtime
 * (ring_init rejects p % 64 == 0); we assert it at compile time too.
 */
_Static_assert(SYNDROME_P % 64 != 0,
               "gf2x reduction assumes p is not a multiple of 64");

/*
 * Per-call scratch bound (in u64).  ichor's inv needs the most
 * (inv_scratch_limbs = 4*limbs + mul_scratch_limbs = 10*limbs + 128), which also
 * covers mul (6*limbs + 128) and rotl (4*limbs), so one compile-time-sized stack
 * buffer serves every op.  LIMBS is a compile-time constant here, so this is a
 * fixed-size stack array: no allocation, and no shared state.
 */
#define GF2X_SCRATCH_LIMBS (10u * (unsigned)LIMBS + 128u)

/*
 * Build the ring descriptor for this set's prime on the caller's stack.  init
 * derives only public quantities from the public p (a handful of integer ops,
 * no allocation), so this is cheap, constant-time with respect to any secret,
 * and, crucially, carries NO shared mutable state: every wrapper holds its own
 * ring and scratch, so the gf2x layer is fully reentrant (the DFR Monte-Carlo
 * harness and any other caller run it from many threads at once).  A valid set
 * prime never fails init and GF2X_SCRATCH_LIMBS always covers ichor's
 * requirement for it; the abort() is an integration tripwire, not an
 * input-reachable path.
 */
static void
gf2x_ring(ichor_gf2x_ring *ring)
{
    if (ichor_gf2x_ring_init(ring, SYNDROME_P) != 0 ||
        ring->inv_scratch_limbs > GF2X_SCRATCH_LIMBS)
        abort();
}

void
syndrome_gf2x_load(uint64_t *r, const uint8_t *in)
{
    ichor_gf2x_ring ring;

    gf2x_ring(&ring);
    ichor_gf2x_load(&ring, r, in);
}

void
syndrome_gf2x_store(uint8_t *out, const uint64_t *a)
{
    ichor_gf2x_ring ring;

    gf2x_ring(&ring);
    ichor_gf2x_store(&ring, out, a);
}

void
syndrome_gf2x_add(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    ichor_gf2x_ring ring;

    gf2x_ring(&ring);
    ichor_gf2x_add(&ring, r, a, b);
}

void
syndrome_gf2x_mul(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
    ichor_gf2x_ring ring;
    uint64_t scratch[GF2X_SCRATCH_LIMBS];

    gf2x_ring(&ring);
    ichor_gf2x_mul(&ring, r, a, b, scratch);
}

void
syndrome_gf2x_rotl_var(uint64_t *out, const uint64_t *in, uint32_t k)
{
    ichor_gf2x_ring ring;
    uint64_t scratch[GF2X_SCRATCH_LIMBS];

    gf2x_ring(&ring);
    ichor_gf2x_rotl_var(&ring, out, in, k, scratch);
}

int
syndrome_gf2x_inv(uint64_t *r, const uint64_t *a)
{
    ichor_gf2x_ring ring;
    uint64_t scratch[GF2X_SCRATCH_LIMBS];

    gf2x_ring(&ring);
    /* ichor returns 0 on success, -1 if a is not a unit; syndrome's contract is
     * identical (keygen resamples on failure). */
    return ichor_gf2x_inv(&ring, r, a, scratch);
}

/* ========================================================================
 * Self-test (docs/TESTING.md)
 *
 * Retained as an integration check that the wrappers drive ichor correctly for
 * this set's prime; the underlying algebra is also validated in ichor's own
 * test_gf2x across every QC-MDPC prime.
 * ======================================================================== */

static int
gf2x_equal(const uint64_t *a, const uint64_t *b)
{
    size_t i;

    for (i = 0; i < LIMBS; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

/* Build the polynomial with the listed exponents set (all others clear). */
static void
gf2x_set(uint64_t *p, const unsigned *exps, size_t n)
{
    size_t i;

    memset(p, 0, (size_t)LIMBS * sizeof(uint64_t));
    for (i = 0; i < n; i++)
        p[exps[i] >> 6] |= UINT64_C(1) << (exps[i] & 63u);
}

int
syndrome_gf2x_selftest(void)
{
    static const unsigned e_x[] = {1};
    static const unsigned e_top[] = {SYNDROME_P - 1};
    static const unsigned e_1px[] = {0, 1};
    static const unsigned e_1px2[] = {0, 2};
    static const unsigned e_mix[] = {0, 3, 64, SYNDROME_P - 2};
    static const unsigned e_mix3[] = {0, 1, 2};
    uint64_t zero[LIMBS], one[LIMBS], x[LIMBS];
    uint64_t a[LIMBS], b[LIMBS], c[LIMBS];
    uint64_t r[LIMBS], r2[LIMBS], t[LIMBS];
    uint8_t bytes[SYNDROME_BLOCK_BYTES];

    gf2x_set(zero, NULL, 0);
    gf2x_set(one, NULL, 0);
    one[0] = 1;
    gf2x_set(x, e_x, 1);

    /* add: self-inverse, and (a + b) + b == a. */
    gf2x_set(a, e_mix, sizeof e_mix / sizeof e_mix[0]);
    gf2x_set(b, e_1px, 2);
    syndrome_gf2x_add(c, a, a);
    if (!gf2x_equal(c, zero))
        return -1;
    syndrome_gf2x_add(c, a, b);
    syndrome_gf2x_add(c, c, b);
    if (!gf2x_equal(c, a))
        return -1;

    /* load/store round-trip. */
    syndrome_gf2x_store(bytes, a);
    syndrome_gf2x_load(r, bytes);
    if (!gf2x_equal(r, a))
        return -1;

    /* Multiplicative identity, both orders. */
    syndrome_gf2x_mul(r, a, one);
    if (!gf2x_equal(r, a))
        return -1;
    syndrome_gf2x_mul(r, one, a);
    if (!gf2x_equal(r, a))
        return -1;

    /* (1 + x)^2 == 1 + x^2 (the cross term 2x vanishes over F_2). */
    gf2x_set(b, e_1px, 2);
    gf2x_set(c, e_1px2, 2);
    syndrome_gf2x_mul(r, b, b);
    if (!gf2x_equal(r, c))
        return -1;

    /* Cyclic reduction: x^{p-1} * x == 1 (x^p folds to x^0). */
    gf2x_set(a, e_top, 1);
    syndrome_gf2x_mul(r, a, x);
    if (!gf2x_equal(r, one))
        return -1;

    /* Commutativity: a*b == b*a. */
    gf2x_set(a, e_mix, sizeof e_mix / sizeof e_mix[0]);
    gf2x_set(b, e_top, 1);
    syndrome_gf2x_add(b, b, x); /* b = x^{p-1} + x */
    syndrome_gf2x_mul(r, a, b);
    syndrome_gf2x_mul(r2, b, a);
    if (!gf2x_equal(r, r2))
        return -1;

    /* Distributivity: a*(b + c) == a*b + a*c. */
    gf2x_set(c, e_1px2, 2);
    syndrome_gf2x_add(t, b, c);
    syndrome_gf2x_mul(r, a, t);
    syndrome_gf2x_mul(r2, a, b);
    syndrome_gf2x_mul(t, a, c);
    syndrome_gf2x_add(r2, r2, t);
    if (!gf2x_equal(r, r2))
        return -1;

    /* Inverse: inv(1) == 1. */
    if (syndrome_gf2x_inv(r, one) != 0 || !gf2x_equal(r, one))
        return -1;

    /* Inverse: inv(x) == x^{p-1}, since x * x^{p-1} == x^p == 1. */
    gf2x_set(a, e_top, 1);
    if (syndrome_gf2x_inv(r, x) != 0 || !gf2x_equal(r, a))
        return -1;

    /* Inverse round-trip on an odd-weight unit: a * inv(a) == 1. */
    gf2x_set(a, e_mix3, sizeof e_mix3 / sizeof e_mix3[0]);
    if (syndrome_gf2x_inv(r, a) != 0)
        return -1;
    syndrome_gf2x_mul(c, a, r);
    if (!gf2x_equal(c, one))
        return -1;

    /*
     * Variable-amount rotation: rotl_var(a, t) == a * x^t for public t < p,
     * cross-checked against the trusted multiply.  The amounts span sub-limb,
     * limb-aligned (wr == 0), cross-limb, and near-p offsets.
     */
    {
        static const unsigned rot_amts[] = {
            0u,
            1u,
            5u,
            63u,
            64u,
            65u,
            127u,
            SYNDROME_P / 2u,
            SYNDROME_P - 2u,
            SYNDROME_P - 1u,
        };
        size_t ri;

        gf2x_set(a, e_mix, sizeof e_mix / sizeof e_mix[0]);
        for (ri = 0; ri < sizeof rot_amts / sizeof rot_amts[0]; ri++) {
            unsigned amt = rot_amts[ri];

            gf2x_set(b, &amt, 1); /* b = x^amt */
            syndrome_gf2x_mul(r, a, b);
            syndrome_gf2x_rotl_var(r2, a, (uint32_t)amt);
            if (!gf2x_equal(r, r2))
                return -1;
        }

        /* k == p is the identity (x^p == 1). */
        syndrome_gf2x_rotl_var(r2, a, (uint32_t)SYNDROME_P);
        if (!gf2x_equal(r2, a))
            return -1;

        /* Aliasing: out == in must be safe.  rotl_var(a, 1) == a * x. */
        memcpy(r, a, sizeof r);
        syndrome_gf2x_rotl_var(r, r, 1u);
        gf2x_set(b, e_x, 1); /* b = x */
        syndrome_gf2x_mul(r2, a, b);
        if (!gf2x_equal(r, r2))
            return -1;
    }

    return 0;
}
