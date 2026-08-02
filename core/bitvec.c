/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bitvec.c - bit-vector helpers shared across layers.
 *
 * Vectors are packed little-endian into bytes (convention documented in
 * core.h).  syndrome_bitvec_weight and syndrome_bitvec_xor are data-independent
 * and therefore constant-time over secret contents; the single-bit accessors
 * take a public index and must not be called with a secret-dependent one.
 */
#include <string.h>

#include "core.h"

/* Constant-time population count of one byte (SWAR; no table, no branch). */
static unsigned
popcount8(uint8_t x)
{
    x = (uint8_t)((x & 0x55) + ((x >> 1) & 0x55));
    x = (uint8_t)((x & 0x33) + ((x >> 2) & 0x33));
    x = (uint8_t)((x & 0x0f) + ((x >> 4) & 0x0f));
    return x;
}

size_t
syndrome_bitvec_weight(const uint8_t *v, size_t nbits)
{
    size_t full = nbits >> 3;
    unsigned rem = (unsigned)(nbits & 7);
    size_t w = 0;
    size_t i;

    for (i = 0; i < full; i++)
        w += popcount8(v[i]);
    if (rem != 0) {
        uint8_t mask = (uint8_t)((1u << rem) - 1u);
        w += popcount8((uint8_t)(v[full] & mask));
    }
    return w;
}

void
syndrome_bitvec_xor(uint8_t *dst, const uint8_t *a, const uint8_t *b,
                    size_t nbytes)
{
    size_t i;

    for (i = 0; i < nbytes; i++)
        dst[i] = (uint8_t)(a[i] ^ b[i]);
}

int
syndrome_bitvec_test(const uint8_t *v, size_t i)
{
    return (v[i >> 3] >> (i & 7)) & 1;
}

void
syndrome_bitvec_set(uint8_t *v, size_t i)
{
    v[i >> 3] |= (uint8_t)(1u << (i & 7));
}

void
syndrome_bitvec_clear(uint8_t *v, size_t i)
{
    v[i >> 3] &= (uint8_t) ~(1u << (i & 7));
}

void
syndrome_bitvec_flip(uint8_t *v, size_t i)
{
    v[i >> 3] ^= (uint8_t)(1u << (i & 7));
}

/*
 * Component self-test (docs/TESTING.md): exercises the accessors, weight
 * (including tail masking past the requested length), and xor.  Returns 0 on
 * success, -1 on any mismatch.
 */
int
syndrome_bitvec_selftest(void)
{
    static const size_t idx[] = {0, 7, 8, 13, 63, 64};
    const size_t n = sizeof idx / sizeof idx[0];
    uint8_t a[16], b[16], c[16];
    size_t i;

    /* Set a handful of bits; each must read back, others stay clear. */
    memset(a, 0, sizeof a);
    for (i = 0; i < n; i++)
        syndrome_bitvec_set(a, idx[i]);
    for (i = 0; i < n; i++)
        if (syndrome_bitvec_test(a, idx[i]) != 1)
            return -1;
    if (syndrome_bitvec_test(a, 1) != 0)
        return -1;
    if (syndrome_bitvec_weight(a, 128) != n)
        return -1;

    /* Clear lowers the weight and the bit. */
    syndrome_bitvec_clear(a, idx[0]);
    if (syndrome_bitvec_test(a, idx[0]) != 0 ||
        syndrome_bitvec_weight(a, 128) != n - 1)
        return -1;

    /* Flip toggles. */
    syndrome_bitvec_flip(a, idx[0]);
    if (syndrome_bitvec_test(a, idx[0]) != 1)
        return -1;
    syndrome_bitvec_flip(a, idx[0]);
    if (syndrome_bitvec_test(a, idx[0]) != 0)
        return -1;

    /* xor: a ^ a is zero; (a ^ b) ^ b recovers a. */
    syndrome_bitvec_xor(c, a, a, sizeof c);
    if (syndrome_bitvec_weight(c, 128) != 0)
        return -1;
    memset(b, 0xa5, sizeof b);
    syndrome_bitvec_xor(c, a, b, sizeof c);
    syndrome_bitvec_xor(c, c, b, sizeof c);
    if (memcmp(c, a, sizeof a) != 0)
        return -1;

    /* weight ignores bits past the requested length. */
    memset(b, 0xff, sizeof b);
    if (syndrome_bitvec_weight(b, 5) != 5)
        return -1;

    return 0;
}
