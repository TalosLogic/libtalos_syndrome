/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_wire.c - freeze test for the (M, s) byte-layout contract.
 *
 * CLAUDE.md design decision #6: the (M, s) byte layout is the ONLY contract
 * shared with libtalos_voleith, and once frozen it must not change silently.
 * docs/DESIGN.md §7 is the authoritative spec; this test pins it in code so any
 * drift fails a CTest gate.
 *
 * Unlike the load/store round-trip in syndrome_gf2x_selftest (which only proves
 * load and store are mutual inverses, and would still pass under any
 * self-consistent but wrong encoding), the checks here pin the ABSOLUTE
 * mapping: which byte and which bit a given polynomial coefficient lands in,
 * the canonical zero padding of the unused high bits, and the public-surface
 * sizes that M, s, and the Argus tag wrap into.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core.h"
#include "talos_syndrome.h"

#define LIMBS SYNDROME_GF2X_LIMBS

static int fails = 0;

static void
check(const char *what, int cond)
{
    if (!cond) {
        printf("  FAIL: %s\n", what);
        fails++;
    }
}

/* Set the single polynomial coefficient x^j in a fresh limb array. */
static void
set_coeff(uint64_t *r, unsigned j)
{
    memset(r, 0, (size_t)LIMBS * sizeof *r);
    r[j >> 6] |= (uint64_t)1 << (j & 63u);
}

/* True iff bytes b[0..n) are all zero except b[byte_idx], which equals mask. */
static int
bytes_onehot(const uint8_t *b, size_t n, size_t byte_idx, uint8_t mask)
{
    size_t i;

    for (i = 0; i < n; i++) {
        uint8_t want = (i == byte_idx) ? mask : 0u;
        if (b[i] != want)
            return 0;
    }
    return 1;
}

int
main(void)
{
    /* Representative coefficients: byte and limb boundaries, plus the top. */
    static const unsigned pos[] = {0, 1, 7, 8, 9, 63, 64, 65, SYNDROME_P - 1};
    uint64_t a[LIMBS];
    uint64_t expect[LIMBS];
    uint8_t bytes[SYNDROME_BLOCK_BYTES];
    size_t k;

    printf("wire-format freeze: (M, s) byte layout\n");

    /* 1. Public-surface size contract. */
    check("BLOCK_BYTES == ceil(p/8)",
          SYNDROME_BLOCK_BYTES == (SYNDROME_P + 7) / 8);
    check("CT_BYTES == BLOCK_BYTES (s is one circulant block)",
          SYNDROME_CT_BYTES == SYNDROME_BLOCK_BYTES);
    check("PK_BYTES == (n0-1)*BLOCK_BYTES (systematic M, I implicit)",
          SYNDROME_PK_BYTES == (SYNDROME_N0 - 1) * SYNDROME_BLOCK_BYTES);
    check("GF2X_LIMBS == ceil(p/64)",
          SYNDROME_GF2X_LIMBS == (SYNDROME_P + 63) / 64);
    check("ARGUS_TAG_BYTES(id) == 1 + CT_BYTES + id (prim_id || s || ct)",
          SYNDROME_ARGUS_TAG_BYTES(7) == (size_t)1 + SYNDROME_CT_BYTES + 7u);

    /*
     * 2. Coefficient <-> (byte, bit): x^j lands in byte j>>3, bit j&7
     *    (little-endian byte order, LSB-first within each byte; equivalently
     *    byte i bit b is the coefficient of x^(8*i + b)).
     */
    for (k = 0; k < sizeof pos / sizeof pos[0]; k++) {
        unsigned j = pos[k];

        /* store: a one-hot coefficient stores to exactly one byte/bit. */
        set_coeff(a, j);
        memset(bytes, 0xAA, sizeof bytes);
        syndrome_gf2x_store(bytes, a);
        check("store: x^j -> byte j>>3, bit j&7 (one-hot)",
              bytes_onehot(bytes, sizeof bytes, j >> 3,
                           (uint8_t)(1u << (j & 7u))));

        /* load: the reverse maps the same byte/bit back to x^j. */
        set_coeff(expect, j);
        memset(bytes, 0, sizeof bytes);
        bytes[j >> 3] = (uint8_t)(1u << (j & 7u));
        memset(a, 0xFF, sizeof a);
        syndrome_gf2x_load(a, bytes);
        check("load: byte j>>3, bit j&7 -> x^j",
              memcmp(a, expect, sizeof a) == 0);
    }

    /*
     * 3. Canonical zero padding: the top (8*BLOCK_BYTES - p) bits are not part
     *    of the block and MUST be zero on the wire.  load() masks them off, so
     *    even an all-ones input round-trips to a canonical block whose final
     *    byte keeps only its valid low bits.
     */
    {
        unsigned last_bits = SYNDROME_P - 8u * (SYNDROME_BLOCK_BYTES - 1u);
        uint8_t last_mask = (uint8_t)((1u << last_bits) - 1u);
        int low_full = 1;
        size_t i;

        memset(bytes, 0xFF, sizeof bytes);
        syndrome_gf2x_load(a, bytes);
        syndrome_gf2x_store(bytes, a);

        check("load masks padding: final byte keeps only valid bits",
              bytes[SYNDROME_BLOCK_BYTES - 1] == last_mask);
        for (i = 0; i + 1 < SYNDROME_BLOCK_BYTES; i++)
            if (bytes[i] != 0xFF)
                low_full = 0;
        check("load masks padding: low bytes are untouched (full)", low_full);
    }

    if (fails != 0) {
        printf("wire: %d FAILED\n", fails);
        return 1;
    }
    printf("wire: OK\n");
    return 0;
}
