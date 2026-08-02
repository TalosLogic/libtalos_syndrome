/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_sample_kat.c - fixed-seed KAT for the constant-time fixed-weight sampler
 * (TESTING.md component KAT #2: "fixed-weight sampler against fixed-DRBG-seed
 * expected outputs").
 *
 * syndrome_sample_selftest already checks the sampler's *properties* (exact
 * weight, distinctness, range, scatter, determinism, seed divergence).  That is
 * necessary but not a KAT: a subtly different-but-still-valid sampler would pass
 * it.  This test pins the *actual output* for a fixed DRBG seed, so the sampled
 * positions cannot drift silently.
 *
 * The pinned value is a SHA3-256 over the little-endian uint32 index lists of
 * (a) a weight-t draw over n = N (the encapsulation error) and (b) a weight-v
 * draw over n = p (an H block), each from a fresh DRBG on the same fixed seed.
 * One golden per parameter set, selected by SYNDROME_LAMBDA.  An all-zero golden
 * means "unpinned": the test then prints the computed digest to paste in and
 * does NOT fail (determinism is still hard-asserted).
 *
 * NOTE: this golden is a *regression* anchor (it freezes what this
 * implementation produces).  To make it a true cross-implementation KAT,
 * cross-check the printed digest against an independent reference sampler /
 * DRBG oracle before pinning (TESTING.md source #1).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/hash.h>
#include <ichor/util.h>

#include "core.h"
#include "talos_syndrome.h"

/* NIST-convention fixed 48-byte seed (0x00..0x2f), as used across the suite. */
static const uint8_t KAT_SEED[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};

/* One golden per (lambda, n0) */
#if SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 2
static const uint8_t SAMPLE_KAT_GOLDEN[32] = {
    0x73, 0x3c, 0x76, 0xb7, 0x22, 0x76, 0x46, 0x32, 0xe5, 0xac, 0x70,
    0x26, 0x97, 0xa7, 0x2c, 0xd5, 0x48, 0x7c, 0xf1, 0x34, 0x30, 0xf0,
    0xa1, 0x5c, 0xe1, 0xf5, 0x33, 0x41, 0xcd, 0x8b, 0x69, 0x89};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 2
static const uint8_t SAMPLE_KAT_GOLDEN[32] = {
    0x0e, 0x3b, 0x1a, 0x63, 0x12, 0x2d, 0x88, 0x4f, 0xf1, 0x2d, 0x6a,
    0x7f, 0xa9, 0x89, 0x15, 0x07, 0x67, 0xd4, 0x33, 0xd6, 0x7a, 0xc1,
    0xf3, 0x06, 0xb0, 0x3a, 0x84, 0xee, 0xbd, 0x96, 0x63, 0x55};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 5
static const uint8_t SAMPLE_KAT_GOLDEN[32] = {
    0xb1, 0xa4, 0x45, 0xb5, 0x06, 0xe0, 0x28, 0xd3, 0x8b, 0x11, 0xab,
    0x12, 0xa5, 0x2d, 0x80, 0xdb, 0x08, 0xf1, 0xf7, 0x76, 0x99, 0x56,
    0x4f, 0x13, 0x5f, 0x89, 0x2e, 0x36, 0xb7, 0xf6, 0xd6, 0x3c};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 5
static const uint8_t SAMPLE_KAT_GOLDEN[32] = {
    0x6a, 0x1e, 0xff, 0x91, 0x12, 0x83, 0x59, 0xa5, 0xc1, 0x1b, 0xb9,
    0x04, 0xef, 0xc8, 0xca, 0x20, 0x49, 0x50, 0x60, 0xcc, 0xe9, 0xd7,
    0x27, 0xad, 0x56, 0x99, 0x6d, 0x58, 0xa4, 0x09, 0x4f, 0xf1};
#else
#error "no SAMPLE_KAT_GOLDEN for this (SYNDROME_LAMBDA, SYNDROME_N0)"
#endif

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond)
        pass_count++;
    else
        printf("  FAIL: %s\n", name);
}

static int
is_all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    size_t i;

    for (i = 0; i < n; i++)
        acc = (uint8_t)(acc | p[i]);
    return acc == 0;
}

static void
print_c_bytes(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%s0x%02x,", (i % 8 == 0) ? "\n        " : " ", p[i]);
    printf("\n");
}

/* Absorb a uint32 index list as little-endian 4-byte words. */
static void
absorb_indices(ichor_hash_ctx_t *h, const uint32_t *idx, uint32_t n)
{
    uint32_t i;

    for (i = 0; i < n; i++) {
        uint8_t le[4];

        le[0] = (uint8_t)(idx[i]);
        le[1] = (uint8_t)(idx[i] >> 8);
        le[2] = (uint8_t)(idx[i] >> 16);
        le[3] = (uint8_t)(idx[i] >> 24);
        ichor_sha3_256_absorb(h, le, sizeof le);
    }
}

/* Compute the sampler digest for the fixed seed.  Returns 0 on sampler error. */
static int
sample_digest(uint8_t digest[32])
{
    syndrome_drbg rng;
    ichor_hash_ctx_t h;
    uint32_t et[SYNDROME_T];
    uint32_t hv[SYNDROME_V];
    int ok = 1;

    ichor_sha3_256_init(&h);

    /* (a) weight-t error over n = N. */
    syndrome_drbg_init(&rng, KAT_SEED);
    if (syndrome_sample_fixed_weight(et, SYNDROME_T, SYNDROME_N, &rng) != 0)
        ok = 0;
    absorb_indices(&h, et, SYNDROME_T);

    /* (b) weight-v H block over n = p, fresh DRBG on the same seed. */
    syndrome_drbg_init(&rng, KAT_SEED);
    if (syndrome_sample_fixed_weight(hv, SYNDROME_V, SYNDROME_P, &rng) != 0)
        ok = 0;
    absorb_indices(&h, hv, SYNDROME_V);

    ichor_sha3_256_finalize(&h, digest);

    syndrome_drbg_clear(&rng);
    ichor_secure_zero(et, sizeof et);
    ichor_secure_zero(hv, sizeof hv);
    return ok;
}

int
main(void)
{
    uint8_t d1[32];
    uint8_t d2[32];

    printf("sample KAT: fixed-seed sampler regression digest\n");

    check("sampler succeeds (draw a)", sample_digest(d1) == 1);
    check("determinism: identical digest across runs",
          sample_digest(d2) == 1 && memcmp(d1, d2, sizeof d1) == 0);

    if (is_all_zero(SAMPLE_KAT_GOLDEN, sizeof SAMPLE_KAT_GOLDEN)) {
        printf("  NOTE: SAMPLE_KAT_GOLDEN is unpinned for lambda=%d. After a\n"
               "  trusted run (ideally cross-checked vs a reference sampler),\n"
               "  paste the body below into test_sample_kat.c to arm the gate:",
               SYNDROME_LAMBDA);
        print_c_bytes(d1, sizeof d1);
        printf("  (determinism is still hard-checked above.)\n");
    } else {
        check("regression: digest matches pinned SAMPLE_KAT_GOLDEN",
              memcmp(d1, SAMPLE_KAT_GOLDEN, sizeof d1) == 0);
    }

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
