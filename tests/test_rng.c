/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rng.c - tests for core/rng.c (AES-256 CTR_DRBG).
 *
 * Anchors correctness on the bundled NIST PQC KAT vector (via
 * syndrome_rng_selftest) and checks the DRBG contract: identical seeds produce
 * identical streams, distinct seeds diverge, and each generate call advances
 * the reseed counter.
 */
#include <stdio.h>
#include <string.h>

#include "core.h"

static int failures;

static void
report(const char *name, int ok)
{
    printf("  %-32s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok)
        failures++;
}

static void
seed_fill(uint8_t seed[48], uint8_t base)
{
    int i;

    for (i = 0; i < 48; i++)
        seed[i] = (uint8_t)(base + i);
}

int
main(void)
{
    uint8_t seed[48], seed2[48], a[100], b[100];
    syndrome_drbg ctx, ctx2;
    int ok;

    printf("rng tests:\n");

    /* NIST PQC CTR_DRBG known-answer vector. */
    report("syndrome_rng_selftest (NIST KAT)", syndrome_rng_selftest() == 0);

    /* Determinism: identical seeds yield identical streams. */
    seed_fill(seed, 0);
    syndrome_drbg_init(&ctx, seed);
    ok = syndrome_drbg_generate(&ctx, a, sizeof a) == 0;
    syndrome_drbg_init(&ctx2, seed);
    ok = ok && syndrome_drbg_generate(&ctx2, b, sizeof b) == 0;
    report("same seed -> same stream", ok && memcmp(a, b, sizeof a) == 0);

    /* Distinct seeds diverge. */
    seed_fill(seed2, 1);
    syndrome_drbg_init(&ctx2, seed2);
    ok = syndrome_drbg_generate(&ctx2, b, sizeof b) == 0;
    report("distinct seed -> different stream",
           ok && memcmp(a, b, sizeof a) != 0);

    /* The reseed counter advances once per generate call. */
    syndrome_drbg_init(&ctx, seed);
    {
        uint64_t c0 = ctx.reseed_counter;
        uint8_t tmp[16];

        ok = syndrome_drbg_generate(&ctx, tmp, sizeof tmp) == 0;
        report("reseed_counter advances",
               ok && ctx.reseed_counter == c0 + 1 && c0 == 1);
    }

    syndrome_drbg_clear(&ctx);
    syndrome_drbg_clear(&ctx2);

    if (failures != 0) {
        fprintf(stderr, "rng: %d failure(s)\n", failures);
        return 1;
    }
    printf("rng: OK\n");
    return 0;
}
