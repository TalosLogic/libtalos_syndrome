/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_kem_kat.c - deterministic KAT and round-trip harness for the KEM.
 *
 * Drives the derandomized seam (syndrome_kem_*_derand) from a fixed top-level
 * seed so the whole keygen/encap/decap sequence is reproducible, in the style
 * of the NIST PQC .req/.rsp KAT generator (one per-case DRBG; keypair then
 * encap consume the same stream).  There is no external KAT vector for the
 * Long-Term parameter sets (new in ePrint 2025/1043), so we generate our own
 * regression fingerprint: a SHA3-256 over (seed, pk, sk, ct, ss) across all
 * cases (docs/TESTING.md, TODO.md "Full KEM").  The constants (seed, case
 * count, golden digest) are shared with the NIST-format emitter
 * (kem_kat_gen.c) via kem_kat_common.h so the two cannot drift.
 *
 * Three checks:
 *   - round-trip: decap(encap) == encap shared secret, every case (invariant;
 *     no pinned value needed);
 *   - determinism: re-running the whole sweep yields an identical digest;
 *   - regression: the digest equals the pinned SYNDROME_KAT_GOLDEN.  Until
 *     pinned (the all-zero placeholder), the harness prints the computed digest
 *     so it can be captured from a trusted run and pasted in -- it does NOT fail
 *     on the placeholder, since round-trip and determinism are already
 *     hard-asserted.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/hash.h>
#include <ichor/util.h>

#include "core.h"
#include "kem.h"
#include "kem_kat_common.h"
#include "talos_syndrome.h"

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

/* Print the digest as a C array body, directly pasteable into the golden. */
static void
print_c_bytes(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        printf("%s0x%02x,", (i % 8 == 0) ? "\n        " : " ", p[i]);
    }
    printf("\n");
}

/*
 * Run the full deterministic sweep, accumulating the regression digest.
 * Returns 1 if every case round-tripped, else 0.
 */
static int
run_kat(uint8_t digest[32])
{
    syndrome_drbg top;
    ichor_hash_ctx_t acc;
    int rt_ok = 1;
    int i;

    syndrome_drbg_init(&top, SYNDROME_KAT_TOPSEED);
    ichor_sha3_256_init(&acc);

    for (i = 0; i < SYNDROME_KAT_CASES; i++) {
        syndrome_drbg rng;
        uint8_t seed[48];
        uint8_t pk[SYNDROME_PK_BYTES];
        uint8_t sk[SYNDROME_SK_BYTES];
        uint8_t ct[SYNDROME_CT_BYTES];
        uint8_t ss[SYNDROME_SS_BYTES];
        uint8_t ss2[SYNDROME_SS_BYTES];

        if (syndrome_drbg_generate(&top, seed, sizeof(seed)) != 0)
            rt_ok = 0;
        syndrome_drbg_init(&rng, seed);

        if (syndrome_kem_keypair_derand(pk, sk, &rng) != 0)
            rt_ok = 0;
        if (syndrome_kem_encap_derand(ct, ss, pk, &rng) != 0)
            rt_ok = 0;
        if (syndrome_kem_decap_impl(ss2, ct, sk) != 0)
            rt_ok = 0;
        if (memcmp(ss, ss2, sizeof(ss)) != 0)
            rt_ok = 0;

        ichor_sha3_256_absorb(&acc, seed, sizeof(seed));
        ichor_sha3_256_absorb(&acc, pk, sizeof(pk));
        ichor_sha3_256_absorb(&acc, sk, sizeof(sk));
        ichor_sha3_256_absorb(&acc, ct, sizeof(ct));
        ichor_sha3_256_absorb(&acc, ss, sizeof(ss));

        syndrome_drbg_clear(&rng);
        ichor_secure_zero(sk, sizeof(sk));
        ichor_secure_zero(ss, sizeof(ss));
        ichor_secure_zero(ss2, sizeof(ss2));
    }

    ichor_sha3_256_finalize(&acc, digest);
    syndrome_drbg_clear(&top);
    return rt_ok;
}

int
main(void)
{
    uint8_t d1[32];
    uint8_t d2[32];

    printf("kem KAT: deterministic round-trip + regression digest (%d cases)\n",
           SYNDROME_KAT_CASES);

    check("round-trip: decap(encap) == ss for every case", run_kat(d1) == 1);
    check("determinism: identical digest across runs",
          run_kat(d2) == 1 && memcmp(d1, d2, sizeof(d1)) == 0);

    if (is_all_zero(SYNDROME_KAT_GOLDEN, sizeof(SYNDROME_KAT_GOLDEN))) {
        printf("  NOTE: SYNDROME_KAT_GOLDEN is unpinned. After a trusted run,\n"
               "  paste the body below into kem_kat_common.h to arm the gate:");
        print_c_bytes(d1, sizeof(d1));
        printf(
            "  (round-trip and determinism are still hard-checked above.)\n");
    } else {
        check("regression: digest matches pinned SYNDROME_KAT_GOLDEN",
              memcmp(d1, SYNDROME_KAT_GOLDEN, sizeof(d1)) == 0);
    }

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
