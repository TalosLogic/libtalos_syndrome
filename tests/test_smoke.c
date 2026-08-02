/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_smoke.c - scaffold smoke test.
 *
 * Confirms the library links, the ichor submodule is wired in through syndrome's
 * own build, and the per-set dispatch surface reports at least one enabled set
 * with self-consistent sizes.  Per-layer behaviour and the full KEM round-trip
 * have dedicated tests; this stays a lean links-and-wiring smoke and asserts no
 * cryptography itself.  Public API only (talos_syndrome.h) apart from the ichor
 * linkage check.
 */
#include <stdio.h>
#include <string.h>

#include "talos_syndrome.h"

#include <ichor/hash.h>

static const char *
set_name(syndrome_set_id set)
{
    switch (set) {
    case SYNDROME_SET_128_2:
        return "SYN_128_2";
    case SYNDROME_SET_128_5:
        return "SYN_128_5";
    case SYNDROME_SET_256_2:
        return "SYN_256_2";
    case SYNDROME_SET_256_5:
        return "SYN_256_5";
    default:
        return "?";
    }
}

int
main(void)
{
    int enabled = 0;
    int fails = 0;
    syndrome_set_id s;

    printf("%s\n", syndrome_version_string());

    for (s = 0; s < SYNDROME_SET_COUNT; s++) {
        if (!syndrome_set_enabled(s))
            continue;
        enabled++;
        printf("  set %-9s: pk=%zu sk=%zu ct=%zu ss=%zu argus_id_max=%zu\n",
               set_name(s), syndrome_pk_bytes(s), syndrome_sk_bytes(s),
               syndrome_ct_bytes(s), syndrome_ss_bytes(s),
               syndrome_argus_id_max_bytes(s));

        /* Sizes of an enabled set must be non-zero and fit the MAX ceilings. */
        if (syndrome_pk_bytes(s) == 0 ||
            syndrome_pk_bytes(s) > SYNDROME_MAX_PK_BYTES)
            fails++;
        if (syndrome_sk_bytes(s) == 0 ||
            syndrome_sk_bytes(s) > SYNDROME_MAX_SK_BYTES)
            fails++;
        if (syndrome_ct_bytes(s) == 0 ||
            syndrome_ct_bytes(s) > SYNDROME_MAX_CT_BYTES)
            fails++;
        if (syndrome_ss_bytes(s) == 0 ||
            syndrome_ss_bytes(s) > SYNDROME_MAX_SS_BYTES)
            fails++;
    }

    /* A disabled set reports zero sizes. */
    for (s = 0; s < SYNDROME_SET_COUNT; s++) {
        if (!syndrome_set_enabled(s) && syndrome_pk_bytes(s) != 0)
            fails++;
    }

    if (enabled == 0) {
        fprintf(stderr, "FAIL: no set is enabled in this build\n");
        return 1;
    }
    if (fails != 0) {
        fprintf(stderr, "FAIL: %d size-consistency check(s) failed\n", fails);
        return 1;
    }

    /*
     * Submodule linkage: ichor's SHA3-256 of the empty string must match the
     * FIPS 202 vector.  Confirms the ichor include path and link work through
     * syndrome's own build.
     */
    {
        static const uint8_t want[4] = {0xa7, 0xff, 0xc6, 0xf8};
        uint8_t digest[32];

        ichor_sha3_256(digest, NULL, 0);
        if (memcmp(digest, want, sizeof(want)) != 0) {
            fprintf(stderr, "FAIL: ichor sha3-256 linkage/KAT mismatch\n");
            return 1;
        }
    }

    printf("smoke: OK (%d set(s) enabled; library links; ichor wired)\n",
           enabled);
    return 0;
}
