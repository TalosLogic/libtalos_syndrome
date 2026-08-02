/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_kem.c - KEM (FO transform) property tests over the public set-id API.
 *
 * Runs the docs/TESTING.md property battery for every set this build enables:
 *   - Correctness round-trip: decap of an honest ciphertext recovers encap's
 *     shared secret.
 *   - Fresh randomness: two encapsulations under one key differ in both the
 *     ciphertext and the shared secret (D2/D5; mandatory for anonymity).
 *   - Implicit rejection: a malformed / tampered ciphertext never yields an
 *     error (decap returns 0) and produces a shared secret unequal to the honest
 *     one, deterministic in (sk, ct) -- a pseudo-random value, not a
 *     decode-failure oracle.  Covered via the all-zero ct, a non-canonical ct,
 *     and a single-bit-flipped honest ct.
 *   - Wrong key: decap under a different secret key rejects.
 *
 * keygen/encap draw system entropy, so these are relational checks (no fixed KAT
 * vectors); byte-exact KATs are test_kem_kat's job.  Buffers are sized by the
 * SYNDROME_MAX_* ceilings, valid for any set.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

static void
test_set(syndrome_set_id set)
{
    uint8_t pk[SYNDROME_MAX_PK_BYTES];
    uint8_t sk[SYNDROME_MAX_SK_BYTES];
    uint8_t pk2[SYNDROME_MAX_PK_BYTES];
    uint8_t sk2[SYNDROME_MAX_SK_BYTES];
    uint8_t ct[SYNDROME_MAX_CT_BYTES];
    uint8_t ct_b[SYNDROME_MAX_CT_BYTES];
    uint8_t ct_bad[SYNDROME_MAX_CT_BYTES];
    uint8_t k1[SYNDROME_MAX_SS_BYTES];
    uint8_t kb[SYNDROME_MAX_SS_BYTES];
    uint8_t k2[SYNDROME_MAX_SS_BYTES];
    uint8_t kr[SYNDROME_MAX_SS_BYTES];
    uint8_t kr2[SYNDROME_MAX_SS_BYTES];
    size_t ct_len = syndrome_ct_bytes(set);
    size_t ss_len = syndrome_ss_bytes(set);

    if (syndrome_kem_keypair(set, pk, sk) != 0) {
        printf("  FAIL: keypair\n");
        test_count++;
        return;
    }
    if (syndrome_kem_encap(set, ct, k1, pk) != 0) {
        printf("  FAIL: encap\n");
        test_count++;
        return;
    }

    /* Correctness round-trip. */
    check("decap return value is 0", syndrome_kem_decap(set, k2, ct, sk) == 0);
    check("round-trip: decap K == encap K", memcmp(k1, k2, ss_len) == 0);

    /* Fresh randomness. */
    check("second encap succeeds", syndrome_kem_encap(set, ct_b, kb, pk) == 0);
    check("fresh encap: ciphertext differs", memcmp(ct, ct_b, ct_len) != 0);
    check("fresh encap: shared secret differs", memcmp(k1, kb, ss_len) != 0);

    /* Implicit rejection 1: all-zero ciphertext (weight 0 != t). */
    memset(ct_bad, 0, ct_len);
    check("reject (zero ct): decap returns 0",
          syndrome_kem_decap(set, kr, ct_bad, sk) == 0);
    check("reject (zero ct): K != honest K", memcmp(kr, k1, ss_len) != 0);
    check("reject (zero ct): decap returns 0 again",
          syndrome_kem_decap(set, kr2, ct_bad, sk) == 0);
    check("reject (zero ct): implicit rejection deterministic in (sk, ct)",
          memcmp(kr, kr2, ss_len) == 0);

    /* Implicit rejection 2: non-canonical ct (a padding bit of the top byte). */
    memcpy(ct_bad, ct, ct_len);
    ct_bad[ct_len - 1] |= 0x80;
    check("reject (non-canonical ct): decap returns 0",
          syndrome_kem_decap(set, kr, ct_bad, sk) == 0);
    check("reject (non-canonical ct): K != honest K",
          memcmp(kr, k1, ss_len) != 0);

    /* Implicit rejection 3: a single-bit-flipped honest ciphertext. */
    memcpy(ct_bad, ct, ct_len);
    ct_bad[0] ^= 0x01;
    check("reject (bit-flip ct): decap returns 0",
          syndrome_kem_decap(set, kr, ct_bad, sk) == 0);
    check("reject (bit-flip ct): K != honest K", memcmp(kr, k1, ss_len) != 0);

    /* Wrong key. */
    check("second keypair succeeds", syndrome_kem_keypair(set, pk2, sk2) == 0);
    check("reject (wrong key): decap returns 0",
          syndrome_kem_decap(set, kr, ct, sk2) == 0);
    check("reject (wrong key): K != honest K", memcmp(kr, k1, ss_len) != 0);
}

int
main(void)
{
    int enabled = 0;
    syndrome_set_id s;

    printf("kem tests: FO transform over the public set-id API\n");

    for (s = 0; s < SYNDROME_SET_COUNT; s++) {
        if (!syndrome_set_enabled(s))
            continue;
        enabled++;
        printf(" set %d:\n", (int)s);
        test_set(s);
    }

    if (enabled == 0) {
        fprintf(stderr, "kem: no set enabled\n");
        return 1;
    }
    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
