/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_null_args.c - NULL-buffer argument validation at the public KEM / seed
 * API boundary (talos_syndrome.h).
 *
 * Every public entry point must reject a NULL buffer with a negative return
 * rather than dereferencing it.  (Argus validates its own pointers and is
 * covered by test_argus / test_argus_gate.)  The checks are set-independent, so
 * this runs against the first enabled set, over the public set-id API only; no
 * keygen runs because every call short-circuits on the NULL argument.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

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

/* Non-NULL scratch buffers sized to the ceilings; never actually written (each
 * call returns before touching them). */
static uint8_t pk[SYNDROME_MAX_PK_BYTES];
static uint8_t sk[SYNDROME_MAX_SK_BYTES];
static uint8_t ct[SYNDROME_MAX_CT_BYTES];
static uint8_t ss[SYNDROME_MAX_SS_BYTES];
static uint8_t blob[SYNDROME_MAX_SEEDBLOB_BYTES];

int
main(void)
{
    syndrome_set_id set = SYNDROME_SET_COUNT;
    int i;

    printf("null-arg validation: public KEM / seed API rejects NULL buffers\n");

    for (i = 0; i < SYNDROME_SET_COUNT; i++)
        if (syndrome_set_enabled((syndrome_set_id)i)) {
            set = (syndrome_set_id)i;
            break;
        }
    if (set == SYNDROME_SET_COUNT) {
        fprintf(stderr, "no parameter set enabled\n");
        return 1;
    }

    check("keypair NULL pk", syndrome_kem_keypair(set, NULL, sk) < 0);
    check("keypair NULL sk", syndrome_kem_keypair(set, pk, NULL) < 0);

    check("encap NULL ct", syndrome_kem_encap(set, NULL, ss, pk) < 0);
    check("encap NULL k", syndrome_kem_encap(set, ct, NULL, pk) < 0);
    check("encap NULL pk", syndrome_kem_encap(set, ct, ss, NULL) < 0);

    check("decap NULL k", syndrome_kem_decap(set, NULL, ct, sk) < 0);
    check("decap NULL ct", syndrome_kem_decap(set, ss, NULL, sk) < 0);
    check("decap NULL sk", syndrome_kem_decap(set, ss, ct, NULL) < 0);

    check("keep_seed NULL pk",
          syndrome_kem_keypair_keep_seed(set, SYNDROME_XOF_SHAKE256, NULL, sk,
                                         blob) < 0);
    check("keep_seed NULL sk",
          syndrome_kem_keypair_keep_seed(set, SYNDROME_XOF_SHAKE256, pk, NULL,
                                         blob) < 0);
    check("keep_seed NULL blob",
          syndrome_kem_keypair_keep_seed(set, SYNDROME_XOF_SHAKE256, pk, sk,
                                         NULL) < 0);

    check("from_seed NULL pk",
          syndrome_kem_keypair_from_seed(set, NULL, sk, blob) < 0);
    check("from_seed NULL sk",
          syndrome_kem_keypair_from_seed(set, pk, NULL, blob) < 0);
    check("from_seed NULL blob",
          syndrome_kem_keypair_from_seed(set, pk, sk, NULL) < 0);

    check("pubkey_from_sk NULL pk",
          syndrome_kem_pubkey_from_sk(set, NULL, sk) < 0);
    check("pubkey_from_sk NULL sk",
          syndrome_kem_pubkey_from_sk(set, pk, NULL) < 0);

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
