/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_argus_gate.c - the fail-closed signature-verification gate on the public
 * syndrome_argus_open dispatch (talos_syndrome.h).
 *
 * Opening an unverified tag returns an unauthenticated identity (the OTP DEM is
 * malleable and open cannot detect a forged ct), so the public entrypoint refuses
 * any call that does not explicitly attest signature verification.  The gate lives in the dispatch layer; the per-set open impl is
 * exercised separately by test_argus / test_argus_kat.  Here we assert only the
 * gate, over the public set-id API, with zeroed buffers of the correct per-set
 * sizes (the gate is checked before the tag is read, so buffer contents are
 * irrelevant to the rejection).
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

int
main(void)
{
    static const syndrome_set_id sets[] = {
        SYNDROME_SET_128_2, SYNDROME_SET_128_5, SYNDROME_SET_256_2,
        SYNDROME_SET_256_5, SYNDROME_SET_128_3, SYNDROME_SET_128_4,
        SYNDROME_SET_192_2, SYNDROME_SET_192_3, SYNDROME_SET_192_4,
        SYNDROME_SET_192_5, SYNDROME_SET_256_3, SYNDROME_SET_256_4};
    const size_t nsets = sizeof sets / sizeof sets[0];
    size_t si;

    printf("argus gate: fail-closed signature-verification gate\n");

    for (si = 0; si < nsets; si++) {
        syndrome_set_id set = sets[si];
        uint8_t sk[SYNDROME_MAX_SK_BYTES];
        uint8_t out[SYNDROME_MAX_ARGUS_ID_MAX_BYTES];
        uint8_t
            tag[SYNDROME_MAX_ARGUS_TAG_BYTES(SYNDROME_MAX_ARGUS_ID_MAX_BYTES)];
        size_t id_len, tag_len;
        char name[72];

        if (!syndrome_set_enabled(set))
            continue;

        id_len = syndrome_argus_id_max_bytes(set);
        tag_len = 1 + syndrome_ct_bytes(set) + id_len; /* prim_id || s || ct */
        memset(sk, 0, sizeof sk);
        memset(out, 0, sizeof out);
        memset(tag, 0, sizeof tag);

        /* UNVERIFIED (the default 0) fails closed, before the tag is read. */
        snprintf(name, sizeof name, "set %d: UNVERIFIED rejected", (int)set);
        check(name, syndrome_argus_open(set, out, id_len, tag, tag_len, sk,
                                        SYNDROME_ARGUS_TAG_UNVERIFIED) ==
                        SYNDROME_ARGUS_EARGS);

        /* A stray nonzero value that is not the magic also fails closed. */
        snprintf(name, sizeof name, "set %d: wrong gate value rejected",
                 (int)set);
        check(name, syndrome_argus_open(set, out, id_len, tag, tag_len, sk,
                                        (syndrome_argus_gate)1) ==
                        SYNDROME_ARGUS_EARGS);

        /*
         * VERIFIED passes the gate and reaches real processing: a zeroed sk/tag
         * is well formed (canonical zero syndrome) but decodes to weight 0 != t,
         * so the open returns EUNOPENABLE, NOT the gate's EARGS.
         */
        snprintf(name, sizeof name, "set %d: VERIFIED passes the gate",
                 (int)set);
        check(name,
              syndrome_argus_open(set, out, id_len, tag, tag_len, sk,
                                  SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED) !=
                  SYNDROME_ARGUS_EARGS);

        /*
         * The gate does not bypass normal argument validation: a wrong tag_len
         * with a VERIFIED gate still yields EARGS.
         */
        snprintf(name, sizeof name, "set %d: VERIFIED + bad tag_len -> EARGS",
                 (int)set);
        check(name,
              syndrome_argus_open(set, out, id_len, tag, tag_len - 1, sk,
                                  SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED) ==
                  SYNDROME_ARGUS_EARGS);
    }

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
