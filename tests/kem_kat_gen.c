/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kem_kat_gen.c - NIST-format .req/.rsp KAT vector emitter for the KEM.
 *
 * A tool (not a pass/fail unit test): writes <prefix>.req and <prefix>.rsp in
 * the NIST PQCgenKAT_kem format, driving the derandomized seam from the same
 * fixed top seed and case count as the regression gate (kem_kat_common.h).  It
 * also recomputes the SHA3-256 over the emitted (seed, pk, sk, ct, ss) stream
 * and cross-checks it against the pinned SYNDROME_KAT_GOLDEN, so the files and
 * the gate are provably the same vectors (returns non-zero on any drift or
 * round-trip failure).
 *
 * Usage: kem_kat_gen [prefix]      (default prefix "kem_kat")
 *   writes prefix.req and prefix.rsp into the current working directory.
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

/* NIST convention: uppercase hex, "label = <hex>\n". */
static void
fprint_bstr(FILE *f, const char *label, const uint8_t *p, size_t n)
{
    size_t i;

    fprintf(f, "%s", label);
    for (i = 0; i < n; i++)
        fprintf(f, "%02X", p[i]);
    fprintf(f, "\n");
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

int
main(int argc, char **argv)
{
    const char *prefix = (argc > 1) ? argv[1] : "kem_kat";
    char reqpath[256];
    char rsppath[256];
    FILE *req;
    FILE *rsp;
    syndrome_drbg top;
    ichor_hash_ctx_t acc;
    uint8_t digest[32];
    int rt_ok = 1;
    int i;

    snprintf(reqpath, sizeof(reqpath), "%s.req", prefix);
    snprintf(rsppath, sizeof(rsppath), "%s.rsp", prefix);

    req = fopen(reqpath, "w");
    if (req == NULL) {
        fprintf(stderr, "kem_kat_gen: cannot open %s\n", reqpath);
        return 1;
    }
    rsp = fopen(rsppath, "w");
    if (rsp == NULL) {
        fprintf(stderr, "kem_kat_gen: cannot open %s\n", rsppath);
        fclose(req);
        return 1;
    }

    fprintf(rsp, "# libtalos_syndrome KEM (lambda=%d, p=%d, v=%d, t=%d)\n\n",
            SYNDROME_LAMBDA, SYNDROME_P, SYNDROME_V, SYNDROME_T);

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

        /* .req: count + seed only (pk/sk/ct/ss left blank). */
        fprintf(req, "count = %d\n", i);
        fprint_bstr(req, "seed = ", seed, sizeof(seed));
        fprintf(req, "pk =\nsk =\nct =\nss =\n\n");

        /* .rsp: full vectors. */
        fprintf(rsp, "count = %d\n", i);
        fprint_bstr(rsp, "seed = ", seed, sizeof(seed));
        fprint_bstr(rsp, "pk = ", pk, sizeof(pk));
        fprint_bstr(rsp, "sk = ", sk, sizeof(sk));
        fprint_bstr(rsp, "ct = ", ct, sizeof(ct));
        fprint_bstr(rsp, "ss = ", ss, sizeof(ss));
        fprintf(rsp, "\n");

        /* Same digest stream as test_kem_kat.c, for the cross-check below. */
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
    fclose(req);
    fclose(rsp);

    printf("kem_kat_gen: wrote %s and %s (%d cases)\n", reqpath, rsppath,
           SYNDROME_KAT_CASES);

    if (!rt_ok) {
        fprintf(stderr, "kem_kat_gen: FAIL - a case did not round-trip\n");
        return 1;
    }
    if (is_all_zero(SYNDROME_KAT_GOLDEN, sizeof(SYNDROME_KAT_GOLDEN))) {
        printf("  SYNDROME_KAT_GOLDEN is unpinned; emitted-vector digest not "
               "cross-checked.\n");
    } else if (memcmp(digest, SYNDROME_KAT_GOLDEN, sizeof(digest)) != 0) {
        fprintf(stderr, "kem_kat_gen: FAIL - emitted-vector digest != pinned "
                        "SYNDROME_KAT_GOLDEN (drift from test_kem_kat)\n");
        return 1;
    } else {
        printf("  digest matches pinned SYNDROME_KAT_GOLDEN: consistent with "
               "test_kem_kat.\n");
    }

    return 0;
}
