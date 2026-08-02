/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_argus_kat.c - deterministic KAT and round-trip harness for the Argus
 * designated-opener seal/open path.
 *
 * Drives the internal seal twin (syndrome_argus_seal_derand) and the public
 * opener (syndrome_argus_open) from a fixed top-level seed, in the style of the
 * KEM KAT (test_kem_kat.c): one per-case DRBG feeds keygen then seal, so the
 * whole keygen/seal/open sequence is reproducible.  Argus has no external KAT
 * vector, so we generate our own regression fingerprint: a SHA3-256 over
 * (seed, pk, sk, id_len, id, tag, opened) across all cases.  Because the seal
 * framing (packed indices, DS-IV, AES-DM/Grostl-256 extractor, OTP CTR
 * extension) is the byte-exact contract the voleith in-circuit gadget will be
 * built to reproduce, this digest is what pins that contract (DESIGN.md §6.1/§6.2).
 *
 * Each case cycles the identity length through SYNDROME_ARGUS_KAT_IDLENS so the
 * fingerprint covers the short, full-width, and CTR-extended OTP pad regimes.
 *
 * Three checks (matching the KEM KAT):
 *   - round-trip: open(seal(id)) == id and status OK, every case;
 *   - determinism: re-running the whole sweep yields an identical digest;
 *   - regression: the digest equals the pinned SYNDROME_ARGUS_KAT_GOLDEN.
 *     Until pinned (the all-zero placeholder) the harness prints the computed
 *     digest so it can be captured from a trusted run and pasted in; it does
 *     NOT fail on the placeholder, since round-trip and determinism already
 *     hard-assert.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/hash.h>
#include <ichor/util.h>

#include "talos_syndrome.h"

#include "argus.h"
#include "argus_kat_common.h"
#include "core.h"
#include "kem.h"

/* Tag and identity buffers are sized to the widest swept identity. */
#define ARGUS_KAT_TAG_MAX SYNDROME_ARGUS_TAG_BYTES(SYNDROME_ARGUS_ID_MAX_BYTES)

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

    for (i = 0; i < n; i++)
        printf("%s0x%02x,", (i % 8 == 0) ? "\n        " : " ", p[i]);
    printf("\n");
}

/*
 * Run the full deterministic sweep, accumulating the regression digest.
 * Returns 1 if every case sealed and round-tripped, else 0.
 */
static int
run_kat(uint8_t digest[32])
{
    syndrome_drbg top;
    ichor_hash_ctx_t acc;
    int rt_ok = 1;
    int i;

    syndrome_drbg_init(&top, SYNDROME_ARGUS_KAT_TOPSEED);
    ichor_sha3_256_init(&acc);

    for (i = 0; i < SYNDROME_ARGUS_KAT_CASES; i++) {
        syndrome_drbg rng;
        uint8_t seed[48];
        uint8_t pk[SYNDROME_PK_BYTES];
        uint8_t sk[SYNDROME_SK_BYTES];
        uint8_t id[SYNDROME_ARGUS_ID_MAX_BYTES];
        uint8_t out[SYNDROME_ARGUS_ID_MAX_BYTES];
        uint8_t tag[ARGUS_KAT_TAG_MAX];
        uint8_t len_byte;
        size_t id_len = SYNDROME_ARGUS_KAT_IDLENS[i % 3];
        size_t tag_len = SYNDROME_ARGUS_TAG_BYTES(id_len);
        size_t j;

        if (syndrome_drbg_generate(&top, seed, sizeof(seed)) != 0)
            rt_ok = 0;
        syndrome_drbg_init(&rng, seed);

        /* Deterministic identity that varies per case and position. */
        for (j = 0; j < id_len; j++)
            id[j] = (uint8_t)((i * 31 + (int)j) & 0xff);

        if (syndrome_kem_keypair_derand(pk, sk, &rng) != 0)
            rt_ok = 0;
        if (syndrome_argus_seal_derand(tag, pk, id, id_len, &rng) != 0)
            rt_ok = 0;

        memset(out, 0, sizeof(out));
        if (syndrome_argus_open_impl(out, id_len, tag, tag_len, sk) !=
            SYNDROME_ARGUS_OK)
            rt_ok = 0;
        if (memcmp(out, id, id_len) != 0)
            rt_ok = 0;

        len_byte = (uint8_t)id_len;
        ichor_sha3_256_absorb(&acc, seed, sizeof(seed));
        ichor_sha3_256_absorb(&acc, pk, sizeof(pk));
        ichor_sha3_256_absorb(&acc, sk, sizeof(sk));
        ichor_sha3_256_absorb(&acc, &len_byte, 1);
        ichor_sha3_256_absorb(&acc, id, id_len);
        ichor_sha3_256_absorb(&acc, tag, tag_len);
        ichor_sha3_256_absorb(&acc, out, id_len);

        syndrome_drbg_clear(&rng);
        ichor_secure_zero(sk, sizeof(sk));
        ichor_secure_zero(id, sizeof(id));
        ichor_secure_zero(out, sizeof(out));
    }

    ichor_sha3_256_finalize(&acc, digest);
    syndrome_drbg_clear(&top);
    return rt_ok;
}

/*
 * Negative KAT for the prim_id gate (AT.GATE): seal one valid tag, then flip the
 * leading selector byte to a non-default value and assert the open fails closed
 * with EUNSUPPORTED, before any H-dependent work.  Covers both an unregistered
 * id (0xFF) and a registered-but-not-compiled id (0x03, Hirose reserved).
 * Neither equals a shipped default (0x01 @ lambda128, 0x02 @ lambda256), so both
 * are non-default at every set this build can carry.
 */
static int
run_primid_reject(void)
{
    syndrome_drbg rng;
    uint8_t pk[SYNDROME_PK_BYTES];
    uint8_t sk[SYNDROME_SK_BYTES];
    uint8_t id[SYNDROME_ARGUS_KEY_BYTES];
    uint8_t out[SYNDROME_ARGUS_KEY_BYTES];
    uint8_t tag[ARGUS_KAT_TAG_MAX];
    const size_t id_len = SYNDROME_ARGUS_KEY_BYTES;
    const size_t tag_len = SYNDROME_ARGUS_TAG_BYTES(id_len);
    static const uint8_t bad_ids[2] = {0xffu, 0x03u};
    int ok = 1;
    size_t k;

    syndrome_drbg_init(&rng, SYNDROME_ARGUS_KAT_TOPSEED);
    memset(id, 0xa5, sizeof(id));
    if (syndrome_kem_keypair_derand(pk, sk, &rng) != 0 ||
        syndrome_argus_seal_derand(tag, pk, id, id_len, &rng) != 0)
        ok = 0;

    /* Sanity: the default-prim_id tag opens (guards against a broken fixture). */
    memset(out, 0, sizeof(out));
    if (syndrome_argus_open_impl(out, id_len, tag, tag_len, sk) !=
        SYNDROME_ARGUS_OK)
        ok = 0;

    for (k = 0; k < sizeof(bad_ids); k++) {
        uint8_t saved = tag[0];

        tag[0] = bad_ids[k];
        memset(out, 0, sizeof(out));
        if (syndrome_argus_open_impl(out, id_len, tag, tag_len, sk) !=
            SYNDROME_ARGUS_EUNSUPPORTED)
            ok = 0;
        tag[0] = saved;
    }

    syndrome_drbg_clear(&rng);
    ichor_secure_zero(sk, sizeof(sk));
    ichor_secure_zero(id, sizeof(id));
    ichor_secure_zero(out, sizeof(out));
    return ok;
}

int
main(void)
{
    uint8_t d1[32];
    uint8_t d2[32];

    printf("argus KAT: deterministic seal/open round-trip + regression digest "
           "(%d cases)\n",
           SYNDROME_ARGUS_KAT_CASES);

    check("round-trip: open(seal(id)) == id for every case", run_kat(d1) == 1);
    check("determinism: identical digest across runs",
          run_kat(d2) == 1 && memcmp(d1, d2, sizeof(d1)) == 0);
    check("prim_id gate: non-default selector -> EUNSUPPORTED",
          run_primid_reject() == 1);

    if (is_all_zero(SYNDROME_ARGUS_KAT_GOLDEN,
                    sizeof(SYNDROME_ARGUS_KAT_GOLDEN))) {
        printf("  NOTE: SYNDROME_ARGUS_KAT_GOLDEN is unpinned. After a trusted "
               "run,\n"
               "  paste the body below into argus_kat_common.h to arm the "
               "gate:");
        print_c_bytes(d1, sizeof(d1));
        printf(
            "  (round-trip and determinism are still hard-checked above.)\n");
    } else {
        check("regression: digest matches pinned SYNDROME_ARGUS_KAT_GOLDEN",
              memcmp(d1, SYNDROME_ARGUS_KAT_GOLDEN, sizeof(d1)) == 0);
    }

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
