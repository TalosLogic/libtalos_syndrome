/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_seed.c - Proteus seed API (DESIGN.md §5; docs/SEED_KEY_API.md).
 *
 * Public, set-dispatched surface, so this is one shared binary iterating the
 * enabled sets (like test_kem), not a per-set force-include.  It exercises:
 *   - round-trip: from_seed(blob) reproduces byte-identical (pk, sk) that
 *     keep_seed emitted;
 *   - public-key recovery: pubkey_from_sk(sk) == pk;
 *   - determinism: from_seed on a fixed blob is reproducible;
 *   - self-describing rejection: a blob built for one set / XOF is rejected by
 *     from_seed under a different set, and an unknown xof / nonzero reserved
 *     byte is rejected;
 *   - malformed sk: an out-of-range H index makes pubkey_from_sk fail;
 *   - a pinned regression digest over (blob, pk, sk) for a fixed blob, freezing
 *     the derivation ABI (domain string, header, SHAKE256 expansion).
 *
 * The 8-byte blob header is a FROZEN public format
 *   lambda/8(1) || n0(1) || xof_id(1) || format(1) || reserved(4)=0
 * so the harness builds fixed blobs directly (which also tests that the
 * documented format is what from_seed accepts).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/hash.h>
#include <ichor/util.h>

#include "talos_syndrome.h"

/* Per-set identity for building a fixed blob header (the enum is public/fixed). */
typedef struct {
    syndrome_set_id set;
    uint8_t lambda_byte; /* lambda / 8 */
    uint8_t n0;
    const char *name;
} set_info;

static const set_info SETS[] = {
    {SYNDROME_SET_128_2, 16, 2, "128_2"},
    {SYNDROME_SET_128_5, 16, 5, "128_5"},
    {SYNDROME_SET_256_2, 32, 2, "256_2"},
    {SYNDROME_SET_256_5, 32, 5, "256_5"},
};
#define NSETS (sizeof(SETS) / sizeof(SETS[0]))

/*
 * Pinned SHA3-256 over (fixed blob, pk, sk) for the fixed-seed regression KAT,
 * one per set (same index order as SETS[]).  All-zero means "unpinned": the
 * harness prints the computed digest to paste in and does NOT fail on it
 * (round-trip / recovery / determinism are still hard-checked).
 */
static const uint8_t SEED_KAT_GOLDEN[NSETS][32] = {
    {0x68, 0x3f, 0xd1, 0x1e, 0x7a, 0xc6, 0x5f, 0xcb, 0xa2, 0x53, 0x07,
     0xa6, 0xfe, 0xdb, 0x25, 0x62, 0xe7, 0xb3, 0x8d, 0x94, 0x1b, 0x4b,
     0x9f, 0x15, 0x27, 0x16, 0x42, 0x8c, 0xa0, 0xeb, 0xb6, 0x70}, /* 128_2 */
    {0x78, 0x3b, 0xe1, 0xd9, 0xee, 0x85, 0x61, 0x01, 0x21, 0x22, 0x92,
     0x37, 0xe5, 0x48, 0x13, 0xdd, 0xab, 0xbe, 0x2a, 0x96, 0x08, 0xd8,
     0xd1, 0x08, 0x3c, 0x99, 0x59, 0x2a, 0xee, 0xd0, 0xc8, 0x4d}, /* 128_5 */
    {0x15, 0x95, 0xfa, 0xf5, 0x0b, 0xbc, 0xbf, 0xdb, 0xf7, 0xa6, 0xb2,
     0x2f, 0xe9, 0x20, 0x76, 0x7d, 0x61, 0x23, 0x69, 0xb6, 0xc3, 0x14,
     0xf3, 0x83, 0xd0, 0x58, 0x55, 0xe7, 0x13, 0x2b, 0x84, 0xd9}, /* 256_2 */
    {0x91, 0x4f, 0x59, 0x77, 0xc3, 0xbd, 0xbf, 0x59, 0x34, 0xf5, 0x73,
     0x05, 0x29, 0x75, 0x16, 0x10, 0x64, 0x5d, 0x9c, 0xa5, 0x0b, 0x2d,
     0xfd, 0x67, 0xba, 0xc9, 0xe4, 0xb2, 0x20, 0x0f, 0x0b, 0xac}, /* 256_5 */
};

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

/* Build a fixed blob: the frozen 8-byte header for (info, xof) + a fixed ramp
 * root seed of seed_len bytes. */
static void
build_blob(const set_info *info, uint8_t xof, uint8_t *blob, size_t seed_len)
{
    size_t i;

    memset(blob, 0, SYNDROME_SEED_HEADER_BYTES);
    blob[0] = info->lambda_byte;
    blob[1] = info->n0;
    blob[2] = xof;
    blob[3] = (uint8_t)SYNDROME_SEED_FORMAT_VERSION;
    /* reserved [4,8) stays zero */
    for (i = 0; i < seed_len; i++)
        blob[SYNDROME_SEED_HEADER_BYTES + i] = (uint8_t)i;
}

static void
run_set(const set_info *info, size_t gi)
{
    syndrome_set_id set = info->set;
    size_t pk_sz = syndrome_pk_bytes(set);
    size_t sk_sz = syndrome_sk_bytes(set);
    size_t seed_len = syndrome_keyseed_bytes(set);
    size_t blob_sz = syndrome_seedblob_bytes(set);

    uint8_t pk[SYNDROME_MAX_PK_BYTES], pk2[SYNDROME_MAX_PK_BYTES];
    uint8_t sk[SYNDROME_MAX_SK_BYTES], sk2[SYNDROME_MAX_SK_BYTES];
    uint8_t blob[SYNDROME_MAX_SEEDBLOB_BYTES];
    uint8_t blob_k[SYNDROME_MAX_SEEDBLOB_BYTES];
    ichor_hash_ctx_t h;
    uint8_t digest[32];
    char lbl[64];

    printf("seed: set %s (pk=%zu sk=%zu seed=%zu blob=%zu)\n", info->name,
           pk_sz, sk_sz, seed_len, blob_sz);

    /* Size sanity: blob = header + raw seed; raw seed = ss (2*lambda). */
    snprintf(lbl, sizeof lbl, "%s: blob = header + seed", info->name);
    check(lbl, blob_sz == SYNDROME_SEED_HEADER_BYTES + seed_len);
    snprintf(lbl, sizeof lbl, "%s: seed = ss_bytes", info->name);
    check(lbl, seed_len == syndrome_ss_bytes(set));

    /* --- Fixed-blob determinism + regression digest ---------------------- */
    build_blob(info, SYNDROME_XOF_SHAKE256, blob, seed_len);
    snprintf(lbl, sizeof lbl, "%s: from_seed(fixed) ok", info->name);
    check(lbl, syndrome_kem_keypair_from_seed(set, pk, sk, blob) == 0);

    snprintf(lbl, sizeof lbl, "%s: from_seed deterministic", info->name);
    check(lbl, syndrome_kem_keypair_from_seed(set, pk2, sk2, blob) == 0 &&
                   memcmp(pk, pk2, pk_sz) == 0 && memcmp(sk, sk2, sk_sz) == 0);

    ichor_sha3_256_init(&h);
    ichor_sha3_256_absorb(&h, blob, blob_sz);
    ichor_sha3_256_absorb(&h, pk, pk_sz);
    ichor_sha3_256_absorb(&h, sk, sk_sz);
    ichor_sha3_256_finalize(&h, digest);

    if (is_all_zero(SEED_KAT_GOLDEN[gi], 32)) {
        printf("  NOTE: SEED_KAT_GOLDEN[%zu] (%s) unpinned; paste to arm:", gi,
               info->name);
        print_c_bytes(digest, 32);
    } else {
        snprintf(lbl, sizeof lbl, "%s: regression digest", info->name);
        check(lbl, memcmp(digest, SEED_KAT_GOLDEN[gi], 32) == 0);
    }

    /* --- public-key recovery from the fixed-blob key --------------------- */
    snprintf(lbl, sizeof lbl, "%s: pubkey_from_sk == pk", info->name);
    check(lbl, syndrome_kem_pubkey_from_sk(set, pk2, sk) == 0 &&
                   memcmp(pk2, pk, pk_sz) == 0);

    /* --- round-trip through keep_seed (random) --------------------------- */
    snprintf(lbl, sizeof lbl, "%s: keep_seed ok", info->name);
    check(lbl, syndrome_kem_keypair_keep_seed(set, SYNDROME_XOF_SHAKE256, pk,
                                              sk, blob_k) == 0);
    snprintf(lbl, sizeof lbl, "%s: from_seed(keep_seed blob) round-trips",
             info->name);
    check(lbl, syndrome_kem_keypair_from_seed(set, pk2, sk2, blob_k) == 0 &&
                   memcmp(pk, pk2, pk_sz) == 0 && memcmp(sk, sk2, sk_sz) == 0);
    snprintf(lbl, sizeof lbl, "%s: pubkey_from_sk(keep_seed sk) == pk",
             info->name);
    check(lbl, syndrome_kem_pubkey_from_sk(set, pk2, sk) == 0 &&
                   memcmp(pk2, pk, pk_sz) == 0);

    /* --- negative: unknown XOF rejected on both create and restore ------- */
    snprintf(lbl, sizeof lbl, "%s: keep_seed rejects bad xof", info->name);
    check(lbl, syndrome_kem_keypair_keep_seed(set, (syndrome_xof_id)0x02, pk,
                                              sk, blob_k) != 0);
    build_blob(info, 0x02, blob, seed_len);
    snprintf(lbl, sizeof lbl, "%s: from_seed rejects bad xof", info->name);
    check(lbl, syndrome_kem_keypair_from_seed(set, pk, sk, blob) != 0);

    /* --- negative: nonzero reserved byte rejected ------------------------ */
    build_blob(info, SYNDROME_XOF_SHAKE256, blob, seed_len);
    blob[5] = 0x01; /* a reserved byte */
    snprintf(lbl, sizeof lbl, "%s: from_seed rejects nonzero reserved",
             info->name);
    check(lbl, syndrome_kem_keypair_from_seed(set, pk, sk, blob) != 0);

    /* --- negative: malformed sk (out-of-range H index) ------------------- *
     * Reuse the valid sk already in hand (from the keep_seed round-trip) and
     * corrupt a copy, so this costs no extra keygen. */
    memcpy(sk2, sk, sk_sz);
    sk2[0] = 0xff; /* H index 0 -> 0xffff >= p for every set */
    sk2[1] = 0xff;
    snprintf(lbl, sizeof lbl, "%s: pubkey_from_sk rejects malformed sk",
             info->name);
    check(lbl, syndrome_kem_pubkey_from_sk(set, pk2, sk2) != 0);

    ichor_secure_zero(sk, sizeof sk);
    ichor_secure_zero(sk2, sizeof sk2);
    ichor_secure_zero(blob, sizeof blob);
    ichor_secure_zero(blob_k, sizeof blob_k);
}

/*
 * Cross-set rejection: a blob built for set A must be rejected by from_seed
 * under a different set B (distinct lambda/n0 in the header).  Only runs for
 * pairs both enabled in this build.
 */
static void
run_cross(void)
{
    uint8_t pk[SYNDROME_MAX_PK_BYTES];
    uint8_t sk[SYNDROME_MAX_SK_BYTES];
    uint8_t blob[SYNDROME_MAX_SEEDBLOB_BYTES];
    char lbl[64];
    size_t a, b;

    for (a = 0; a < NSETS; a++) {
        if (!syndrome_set_enabled(SETS[a].set))
            continue;
        build_blob(&SETS[a], SYNDROME_XOF_SHAKE256, blob,
                   syndrome_keyseed_bytes(SETS[a].set));
        for (b = 0; b < NSETS; b++) {
            if (a == b || !syndrome_set_enabled(SETS[b].set))
                continue;
            snprintf(lbl, sizeof lbl, "cross: %s blob rejected by %s",
                     SETS[a].name, SETS[b].name);
            check(lbl, syndrome_kem_keypair_from_seed(SETS[b].set, pk, sk,
                                                      blob) != 0);
        }
    }
    ichor_secure_zero(sk, sizeof sk);
    ichor_secure_zero(blob, sizeof blob);
}

int
main(void)
{
    size_t i;

    printf("seed API: round-trip / recovery / determinism / rejection\n");

    for (i = 0; i < NSETS; i++) {
        if (!syndrome_set_enabled(SETS[i].set)) {
            printf("seed: set %s not built; skipped\n", SETS[i].name);
            continue;
        }
        run_set(&SETS[i], i);
    }
    run_cross();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
