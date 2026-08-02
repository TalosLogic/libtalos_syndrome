/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rng.c - deterministic random bit generator (DRBG).
 *
 * AES-256 CTR_DRBG without a derivation function (NIST SP 800-90A, Sec. 10.2.1),
 * the construction the NIST PQC KAT framework uses to expand a fixed seed into
 * reproducible test randomness.  Backs both production randomness and the
 * deterministic-seed KAT harness (NIST .req/.rsp format, docs/TESTING.md).
 *
 * The block cipher is ichor's constant-time AES; the counter increment is
 * branch-free, so the generator has no secret-dependent timing or control flow.
 * Sensitive state (Key, V, intermediate blocks) is secure-zeroed on the way out.
 *
 * This is a clean-room implementation from SP 800-90A; the reference rng.c
 * shipped with NIST PQC submissions is not copied from.
 */

/* getentropy(3) requires the BSD/POSIX.1-2008 feature set on glibc. */
#define _DEFAULT_SOURCE

#include <string.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h>
#endif

#include "core.h"

#include <ichor/aes.h>
#include <ichor/util.h>

/*
 * SP 800-90A reseed interval for AES-256 CTR_DRBG: the maximum number of
 * generate requests permitted between reseeds (2^48).  This DRBG is used as a
 * one-shot seed expander (instantiate -> a bounded number of generate calls ->
 * clear) with no reseed capability, so the interval is unreachable in normal
 * use.  The check is a fail-closed guard: if a context is ever reused in a
 * long-running loop it refuses to emit output past the bound rather than
 * silently exceeding the security limit.
 */
#define SYNDROME_DRBG_RESEED_INTERVAL (UINT64_C(1) << 48)

/*
 * Increment the 128-bit big-endian counter V by one, in constant time:
 * every byte is visited and the carry propagated with no early exit, so the
 * timing does not depend on V's value.
 */
static void
drbg_increment(uint8_t v[16])
{
    unsigned carry = 1;
    int j;

    for (j = 15; j >= 0; j--) {
        unsigned sum = (unsigned)v[j] + carry;
        v[j] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

/*
 * CTR_DRBG_Update (SP 800-90A): run three counter blocks under the current
 * Key, optionally XOR in 48 bytes of provided data, and split the result into
 * the new Key (32 bytes) and V (16 bytes).
 */
static void
drbg_update(syndrome_drbg *ctx, const uint8_t provided[48])
{
    uint8_t temp[48];
    ichor_aes_ctx_t aes;
    int i;

    ichor_aes_key_expand(&aes, ctx->key, 256);
    for (i = 0; i < 3; i++) {
        drbg_increment(ctx->v);
        ichor_aes_encrypt(&aes, temp + 16 * i, ctx->v);
    }
    if (provided != NULL)
        for (i = 0; i < 48; i++)
            temp[i] ^= provided[i];

    memcpy(ctx->key, temp, 32);
    memcpy(ctx->v, temp + 32, 16);

    ichor_aes_ctx_clear(&aes);
    ichor_secure_zero(temp, sizeof temp);
}

void
syndrome_drbg_init(syndrome_drbg *ctx, const uint8_t seed[48])
{
    memset(ctx->key, 0, sizeof ctx->key);
    memset(ctx->v, 0, sizeof ctx->v);
    drbg_update(ctx, seed);
    ctx->reseed_counter = 1;
}

int
syndrome_drbg_generate(syndrome_drbg *ctx, uint8_t *out, size_t len)
{
    uint8_t block[16];
    ichor_aes_ctx_t aes;
    size_t off, n;

    /*
     * SP 800-90A generate step 1: refuse (reseed required) once the request
     * count has reached the interval, before producing any output.  Unreachable
     * in the library's one-shot usage; a fail-closed guard against context reuse.
     */
    if (ctx->reseed_counter > SYNDROME_DRBG_RESEED_INTERVAL)
        return -1;

    /* Key is fixed across the request; only V advances per block. */
    ichor_aes_key_expand(&aes, ctx->key, 256);
    for (off = 0; off < len; off += n) {
        drbg_increment(ctx->v);
        ichor_aes_encrypt(&aes, block, ctx->v);
        n = len - off < 16 ? len - off : 16;
        memcpy(out + off, block, n);
    }
    ichor_aes_ctx_clear(&aes);
    ichor_secure_zero(block, sizeof block);

    /* Re-key so produced output cannot be reconstructed from later state. */
    drbg_update(ctx, NULL);
    ctx->reseed_counter++;
    return 0;
}

void
syndrome_drbg_clear(syndrome_drbg *ctx)
{
    ichor_secure_zero(ctx, sizeof *ctx);
}

int
syndrome_randombytes_system(uint8_t *buf, size_t len)
{
    size_t off, n;

    for (off = 0; off < len; off += n) {
        n = len - off < 256 ? len - off : 256;
        if (getentropy(buf + off, n) != 0)
            return -1;
    }
    return 0;
}

/*
 * Component KAT / SP 800-90A Sec. 11.3 health test (docs/TESTING.md): the
 * instantiate-plus-generate known-answer check for this DRBG.  AES-256
 * CTR_DRBG (no df) instantiated with entropy 0x00..0x2f and no personalization,
 * then 48 bytes generated, must reproduce the canonical first seed value shared
 * across the NIST PQC KAT request files.  This validates the whole DRBG
 * composition over ichor's AES.  Run by tests/test_rng.c.
 */
int
syndrome_rng_selftest(void)
{
    static const uint8_t expected[48] = {
        0x06, 0x15, 0x50, 0x23, 0x4d, 0x15, 0x8c, 0x5e, 0xc9, 0x55, 0x95, 0xfe,
        0x04, 0xef, 0x7a, 0x25, 0x76, 0x7f, 0x2e, 0x24, 0xcc, 0x2b, 0xc4, 0x79,
        0xd0, 0x9d, 0x86, 0xdc, 0x9a, 0xbc, 0xfd, 0xe7, 0x05, 0x6a, 0x8c, 0x26,
        0x6f, 0x9e, 0xf9, 0x7e, 0xd0, 0x85, 0x41, 0xdb, 0xd2, 0xe1, 0xff, 0xa1};
    uint8_t seed[48], out[48];
    syndrome_drbg ctx;
    int i, rc;

    for (i = 0; i < 48; i++)
        seed[i] = (uint8_t)i;

    syndrome_drbg_init(&ctx, seed);
    rc = syndrome_drbg_generate(&ctx, out, sizeof out);
    syndrome_drbg_clear(&ctx);

    if (rc == 0)
        rc = ichor_const_memcmp(out, expected, sizeof out) == 0 ? 0 : -1;
    ichor_secure_zero(out, sizeof out);
    return rc;
}
