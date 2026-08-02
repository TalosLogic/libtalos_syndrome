/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_argus.c - designated-opener (Argus) round-trip and property tests.
 *
 * Argus has no public sealing surface (the signer seals in-circuit), so the
 * end-to-end test drives the internal software twin syndrome_argus_seal_derand
 * (opener/argus.h) and the public syndrome_argus_open.  This exercises the
 * whole opener path -- decode, support extraction, K = H(support(e)) KDF, and
 * the OTP DEM -- without needing the voleith proof (DESIGN.md §6.2).  Properties
 * (docs/TESTING.md style):
 *
 *   - Correctness round-trip: open(seal(id)) == id, full-width and short id.
 *   - Determinism: sealing from the same seed yields the same tag.
 *   - Malformed syndrome (a set padding bit) -> EMALFORMED.
 *   - Corrupted / wrong-key syndrome -> EUNOPENABLE (no opened identity).
 *   - OTP has no integrity: tampering ct opens to a *different* identity with no
 *     error -- the integrity Argus relies on is the proof's, not the tag's.
 *   - Argument checks (length / sizing) -> EARGS.
 *
 * Reaches the internal DRBG (core.h), the KEM keygen derand seam (kem.h), and
 * the Argus seal seam (opener/argus.h); keygen+seal run off a fixed seed.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "talos_syndrome.h"

#include "argus.h"
#include "core.h"
#include "kem.h"

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

/* Deterministic keypair + tag from a fixed 48-byte seed value. */
static int
seal_from_seed(uint8_t seed_byte, uint8_t *pk, uint8_t *sk, uint8_t *tag,
               const uint8_t *id, size_t id_len)
{
    syndrome_drbg rng;
    uint8_t seed[48];
    int ret;

    memset(seed, seed_byte, sizeof(seed));
    syndrome_drbg_init(&rng, seed);
    if (syndrome_kem_keypair_derand(pk, sk, &rng) != 0) {
        syndrome_drbg_clear(&rng);
        return -1;
    }
    ret = syndrome_argus_seal_derand(tag, pk, id, id_len, &rng);
    syndrome_drbg_clear(&rng);
    return ret;
}

int
main(void)
{
    enum { TAG_MAX = SYNDROME_ARGUS_TAG_BYTES(SYNDROME_ARGUS_KEY_BYTES) };
    uint8_t pk[SYNDROME_PK_BYTES];
    uint8_t sk[SYNDROME_SK_BYTES];
    uint8_t pk2[SYNDROME_PK_BYTES];
    uint8_t sk2[SYNDROME_SK_BYTES];
    uint8_t tag[TAG_MAX];
    uint8_t tag2[TAG_MAX];
    uint8_t tag_bad[TAG_MAX];
    uint8_t id[SYNDROME_ARGUS_KEY_BYTES];
    uint8_t out[SYNDROME_ARGUS_KEY_BYTES];
    const size_t id_len = SYNDROME_ARGUS_KEY_BYTES;
    const size_t tag_len = SYNDROME_ARGUS_TAG_BYTES(SYNDROME_ARGUS_KEY_BYTES);
    size_t i;

    printf("argus tests: designated-opener seal/open round-trip\n");

    for (i = 0; i < sizeof(id); i++)
        id[i] = (uint8_t)(0xa0 ^ i);

    if (seal_from_seed(0x42, pk, sk, tag, id, id_len) != 0) {
        fprintf(stderr, "argus: keygen/seal FAILED\n");
        return 1;
    }

    /* Correctness round-trip, full-width identity. */
    memset(out, 0, sizeof(out));
    check("open returns OK", syndrome_argus_open_impl(out, id_len, tag, tag_len,
                                                      sk) == SYNDROME_ARGUS_OK);
    check("round-trip: opened identity == sealed identity",
          memcmp(out, id, id_len) == 0);

    /* Correctness round-trip, short identity (uses a prefix of the OTP pad). */
    {
        uint8_t tag_s[TAG_MAX];
        uint8_t out_s[SYNDROME_ARGUS_KEY_BYTES];
        const size_t short_len = 8;
        const size_t short_tag = SYNDROME_ARGUS_TAG_BYTES(short_len);

        check("short-id seal succeeds",
              seal_from_seed(0x07, pk2, sk2, tag_s, id, short_len) == 0);
        memset(out_s, 0, sizeof(out_s));
        check("short-id open returns OK",
              syndrome_argus_open_impl(out_s, short_len, tag_s, short_tag,
                                       sk2) == SYNDROME_ARGUS_OK);
        check("short-id round-trip matches", memcmp(out_s, id, short_len) == 0);
    }

    /* Determinism: same seed -> identical tag. */
    check("re-seal from same seed succeeds",
          seal_from_seed(0x42, pk2, sk2, tag2, id, id_len) == 0);
    check("determinism: tag reproducible from seed",
          memcmp(tag, tag2, tag_len) == 0);

    /* Malformed syndrome: a set padding bit in the top byte of s (s = tag + 1). */
    memcpy(tag_bad, tag, tag_len);
    tag_bad[1 + SYNDROME_CT_BYTES - 1] |= 0x80;
    check("malformed (padding bit): open returns EMALFORMED",
          syndrome_argus_open_impl(out, id_len, tag_bad, tag_len, sk) ==
              SYNDROME_ARGUS_EMALFORMED);

    /*
     * Zero syndrome: decodes to weight 0 != t, a guaranteed EUNOPENABLE.  The
     * constant-time tail must also leave identity_out masked to zero on failure
     * (not the caller's prior contents): pre-fill out with a sentinel and check
     * it is overwritten with zero.
     */
    memcpy(tag_bad, tag, tag_len);
    memset(tag_bad + 1, 0, SYNDROME_CT_BYTES);
    memset(out, 0x5a, sizeof(out));
    check("zero s: open returns EUNOPENABLE",
          syndrome_argus_open_impl(out, id_len, tag_bad, tag_len, sk) ==
              SYNDROME_ARGUS_EUNOPENABLE);
    {
        int zeroed = 1;

        for (i = 0; i < id_len; i++)
            if (out[i] != 0)
                zeroed = 0;
        check("zero s: identity_out masked to zero on failure", zeroed);
    }

    /*
     * Corrupted syndrome: a single flipped bit overwhelmingly fails to decode to
     * a weight-t error.  Assert robustly -- it must not recover the sealed
     * identity (either EUNOPENABLE, or the negligible case of opening to garbage).
     */
    memcpy(tag_bad, tag, tag_len);
    tag_bad[1] ^= 0x01;
    memset(out, 0, sizeof(out));
    {
        int r = syndrome_argus_open_impl(out, id_len, tag_bad, tag_len, sk);

        check("corrupted s: does not recover the sealed identity",
              r != SYNDROME_ARGUS_OK || memcmp(out, id, id_len) != 0);
    }

    /* Wrong opener key: the honest tag does not decode under a different sk. */
    check("second keypair/seal succeeds",
          seal_from_seed(0x99, pk2, sk2, tag2, id, id_len) == 0);
    check("wrong key: open returns EUNOPENABLE",
          syndrome_argus_open_impl(out, id_len, tag, tag_len, sk2) ==
              SYNDROME_ARGUS_EUNOPENABLE);

    /*
     * OTP carries no integrity: tampering the DEM ciphertext opens cleanly to a
     * *different* identity.  This is by design -- ciphertext integrity comes
     * from the enclosing voleith proof, not the tag (DESIGN.md §6.2, §8).
     */
    memcpy(tag_bad, tag, tag_len);
    tag_bad[1 + SYNDROME_CT_BYTES] ^= 0x01;
    memset(out, 0, sizeof(out));
    check("tampered ct: open still returns OK (OTP unauthenticated)",
          syndrome_argus_open_impl(out, id_len, tag_bad, tag_len, sk) ==
              SYNDROME_ARGUS_OK);
    check("tampered ct: opened identity differs from sealed",
          memcmp(out, id, id_len) != 0);

    /* Argument checks. */
    check("EARGS: identity_len == 0",
          syndrome_argus_open_impl(out, 0, tag, SYNDROME_CT_BYTES, sk) ==
              SYNDROME_ARGUS_EARGS);
    check("EARGS: identity_len > ID_MAX",
          syndrome_argus_open_impl(out, SYNDROME_ARGUS_ID_MAX_BYTES + 1, tag,
                                   tag_len + 1, sk) == SYNDROME_ARGUS_EARGS);
    check("EARGS: tag_len mismatch",
          syndrome_argus_open_impl(out, id_len, tag, tag_len - 1, sk) ==
              SYNDROME_ARGUS_EARGS);

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
