/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * syndrome.c - public dispatch layer.
 *
 * The public API (talos_syndrome.h) is parameterized by a syndrome_set_id.  Each
 * entry point looks up the per-set vtable (compiled into the sets/syn_* wrapper
 * TUs) and calls through it.  The set id is public, never secret, so selecting a
 * vtable by it is not a side channel.  keypair/encap draw system entropy, seed an
 * AES-CTR DRBG, and delegate to the set's derandomized seam; decap and
 * argus_open are deterministic and dispatch directly.  The DRBG and system RNG
 * are parameter-free (core/rng.c, shared).
 */
#include <stdint.h>
#include <string.h>

#include <ichor/hash.h>
#include <ichor/util.h>

#include "core.h"
#include "set_vtable.h"
#include "talos_syndrome.h"

const char *
syndrome_version_string(void)
{
/* Derived from the SYNDROME_VERSION_* macros so it cannot drift from them. */
#define SYNDROME_STR_(x) #x
#define SYNDROME_STR(x) SYNDROME_STR_(x)
    return "libtalos_syndrome " SYNDROME_STR(SYNDROME_VERSION_MAJOR) "." SYNDROME_STR(
        SYNDROME_VERSION_MINOR) "." SYNDROME_STR(SYNDROME_VERSION_PATCH);
#undef SYNDROME_STR
#undef SYNDROME_STR_
}

/*
 * The vtable table.  A set has a non-NULL entry only if its wrapper was
 * compiled into this build (CMake defines SYNDROME_BUILT_SYN_<set>=1 and adds
 * the wrapper source for every enabled + implemented set).  Omitted designated
 * initializers default to NULL, so a disabled or not-yet-implemented set reads
 * back as "not enabled".
 */
static const syndrome_set_vtable *const set_table[SYNDROME_SET_COUNT] = {
#ifdef SYNDROME_BUILT_SYN_128_2
    [SYNDROME_SET_128_2] = &syndrome_set_128_2,
#endif
#ifdef SYNDROME_BUILT_SYN_128_5
    [SYNDROME_SET_128_5] = &syndrome_set_128_5,
#endif
#ifdef SYNDROME_BUILT_SYN_256_2
    [SYNDROME_SET_256_2] = &syndrome_set_256_2,
#endif
#ifdef SYNDROME_BUILT_SYN_256_5
    [SYNDROME_SET_256_5] = &syndrome_set_256_5,
#endif
};

static const syndrome_set_vtable *
lookup(syndrome_set_id set)
{
    if ((unsigned)set >= (unsigned)SYNDROME_SET_COUNT)
        return NULL;
    return set_table[set];
}

int
syndrome_set_enabled(syndrome_set_id set)
{
    return lookup(set) != NULL;
}

size_t
syndrome_pk_bytes(syndrome_set_id set)
{
    const syndrome_set_vtable *v = lookup(set);

    return v ? v->pk_bytes : 0;
}

size_t
syndrome_sk_bytes(syndrome_set_id set)
{
    const syndrome_set_vtable *v = lookup(set);

    return v ? v->sk_bytes : 0;
}

size_t
syndrome_ct_bytes(syndrome_set_id set)
{
    const syndrome_set_vtable *v = lookup(set);

    return v ? v->ct_bytes : 0;
}

size_t
syndrome_ss_bytes(syndrome_set_id set)
{
    const syndrome_set_vtable *v = lookup(set);

    return v ? v->ss_bytes : 0;
}

size_t
syndrome_argus_id_max_bytes(syndrome_set_id set)
{
    const syndrome_set_vtable *v = lookup(set);

    return v ? v->argus_id_max_bytes : 0;
}

/* ========================================================================
 * Proteus seed API (DESIGN.md §5): deterministic key generation from a
 * 2*lambda-bit root seed.  The seed->DRBG expansion is set-agnostic (it reads
 * the set identity from the vtable's lambda/n0), so it lives here in the shared
 * dispatch TU rather than per set; it reuses the per-set kem_keypair_derand.
 * ======================================================================== */

/*
 * Frozen derivation domain and self-describing seed-blob header (§5):
 *   blob      = header(8) || root_seed(2*lambda)
 *   header    = lambda/8(1) || n0(1) || xof_id(1) || format(1) || reserved(4)=0
 *   drbg_seed = SHAKE256( SYNDROME_SEED_DOMAIN || header || root_seed )[48]
 * The whole header (including the zero reserved bytes) is bound into the
 * derivation, so any variation grinds a distinct key and cannot be replayed.
 */
static const uint8_t SYNDROME_SEED_DOMAIN[12] = {'T', 'A', 'L', 'O', 'S', 'P',
                                                 'r', 'o', 't', 'e', 'u', 's'};

#define SEED_HDR_LAMBDA 0
#define SEED_HDR_N0 1
#define SEED_HDR_XOF 2
#define SEED_HDR_FORMAT 3
#define SEED_HDR_RESERVED 4 /* 4 bytes, [4,8) */

size_t
syndrome_keyseed_bytes(syndrome_set_id set)
{
    const syndrome_set_vtable *v = lookup(set);

    return v ? v->ss_bytes : 0; /* raw root seed = 2*lambda = ss_bytes */
}

size_t
syndrome_seedblob_bytes(syndrome_set_id set)
{
    const syndrome_set_vtable *v = lookup(set);

    return v ? SYNDROME_SEED_HEADER_BYTES + v->ss_bytes : 0;
}

/* Write the 8-byte self-describing header for (set, xof) into hdr. */
static void
seed_build_header(const syndrome_set_vtable *v, syndrome_xof_id xof,
                  uint8_t hdr[SYNDROME_SEED_HEADER_BYTES])
{
    memset(hdr, 0, SYNDROME_SEED_HEADER_BYTES);
    hdr[SEED_HDR_LAMBDA] = (uint8_t)(v->lambda / 8u);
    hdr[SEED_HDR_N0] = (uint8_t)v->n0;
    hdr[SEED_HDR_XOF] = (uint8_t)xof;
    hdr[SEED_HDR_FORMAT] = SYNDROME_SEED_FORMAT_VERSION;
    /* reserved [4,8) already zero. */
}

/*
 * Validate a stored blob header against the requested set: identity must match,
 * xof/format must be known, reserved bytes must be zero.  On success returns 0
 * and writes the recorded XOF to *xof_out.  This is a boundary check on an
 * untrusted blob, so an explicit reject (not constant-time) is correct here.
 */
static int
seed_check_header(const syndrome_set_vtable *v,
                  const uint8_t hdr[SYNDROME_SEED_HEADER_BYTES],
                  syndrome_xof_id *xof_out)
{
    unsigned i;

    if (hdr[SEED_HDR_LAMBDA] != (uint8_t)(v->lambda / 8u))
        return -1;
    if (hdr[SEED_HDR_N0] != (uint8_t)v->n0)
        return -1;
    if (hdr[SEED_HDR_XOF] != SYNDROME_XOF_SHAKE256)
        return -1;
    if (hdr[SEED_HDR_FORMAT] != SYNDROME_SEED_FORMAT_VERSION)
        return -1;
    for (i = SEED_HDR_RESERVED; i < SYNDROME_SEED_HEADER_BYTES; i++)
        if (hdr[i] != 0)
            return -1;
    *xof_out = (syndrome_xof_id)hdr[SEED_HDR_XOF];
    return 0;
}

/*
 * Expand (header || root_seed) to the 48-byte CTR_DRBG material via the selected
 * XOF.  1.0.0 implements SHAKE256 only; the xof argument is already validated by
 * the callers, and the header binds xof_id so a future XOF is domain-separated.
 */
static void
seed_expand(syndrome_xof_id xof, const uint8_t hdr[SYNDROME_SEED_HEADER_BYTES],
            const uint8_t *seed, size_t seed_len, uint8_t drbg_seed[48])
{
    ichor_hash_ctx_t h;

    (void)xof; /* SHAKE256 only in 1.0.0 (validated by callers). */
    ichor_shake256_init(&h);
    ichor_shake256_absorb(&h, SYNDROME_SEED_DOMAIN,
                          sizeof(SYNDROME_SEED_DOMAIN));
    ichor_shake256_absorb(&h, hdr, SYNDROME_SEED_HEADER_BYTES);
    ichor_shake256_absorb(&h, seed, seed_len);
    ichor_shake256_squeeze(&h, drbg_seed, 48);
    ichor_hash_ctx_clear(&h);
}

/*
 * Core: expand the (already-built) header + raw seed, seed the DRBG, and run the
 * per-set derandomized keygen.  All expanded material is zeroed before return.
 */
static int
seed_keygen_core(const syndrome_set_vtable *v, syndrome_xof_id xof,
                 const uint8_t hdr[SYNDROME_SEED_HEADER_BYTES],
                 const uint8_t *seed, size_t seed_len, uint8_t *pk, uint8_t *sk)
{
    syndrome_drbg rng;
    uint8_t drbg_seed[48];
    int ret;

    seed_expand(xof, hdr, seed, seed_len, drbg_seed);
    syndrome_drbg_init(&rng, drbg_seed);
    ret = v->kem_keypair_derand(pk, sk, &rng);
    syndrome_drbg_clear(&rng);
    ichor_secure_zero(drbg_seed, sizeof(drbg_seed));
    return ret;
}

int
syndrome_kem_keypair(syndrome_set_id set, uint8_t *pk, uint8_t *sk)
{
    const syndrome_set_vtable *v = lookup(set);
    uint8_t hdr[SYNDROME_SEED_HEADER_BYTES];
    uint8_t seed[SYNDROME_MAX_KEYSEED_BYTES];
    size_t seed_len;
    int ret;

    if (v == NULL)
        return -1;
    if (pk == NULL || sk == NULL)
        return -1;
    /* Fresh key = draw a random root seed, run the seed core, discard the seed
     * (§5); no duplicated keygen path. */
    seed_len = v->ss_bytes;
    if (syndrome_randombytes_system(seed, seed_len) != 0)
        return -1;
    seed_build_header(v, SYNDROME_XOF_SHAKE256, hdr);
    ret =
        seed_keygen_core(v, SYNDROME_XOF_SHAKE256, hdr, seed, seed_len, pk, sk);
    if (ret != 0) {
        /* Leave no partial key material to the caller on a keygen failure,
         * matching the keep_seed / from_seed paths. */
        ichor_secure_zero(pk, v->pk_bytes);
        ichor_secure_zero(sk, v->sk_bytes);
    }
    ichor_secure_zero(seed, sizeof(seed));
    return ret;
}

int
syndrome_kem_keypair_keep_seed(syndrome_set_id set, syndrome_xof_id xof,
                               uint8_t *pk, uint8_t *sk, uint8_t *blob)
{
    const syndrome_set_vtable *v = lookup(set);
    size_t seed_len;
    int ret;

    if (v == NULL || xof != SYNDROME_XOF_SHAKE256)
        return -1;
    if (pk == NULL || sk == NULL || blob == NULL)
        return -1;
    seed_len = v->ss_bytes;

    /* Assemble the blob in place: header || fresh random root seed. */
    seed_build_header(v, xof, blob);
    if (syndrome_randombytes_system(blob + SYNDROME_SEED_HEADER_BYTES,
                                    seed_len) != 0) {
        ichor_secure_zero(blob, SYNDROME_SEED_HEADER_BYTES + seed_len);
        return -1;
    }

    ret = seed_keygen_core(v, xof, blob, blob + SYNDROME_SEED_HEADER_BYTES,
                           seed_len, pk, sk);
    if (ret != 0) {
        /* On failure the caller must observe no key material and no seed. */
        ichor_secure_zero(blob, SYNDROME_SEED_HEADER_BYTES + seed_len);
        ichor_secure_zero(pk, v->pk_bytes);
        ichor_secure_zero(sk, v->sk_bytes);
    }
    return ret;
}

int
syndrome_kem_keypair_from_seed(syndrome_set_id set, uint8_t *pk, uint8_t *sk,
                               const uint8_t *blob)
{
    const syndrome_set_vtable *v = lookup(set);
    syndrome_xof_id xof;
    int ret;

    if (v == NULL)
        return -1;
    if (pk == NULL || sk == NULL || blob == NULL)
        return -1;
    /* The blob is self-describing: validate its header against set and read the
     * XOF it was created under. */
    if (seed_check_header(v, blob, &xof) != 0)
        return -1;
    ret = seed_keygen_core(v, xof, blob, blob + SYNDROME_SEED_HEADER_BYTES,
                           v->ss_bytes, pk, sk);
    if (ret != 0) {
        ichor_secure_zero(pk, v->pk_bytes);
        ichor_secure_zero(sk, v->sk_bytes);
    }
    return ret;
}

int
syndrome_kem_pubkey_from_sk(syndrome_set_id set, uint8_t *pk, const uint8_t *sk)
{
    const syndrome_set_vtable *v = lookup(set);

    if (v == NULL)
        return -1;
    if (pk == NULL || sk == NULL)
        return -1;
    return v->kem_pubkey_from_sk(pk, sk);
}

int
syndrome_kem_encap(syndrome_set_id set, uint8_t *ct, uint8_t *k,
                   const uint8_t *pk)
{
    const syndrome_set_vtable *v = lookup(set);
    syndrome_drbg rng;
    uint8_t seed[48];
    int ret;

    if (v == NULL)
        return -1;
    if (ct == NULL || k == NULL || pk == NULL)
        return -1;
    if (syndrome_randombytes_system(seed, sizeof(seed)) != 0)
        return -1;
    syndrome_drbg_init(&rng, seed);
    ret = v->kem_encap_derand(ct, k, pk, &rng);
    syndrome_drbg_clear(&rng);
    ichor_secure_zero(seed, sizeof(seed));
    return ret;
}

int
syndrome_kem_decap(syndrome_set_id set, uint8_t *k, const uint8_t *ct,
                   const uint8_t *sk)
{
    const syndrome_set_vtable *v = lookup(set);

    if (v == NULL)
        return -1;
    if (k == NULL || ct == NULL || sk == NULL)
        return -1;
    return v->kem_decap(k, ct, sk);
}

int
syndrome_argus_open(syndrome_set_id set, uint8_t *identity_out,
                    size_t identity_len, const uint8_t *tag, size_t tag_len,
                    const uint8_t *sk, syndrome_argus_gate gate)
{
    const syndrome_set_vtable *v = lookup(set);

    /*
     * Fail-closed signature gate (talos_syndrome.h): opening an unverified tag
     * is a key-recovery oracle, so refuse anything but the explicit caller
     * attestation before the tag is touched.  A real runtime reject (not an
     * assert), so it holds under -DNDEBUG.
     */
    if (gate != SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED)
        return SYNDROME_ARGUS_EARGS;
    if (v == NULL)
        return SYNDROME_ARGUS_EARGS;
    return v->argus_open(identity_out, identity_len, tag, tag_len, sk);
}
