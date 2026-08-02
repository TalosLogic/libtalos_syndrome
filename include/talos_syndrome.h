/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * talos_syndrome.h - public API for libtalos_syndrome.
 *
 * QC-MDPC Niederreiter post-quantum KEM (ePrint 2025/1043) with a
 * designated-opener (Argus) facility.  This is the only header consumers
 * include; everything under core/, code/, decoder/, pke/, kem/, and opener/
 * is internal.
 *
 * Two API families live here:
 *   - the general-purpose KEM (NIST SP 800-227 shape): syndrome_kem_*
 *   - the designated-opener facility built on decap: syndrome_argus_*
 *
 * Error convention (matches the house style): functions return 0 on success
 * and a negative value on failure.  The KEM never exposes a decode-failure
 * oracle; decap performs constant-time implicit rejection.
 */
#ifndef TALOS_SYNDROME_H
#define TALOS_SYNDROME_H

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
#define SYNDROME_BEGIN_DECLS extern "C" {
#define SYNDROME_END_DECLS }
#else
#define SYNDROME_BEGIN_DECLS
#define SYNDROME_END_DECLS
#endif

SYNDROME_BEGIN_DECLS

/*
 * Parameter-set selection (Long-Term sets only; the Ephemeral 2^-64 sets from
 * the paper are deliberately not exposed).  A single build carries a
 * caller-selected subset of the (lambda, n0) sets (liboqs-style; see
 * SYNDROME_MINIMAL_BUILD in the top-level CMakeLists.txt).  Every public entry
 * point takes a syndrome_set_id first argument selecting the set; the id is
 * public, never secret, so dispatching on it is not a side channel.
 *
 * Per-set sizes are queried at runtime (the syndrome_*_bytes accessors below).
 * Callers that need compile-time fixed stack buffers use the SYNDROME_MAX_*
 * ceilings, which bound every set the library can carry.
 */
typedef enum {
    SYNDROME_SET_128_2 = 0, /* lambda 128, n0 2 (smallest public key) */
    SYNDROME_SET_128_5,     /* lambda 128, n0 5 (cheapest circuit)     */
    SYNDROME_SET_256_2,     /* lambda 256, n0 2                        */
    SYNDROME_SET_256_5,     /* lambda 256, n0 5                        */
    SYNDROME_SET_COUNT
} syndrome_set_id;

/*
 * Compile-time size ceilings over ALL sets the library can carry, for callers
 * that size fixed stack buffers.  A minimal build (fewer sets) never exceeds
 * these, so a buffer sized by SYNDROME_MAX_* is always large enough.  Governing
 * set noted per line (n0=5 sizes from the paper Long-Term table).
 */
#define SYNDROME_MAX_PK_BYTES 12368 /* (n0-1)*ceil(p/8), max @ SYN_256_5 */
#define SYNDROME_MAX_CT_BYTES 5432  /* ceil(p/8),        max @ SYN_256_2 */
#define SYNDROME_MAX_SK_BYTES 1778  /* n0*v*2 + 2*ss,    max @ SYN_256_5 */
#define SYNDROME_MAX_SS_BYTES 64    /* 2*lambda/8,       max @ lambda256 */
#define SYNDROME_MAX_ARGUS_ID_MAX_BYTES 96 /* 3*lambda/8, max @ lambda256 */
#define SYNDROME_MAX_ARGUS_TAG_BYTES(id_len)                                   \
    (1 + SYNDROME_MAX_CT_BYTES + (size_t)(id_len))

/*
 * Set availability + per-set sizes (runtime).  syndrome_set_enabled returns 1
 * if this build carries the set, else 0.  The size accessors return 0 for a
 * disabled or out-of-range set.
 */
int syndrome_set_enabled(syndrome_set_id set);
size_t syndrome_pk_bytes(syndrome_set_id set);
size_t syndrome_sk_bytes(syndrome_set_id set);
size_t syndrome_ct_bytes(syndrome_set_id set);
size_t syndrome_ss_bytes(syndrome_set_id set);
size_t syndrome_argus_id_max_bytes(syndrome_set_id set);

/*
 * General KEM (NIST SP 800-227 shape).  Buffers are sized per the set: pk is
 * syndrome_pk_bytes(set), sk is syndrome_sk_bytes(set), ct is
 * syndrome_ct_bytes(set), k is syndrome_ss_bytes(set) (or the SYNDROME_MAX_*
 * ceilings).  Return 0 on success, negative on failure (including an unknown or
 * disabled set, or a NULL buffer argument).
 *
 * The (M, s) byte layout inside pk/ct is the ONLY contract shared with
 * libtalos_voleith and is FROZEN: see docs/DESIGN.md §7 (circulant blocks packed
 * little-endian, LSB-first, canonical zero padding) and tests/test_wire.c.  The
 * secret-key layout is private (H | sigma | hpk; DESIGN.md §4.2/§4.6).
 */
int syndrome_kem_keypair(syndrome_set_id set, uint8_t *pk, uint8_t *sk);
int syndrome_kem_encap(syndrome_set_id set, uint8_t *ct, uint8_t *k,
                       const uint8_t *pk);
int syndrome_kem_decap(syndrome_set_id set, uint8_t *k, const uint8_t *ct,
                       const uint8_t *sk);

/*
 * Seed-based key management (Proteus seed API; DESIGN.md §5).
 *
 * A private key is a deterministic function of a 2*lambda-bit root seed, and the
 * public key is a deterministic function of the private key.  These entry points
 * expose both facts: an application can persist a small seed instead of the full
 * sk/pk and rebuild them, and can recover pk from sk alone.
 *
 * The seed is as sensitive as sk: these paths are constant-time in the seed and
 * zeroize on every path.  The persisted form is a SELF-DESCRIBING blob
 * (syndrome_seedblob_bytes): an 8-byte header
 *   lambda/8(1) || n0(1) || xof_id(1) || format(1) || reserved(4, zero)
 * followed by the 2*lambda-bit raw seed.  The library builds and validates the
 * header from the (set, xof) you pass, so a lambda-128 blob cannot reconstruct
 * as lambda-256, an n0=2 blob cannot reconstruct as n0=5, and a key derived
 * under one XOF cannot reconstruct under another.
 *
 * The seed-expansion XOF is an axis ORTHOGONAL to the (lambda, n0) set.  1.0.0
 * ships SYNDROME_XOF_SHAKE256 only; the xof_id byte is present-and-fixed in the
 * derivation domain, so a future GF(2^8)-native XOF (for in-circuit
 * key-derivation proofs) is an additive new xof_id value that never reinterprets
 * an existing key.
 *
 * FROZEN ABI: the derivation pipeline (domain string, header, SHAKE256
 * expansion, CTR_DRBG, keygen consumption) is a compatibility contract once
 * 1.0.0 ships -- any change silently invalidates every stored seed.
 * SYNDROME_SEED_FORMAT_VERSION makes such a change detectable at load.
 */
typedef enum {
    SYNDROME_XOF_SHAKE256 = 0x01 /* the only XOF in 1.0.0 */
} syndrome_xof_id;

#define SYNDROME_SEED_FORMAT_VERSION 1
#define SYNDROME_SEED_HEADER_BYTES 8

/* Ceilings over all sets, for fixed stack buffers (raw seed = 2*lambda). */
#define SYNDROME_MAX_KEYSEED_BYTES                                             \
    SYNDROME_MAX_SS_BYTES /* 2*lambda/8, max 64 */
#define SYNDROME_MAX_SEEDBLOB_BYTES                                            \
    (SYNDROME_SEED_HEADER_BYTES + SYNDROME_MAX_KEYSEED_BYTES) /* 8 + 64 = 72 */

/* Runtime per-set sizes: raw seed (2*lambda) and the stored blob (header+seed). */
size_t syndrome_keyseed_bytes(syndrome_set_id set);
size_t syndrome_seedblob_bytes(syndrome_set_id set);

/*
 * Fresh keypair, additionally returning the persistable seed blob (self-
 * describing, syndrome_seedblob_bytes).  xof selects the seed-expansion XOF
 * (SYNDROME_XOF_SHAKE256 in 1.0.0).  Returns 0 on success, negative on failure.
 * An unknown/disabled set, unsupported xof, or NULL buffer is rejected before
 * anything is written (buffers untouched); a later entropy/keygen failure
 * zeroizes pk, sk,
 * and blob so no partial key material is left to the caller.
 */
int syndrome_kem_keypair_keep_seed(syndrome_set_id set, syndrome_xof_id xof,
                                   uint8_t *pk, uint8_t *sk, uint8_t *blob);

/*
 * Deterministically reconstruct (pk, sk) from a stored seed blob.  The XOF is
 * read from the blob header, which is validated against set (mismatched
 * lambda/n0, unknown xof/format, or nonzero reserved bytes -> negative).
 * Returns 0 on success, negative on failure (a NULL argument is also rejected).
 */
int syndrome_kem_keypair_from_seed(syndrome_set_id set, uint8_t *pk,
                                   uint8_t *sk, const uint8_t *blob);

/*
 * Recompute the public key from the secret key alone (M0 = H_{n0-1}^{-1} H_0).
 * Returns 0 on success, negative on a malformed sk (out-of-range H index or a
 * non-invertible last block), an unknown/disabled set, or a NULL argument.
 */
int syndrome_kem_pubkey_from_sk(syndrome_set_id set, uint8_t *pk,
                                const uint8_t *sk);

/*
 * Designated-opener (Argus): a thin facility on decap.  See docs/DESIGN.md
 * §6.2 for the full opener recipe and §8 for the SP 800-227 deviation
 * analysis.
 *
 * Argus DEM-key width: the output width of the in-circuit KDF root =
 * H(support(e)) -- AES-128 Davies-Meyer (128-bit) at lambda=128, Grostl-256
 * (256-bit) at lambda=256 -- is syndrome_argus_key_width, i.e. lambda/8 (the
 * per-set ss/2).  The DEM is a one-time pad; identities up to that width use
 * root directly, and longer identities (up to syndrome_argus_id_max_bytes(set),
 * = 3*lambda/8) are covered by an AES-CTR extension keyed by root (DESIGN.md
 * §6.2).  ID_MAX is a buffer-sizing bound, not a security cap; it is sized to the
 * voleith rsv5 fixed-leaf capacity and may be raised later without breaking the
 * wire (tag length is carried per call).
 *
 * Tracing-tag layout: tag = prim_id || s || ct, a one-byte KDF-hash selector
 * (the ARGUS_DS_PRIM_ID registry value; see docs/DESIGN.md §6.2)
 * followed by the syndrome (syndrome_ct_bytes(set), the shared (M, s) wire) and
 * the DEM ciphertext (identity_len bytes).  The leading byte is self-describing
 * so future KDF hashes are additive with no wire change; this build opens only
 * its per-lambda default and rejects any other prim_id with EUNSUPPORTED.  Use
 * SYNDROME_MAX_ARGUS_TAG_BYTES(id_len) for a fixed buffer.
 */

/* Typed statuses for syndrome_argus_open (0 on a successful open). */
#define SYNDROME_ARGUS_OK 0
#define SYNDROME_ARGUS_EARGS (-1)       /* null / mis-sized / oversized args  */
#define SYNDROME_ARGUS_EMALFORMED (-2)  /* non-canonical syndrome in the tag  */
#define SYNDROME_ARGUS_EUNOPENABLE (-3) /* s does not decode to a weight-t e  */
#define SYNDROME_ARGUS_EUNSUPPORTED                                            \
    (-4) /* prim_id names a hash not compiled  */

/*
 * Caller attestation that `tag` has already passed voleith ring-signature
 * verification.  This is a REQUIRED, fail-closed gate on syndrome_argus_open:
 * pass SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED only after the enclosing proof has
 * verified; any other value (including the default 0) is rejected with
 * SYNDROME_ARGUS_EARGS before the tag is touched.
 *
 * Why it is mandatory: the gate is load-bearing for two reasons.  First, key
 * secrecy: open returns a typed status (OK vs EUNOPENABLE) that reveals whether
 * the attacker-chosen syndrome decoded to a weight-t error, which on an
 * unverified, attacker-chosen tag is a decoding oracle on the private H, the
 * exact primitive a QC-MDPC reaction attack needs to recover the opener key.  The
 * constant-time open closes the timing and cache channels but not the typed
 * return value, and the DFR bound covers honest errors, not adversarial tags, so
 * only the signature gate denies an attacker chosen-tag access to that oracle.
 * Second, plaintext authentication: the one-time-pad DEM is unauthenticated and
 * malleable, so open returns a K-derived identity for ANY tag and its OK status
 * attests only that the syndrome decoded, never that ct, or the recovered
 * identity, is authentic.  The verified signature supplies both the access
 * control that keeps H out of an attacker's reach and the plaintext integrity the
 * DEM does not (DESIGN.md §6.2, §8).  syndrome cannot check the proof itself, so
 * the caller attests it here; the default fails closed.
 */
typedef enum {
    SYNDROME_ARGUS_TAG_UNVERIFIED = 0, /* default: the open is rejected */
    SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED =
        0x5a9e7c31 /* tag passed voleith signature verification */
} syndrome_argus_gate;

/*
 * syndrome_argus_open: open a tracing tag (prim_id || s || ct) under the opener secret key
 * sk of the given set.  Recovers e via decap, recomputes K = H(support(e)), and
 * OTP-decrypts ct into identity_out (identity_len <=
 * syndrome_argus_id_max_bytes(set)).  Returns SYNDROME_ARGUS_OK and writes
 * identity_out on success, or a negative typed status above (SYNDROME_ARGUS_EARGS
 * also covers an unknown or disabled set).
 *
 * gate MUST be SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED (see syndrome_argus_gate):
 * opening an unverified, attacker-chosen tag is a key-recovery oracle on H (and
 * the malleable OTP DEM would return an unauthenticated identity), so any other
 * value is rejected with SYNDROME_ARGUS_EARGS before the tag is read.  For
 * standalone encrypt-to-recipient use the general KEM (syndrome_kem_*) instead.
 */
int syndrome_argus_open(syndrome_set_id set, uint8_t *identity_out,
                        size_t identity_len, const uint8_t *tag, size_t tag_len,
                        const uint8_t *sk, syndrome_argus_gate gate);

/*
 * Library version, for ABI/diagnostic reporting.  This is the libtalos_syndrome
 * semantic version.  It is DECOUPLED from the Argus parameter-set-recipe version
 * carried in the DS IV (version_u24 = 1; see docs/DESIGN.md §6.2): the
 * recipe version forks only when a byte of the opener recipe changes, whereas
 * this semver tracks the library's public API/ABI and can advance (new sets, bug
 * fixes, doc-only tags) without touching the recipe.
 */
#define SYNDROME_VERSION_MAJOR 1
#define SYNDROME_VERSION_MINOR 0
#define SYNDROME_VERSION_PATCH 0
const char *syndrome_version_string(void);

SYNDROME_END_DECLS

#endif /* TALOS_SYNDROME_H */
