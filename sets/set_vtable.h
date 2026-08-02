/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * set_vtable.h - the per-set dispatch record.
 *
 * Each enabled (lambda, n0) set is compiled into one wrapper TU
 * (sets/syn_<lambda>_<n0>.c) that exports exactly one external symbol: a
 * const syndrome_set_vtable carrying that set's sizes and op function pointers.
 * The public dispatch layer (syndrome.c) selects a vtable by a public
 * syndrome_set_id and calls through it.  Parameter-free, so it is shared by the
 * dispatch TU and every wrapper.
 *
 * The op pointers use plain uint8_t * (not fixed-size arrays): the buffer sizes
 * differ per set and are queried at runtime via the size fields (or bounded at
 * compile time by the SYNDROME_MAX_* ceilings in talos_syndrome.h).  The
 * per-set impl functions declare fixed-array parameters, which decay to the
 * same pointer type, so no cast is needed to take their address.
 *
 * Which vtables actually exist is set by the build: CMake compiles a wrapper
 * only for a set that is both enabled (SYNDROME_ENABLE_SYN_*, see the top-level
 * CMakeLists.txt) and implemented, and defines SYNDROME_BUILT_SYN_<set>=1 for
 * each one it compiles.  Only the vtables for compiled sets are declared here.
 */
#ifndef SYNDROME_SET_VTABLE_H
#define SYNDROME_SET_VTABLE_H

#include <stddef.h>
#include <stdint.h>

#include "core.h" /* syndrome_drbg (op-pointer signatures reference it) */

typedef struct {
    /* Set identity. */
    uint16_t lambda; /* 128 / 256 */
    uint16_t n0;     /* 2 / 5     */

    /* Per-set byte sizes (the removed flat SYNDROME_*_BYTES macros). */
    size_t pk_bytes;
    size_t sk_bytes;
    size_t ct_bytes;
    size_t ss_bytes;
    size_t argus_key_bytes;
    size_t argus_id_max_bytes;

    /*
     * Production ops.  keypair/encap are the derandomized seams (the public
     * wrappers draw system entropy and seed a DRBG before calling); decap and
     * argus_open are deterministic.  argus_seal_derand is the signer-side
     * software twin used by the KAT harness (not a public entrypoint).
     */
    int (*kem_keypair_derand)(uint8_t *pk, uint8_t *sk, syndrome_drbg *rng);
    int (*kem_encap_derand)(uint8_t *ct, uint8_t *k, const uint8_t *pk,
                            syndrome_drbg *rng);
    int (*kem_decap)(uint8_t *k, const uint8_t *ct, const uint8_t *sk);
    /* Recompute pk = M from a deserialized sk's H (seed API; no entropy). */
    int (*kem_pubkey_from_sk)(uint8_t *pk, const uint8_t *sk);
    int (*argus_seal_derand)(uint8_t *tag, const uint8_t *pk,
                             const uint8_t *identity, size_t identity_len,
                             syndrome_drbg *rng);
    int (*argus_open)(uint8_t *identity_out, size_t identity_len,
                      const uint8_t *tag, size_t tag_len, const uint8_t *sk);
} syndrome_set_vtable;

#ifdef SYNDROME_BUILT_SYN_128_2
extern const syndrome_set_vtable syndrome_set_128_2;
#endif
#ifdef SYNDROME_BUILT_SYN_128_5
extern const syndrome_set_vtable syndrome_set_128_5;
#endif
#ifdef SYNDROME_BUILT_SYN_256_2
extern const syndrome_set_vtable syndrome_set_256_2;
#endif
#ifdef SYNDROME_BUILT_SYN_256_5
extern const syndrome_set_vtable syndrome_set_256_5;
#endif

#endif /* SYNDROME_SET_VTABLE_H */
