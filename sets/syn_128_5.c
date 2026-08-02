/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * syn_128_5.c - per-set wrapper for (lambda = 128, n0 = 5).
 *
 * Compiles the generic implementation bodies with this set's constants and
 * exports exactly one external symbol: the syndrome_set_128_5 vtable.  See
 * sets/set_vtable.h for the dispatch contract.  `nm` on this object shows one
 * external definition (plus references to the shared DRBG / bit-vector symbols).
 */
#define SYNDROME_LAMBDA 128
#define SYNDROME_N0 5

#include "set_vtable.h"

/* Generic bodies (+ the parameter table), compiled here with this set's
 * (lambda, n0) constants.  set_bodies.inc is the single source of truth for the
 * body list, shared with the per-set test binaries. */
#include "set_bodies.inc"

const syndrome_set_vtable syndrome_set_128_5 = {
    .lambda = SYNDROME_LAMBDA,
    .n0 = SYNDROME_N0,
    .pk_bytes = SYNDROME_PK_BYTES,
    .sk_bytes = SYNDROME_SK_BYTES,
    .ct_bytes = SYNDROME_CT_BYTES,
    .ss_bytes = SYNDROME_SS_BYTES,
    .argus_key_bytes = SYNDROME_ARGUS_KEY_BYTES,
    .argus_id_max_bytes = SYNDROME_ARGUS_ID_MAX_BYTES,
    .kem_keypair_derand = syndrome_kem_keypair_derand,
    .kem_encap_derand = syndrome_kem_encap_derand,
    .kem_decap = syndrome_kem_decap_impl,
    .kem_pubkey_from_sk = syndrome_kem_pubkey_from_sk_impl,
    .argus_seal_derand = syndrome_argus_seal_derand,
    .argus_open = syndrome_argus_open_impl,
};
