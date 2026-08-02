/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * argus_kat_common.h - shared constants for the Argus opener KAT regression
 * gate (tests/test_argus_kat.c).
 *
 * The Argus seal/open framing (packed support indices, DS-IV, AES-DM/Grostl-256
 * extractor, OTP CTR extension: docs/DESIGN.md §6.1/§6.2) is the byte-exact
 * cross-firewall contract the (as-yet-unwritten) voleith in-circuit gadget must
 * reproduce.  There is no external oracle for it, so -- exactly as the KEM KAT
 * (kem_kat_common.h) -- this harness generates its own regression fingerprint:
 * a SHA3-256 over (seed, pk, sk, id_len, id, tag, opened) across a fixed sweep
 * driven from one pinned top-level seed.  Once captured from a trusted run and
 * pasted into SYNDROME_ARGUS_KAT_GOLDEN below, that digest IS the KAT: it pins
 * every byte a conforming gadget must emit.
 *
 * The golden is tied to the parameter set selected at build time, so there is
 * one pinned digest per (lambda, n0).  An all-zero entry means "unpinned": the
 * harness then skips the hard regression check and prints the computed digest
 * instead, so round-trip and determinism still gate.
 *
 * Argus is defined for the lambda=128 and lambda=256 opener parameter sets only
 * (docs/DESIGN.md; the KEM-only sets carry no opener), which is exactly the set
 * talos_syndrome.h admits, so no further guard is needed here.
 */
#ifndef SYNDROME_ARGUS_KAT_COMMON_H
#define SYNDROME_ARGUS_KAT_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* SYNDROME_LAMBDA and SYNDROME_N0 select the per-parameter-set golden below. */
#include "talos_syndrome.h"

#define SYNDROME_ARGUS_KAT_CASES 12

/*
 * Identity lengths swept, cycled across the cases so the fingerprint pins all
 * three OTP pad regimes (DESIGN.md §6.2 DEM):
 *   - a short identity  (< lambda bytes): a prefix of the direct root pad;
 *   - a full-width one   (== lambda bytes, == SYNDROME_ARGUS_KEY_BYTES): the
 *     whole root pad;
 *   - an over-long one   (> lambda bytes, up to SYNDROME_ARGUS_ID_MAX_BYTES):
 *     the AES-CTR keystream extension keyed by root.
 */
static const size_t SYNDROME_ARGUS_KAT_IDLENS[3] = {
    8u, (size_t)SYNDROME_ARGUS_KEY_BYTES, (size_t)SYNDROME_ARGUS_ID_MAX_BYTES};

/* NIST-convention fixed entropy: an incrementing 48-byte top-level seed. */
static const uint8_t SYNDROME_ARGUS_KAT_TOPSEED[48] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};

/*
 * Pinned SHA3-256 over (seed, pk, sk, id_len, id, tag, opened) for all
 * SYNDROME_ARGUS_KAT_CASES at the active parameter set.  One golden per
 * (lambda, n0), selected at compile time.  All-zero means "unpinned" (the
 * harness then skips the hard regression check and prints the computed digest
 * instead).
 */
/* Pinned over tag = prim_id || s || ct (the selector byte leads the tag).  To
 * re-capture after an intentional framing change: blank the affected block to
 * {0}, rebuild that (lambda, n0) variant, run test_argus_kat, and paste the
 * printed body back to re-arm the regression gate. */
#if SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 2
static const uint8_t SYNDROME_ARGUS_KAT_GOLDEN[32] = {
    0xbf, 0xbf, 0xd3, 0xd8, 0xd9, 0x36, 0x12, 0x1d, 0xf2, 0x1b, 0x8e,
    0xab, 0xfe, 0xa1, 0x32, 0x19, 0xb0, 0x40, 0x30, 0xfd, 0x82, 0x29,
    0x18, 0xed, 0xf6, 0x65, 0xc1, 0x3b, 0x7d, 0xbb, 0xf2, 0x96};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 2
static const uint8_t SYNDROME_ARGUS_KAT_GOLDEN[32] = {
    0x8e, 0x4f, 0xca, 0x94, 0x18, 0xdd, 0xa3, 0x81, 0x43, 0x67, 0x74,
    0xd7, 0xf0, 0x52, 0x5f, 0x3e, 0xaf, 0x3c, 0xe4, 0x7f, 0x0f, 0x79,
    0x33, 0x80, 0x97, 0x99, 0xb7, 0x31, 0xaa, 0x4d, 0x13, 0xf4};
#elif SYNDROME_LAMBDA == 128 && SYNDROME_N0 == 5
static const uint8_t SYNDROME_ARGUS_KAT_GOLDEN[32] = {
    0x0e, 0x7b, 0xd8, 0x52, 0x01, 0xc6, 0x64, 0x16, 0xb0, 0xa9, 0xc8,
    0x8d, 0xb4, 0xd1, 0xc4, 0xb8, 0x62, 0x7a, 0x25, 0x5d, 0xd1, 0x17,
    0x6e, 0xc3, 0xc2, 0x10, 0xc0, 0x5f, 0x4a, 0xb4, 0xc2, 0x1b};
#elif SYNDROME_LAMBDA == 256 && SYNDROME_N0 == 5
static const uint8_t SYNDROME_ARGUS_KAT_GOLDEN[32] = {
    0xca, 0xd8, 0x7e, 0x5d, 0x48, 0xdc, 0xf9, 0xa9, 0x69, 0x61, 0xd4,
    0x56, 0x74, 0x04, 0xb7, 0x18, 0xd2, 0x35, 0x0c, 0x59, 0x97, 0x0b,
    0xaa, 0x51, 0x5c, 0x58, 0x4f, 0x0f, 0x99, 0xa6, 0x7e, 0xe8};
#else
#error "no SYNDROME_ARGUS_KAT_GOLDEN for this (SYNDROME_LAMBDA, SYNDROME_N0)"
#endif

#endif /* SYNDROME_ARGUS_KAT_COMMON_H */
