/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * core.h - internal interface for Layer 1 (core/).
 *
 * Circulant F_2[x]/(x^p - 1) arithmetic, bit vectors, DRBG, and constant-time
 * fixed-weight sampling.  Not part of the public surface.  SHAKE/SHA-3, AES,
 * the constant-time util helpers, and CPU dispatch now come from libtalos_ichor
 * (<ichor/hash.h>, <ichor/aes.h>, <ichor/util.h>).
 *
 * Each module currently exposes only a self-test entry point used by the
 * component-KAT harness (docs/TESTING.md).  They return 0 on success and a
 * negative value on failure; -1 means "not yet implemented".
 */
#ifndef SYNDROME_CORE_H
#define SYNDROME_CORE_H

#include <stddef.h>
#include <stdint.h>

#include <ichor/version.h>

#include "talos_syndrome.h"

/*
 * Supported ichor range: [1.1.0, 2.0.0).  The floor is 1.1.0 because syndrome's
 * gf2x, fixed-weight sampler, and scatter delegate to <ichor/gf2x.h> /
 * <ichor/sample.h>, added in ichor 1.1.0 (absent from 1.0.0).  The build
 * enforces the full range at configure time (top-level CMakeLists.txt); this
 * guard travels with the source and catches a version-skewed ichor even when
 * the build system is bypassed.
 */
#if ICHOR_VERSION_MAJOR != 1 ||                                                \
    (ICHOR_VERSION_MAJOR == 1 && ICHOR_VERSION_MINOR < 1)
#error "libtalos_syndrome requires libtalos_ichor >= 1.1.0, < 2.0.0"
#endif

/*
 * Deterministic random bit generator: AES-256 CTR_DRBG without a derivation
 * function (NIST SP 800-227 randomness; the SP 800-90A construction used by the
 * NIST PQC KAT harness).  Built on ichor's constant-time AES, so the generator
 * is constant-time in its secret state.  Instantiated from 48 bytes of seed
 * material -- system entropy in production, the fixed .req seed for KATs.
 */
typedef struct {
    uint8_t key[32];         /* AES-256 key (CTR_DRBG Key) */
    uint8_t v[16];           /* counter block (CTR_DRBG V) */
    uint64_t reseed_counter; /* generate requests since instantiation; bounded
                              * by the SP 800-90A reseed interval (rng.c) */
} syndrome_drbg;

/*
 * warn_unused_result where the toolchain supports it (Clang and GCC 5+ via
 * __has_attribute; empty elsewhere, e.g. MSVC).  syndrome_drbg_generate can
 * refuse once the SP 800-90A reseed interval is reached, and no caller may
 * silently drop that fail-closed signal.  The attribute is compile-time only:
 * it never crosses the FFI/ABI boundary, so managed-VM consumers are unaffected.
 */
#if defined(__has_attribute)
#if __has_attribute(warn_unused_result)
#define SYNDROME_WUR __attribute__((warn_unused_result))
#endif
#endif
#ifndef SYNDROME_WUR
#define SYNDROME_WUR
#endif

void syndrome_drbg_init(syndrome_drbg *, const uint8_t[48]);
SYNDROME_WUR int syndrome_drbg_generate(syndrome_drbg *, uint8_t *, size_t);
void syndrome_drbg_clear(syndrome_drbg *);

/* Fill buf with len bytes from the operating-system CSPRNG (production seed). */
int syndrome_randombytes_system(uint8_t *, size_t);

/*
 * Bit vectors are packed little-endian into bytes: logical bit i lives in byte
 * i/8 at bit position i%8 (bit 0 is the LSB of byte 0).  When a logical length
 * is not a multiple of 8, the unused high bits of the final byte are kept zero
 * (canonical form); syndrome_bitvec_weight masks the tail itself.
 *
 * weight (length in bits) and xor (length in bytes) are data-independent, so
 * they are constant-time over secret contents.  The single-bit accessors take
 * a PUBLIC index and touch memory at that offset -- never call them with a
 * secret-dependent index (oblivious secret placement is the sampler's job).
 */
size_t syndrome_bitvec_weight(const uint8_t *, size_t);
void syndrome_bitvec_xor(uint8_t *, const uint8_t *, const uint8_t *, size_t);
int syndrome_bitvec_test(const uint8_t *, size_t);
void syndrome_bitvec_set(uint8_t *, size_t);
void syndrome_bitvec_clear(uint8_t *, size_t);
void syndrome_bitvec_flip(uint8_t *, size_t);

/*
 * Circulant F_2[x]/(x^p-1) ring arithmetic (gf2x) and constant-time
 * fixed-weight sampling are parameter-dependent (they size buffers by p, v,
 * t, n), so their declarations live in the per-set header sets/set_internal.h
 * -- compiled once per (lambda, n0) set with internal linkage -- not here in
 * the parameter-free shared core.  This header carries only the DRBG and bit
 * vectors, which are parameter-independent and compiled once as shared TUs.
 */

int syndrome_bitvec_selftest(void);
int syndrome_rng_selftest(void);

#endif /* SYNDROME_CORE_H */
