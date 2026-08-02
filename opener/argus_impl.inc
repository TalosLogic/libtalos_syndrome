/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * argus.c - designated-opener facility (Layer 6), built ON decap.
 *
 * Given a tracing tag (syndrome s plus DEM ciphertext ct), recover e via the
 * decoder, recompute the DEM key K = H(support(e)), OTP-decrypt ct, and return
 * the opened identity.  This is the only layer aware of the voleith opener use
 * case; the KEM primitive below it stays scheme-neutral and opener-agnostic.
 *
 * Concrete recipe (DESIGN.md §6.2), pinned here as the byte-exact contract the
 * voleith in-circuit gadget must reproduce (validated by shared KATs):
 *
 *   - Tag:   tag = prim_id || s || ct, where prim_id is one byte naming the KDF
 *            hash (the ARGUS_DS_PRIM_ID registry value; contract A5), s is
 *            SYNDROME_CT_BYTES (the (M, s) wire), and ct is identity_len bytes of
 *            DEM ciphertext.  The byte is self-describing so future hashes are
 *            additive with no wire change; the opener rejects any non-default
 *            prim_id (AT.GATE) with SYNDROME_ARGUS_EUNSUPPORTED.
 *   - KDF:   root = H(support(e)).  The support is the t set positions of e over
 *            [0, n) with n = n0*p: block b in b*p + [0, p), sorted ascending.
 *            Each global index is bit-packed LSB-first into exactly
 *            ARGUS_IDX_BITS = ceil(log2(n)) bits (no per-index byte alignment,
 *            no uint32 dump), and the packed message is zero-padded to the
 *            compression-block boundary -- NO Merkle-Damgard length
 *            strengthening, because the length is a compile-time constant and
 *            the IV / domain is single-purpose.  The message is absorbed through
 *            the bare ichor extractor:
 *              lambda=128: AES-128 Davies-Meyer, IV = ARGUS_DS_IV (16 B);
 *                          root = final chaining value                  (16 B)
 *              lambda=256: Grostl-256, IV = ARGUS_DS_IV zero-padded to 64 B;
 *                          root = truncated output transform            (32 B)
 *            ichor owns the framing (ichor_aesdm_* / ichor_grostl_*); the DS IV
 *            and packing width live here (ichor is opener-agnostic).  Why
 *            AES/Grostl and not SHAKE, why Grostl-256 not Hirose, and why
 *            collision resistance is not load-bearing: DESIGN.md §6.1.
 *   - DEM:   one-time pad.  When identity_len <= lambda bytes the pad is root
 *            directly; when it is longer, root keys AES-CTR (AES-128 @ lambda128
 *            / AES-256 @ lambda256) under the fixed label ARGUS_CTR_LABEL and the
 *            keystream is the pad (DESIGN.md §6.2).  identity = ct XOR
 *            pad.  One-time-pad validity rests on the fresh-e-per-encap rule
 *            (§4.2): root, hence the pad, never repeats.  identity_len is public,
 *            so branching on it is not a side channel.
 *   - Check: re-encryption only (§4.4/§4.8), no confirmation field -- accept iff s
 *            is canonical AND the decoder's ok flag (residual private syndrome
 *            zero, i.e. M*e'^T == s) AND wt(e') == t.  A bad tag returns a typed
 *            status rather than implicit rejection: Argus is the trusted opener,
 *            not a KEM-decap oracle exposed to attackers, and with DFR <= 2^-lambda
 *            (long-term keys) plus the canonical/re-encryption checks the status
 *            leaks negligible information about H.  The general decap retains
 *            implicit rejection.
 *
 * SP 800-227 posture (DESIGN.md §6.2, §8): the conformant surface is the
 * general KEM (syndrome_kem_*); Argus deviates deliberately -- a non-approved
 * KDF (AES-DM/Grostl-256, forced by in-circuit expressibility) and a non-AEAD
 * OTP DEM (integrity supplied by the enclosing voleith proof, not the tag).
 * Hence Argus is IND-CPA on the DEM standalone but IND-CCA2 in-protocol, and
 * MUST only be used on tags that have passed signature verification.
 */
#include <stdint.h>
#include <string.h>

#include <ichor/aes.h>
#include <ichor/aesdm.h>
#include <ichor/grostl.h>
#include <ichor/util.h>

#include "argus.h"
#include "core.h"
#include "pke.h"

/*
 * KDF message framing (DESIGN.md §6.2): the t global support positions live in
 * [0, n) with n = n0*p (SYNDROME_N), so each packs LSB-first into
 * ARGUS_IDX_BITS = ceil(log2(n)) bits.  ARGUS_MSG_BYTES is the packed length;
 * the extractor zero-pads it up to its own block boundary, so no explicit
 * padding constant is needed here.  Shipped widths: 15 (128/n0=2), 16
 * (128/n0=5), 17 (256/n0=2 and 256/n0=5).
 */
#define ARGUS_IDX_BITS                                                         \
    (SYNDROME_N <= (1u << 15)   ? 15u                                          \
     : SYNDROME_N <= (1u << 16) ? 16u                                          \
     : SYNDROME_N <= (1u << 17) ? 17u                                          \
                                : 0u /* extend the ladder for a larger n */)
#define ARGUS_MSG_BYTES (((SYNDROME_T * ARGUS_IDX_BITS) + 7u) / 8u)

/* Every global index in [0, n) must fit the packing field. */
_Static_assert((SYNDROME_N - 1u) < (1u << ARGUS_IDX_BITS),
               "ARGUS_IDX_BITS too small for [0, n)");

/*
 * Domain-separation IV core (DESIGN.md §6.2), a fixed
 * public 16-byte constant that binds the (lambda, primitive, n0) set identity
 * into the extractor / OTP-KDF domain, so n0=2 and n0=5 at the same lambda are
 * domain-separated:
 *   "TALOS"(5) || "Argus"(5) || lambda-in-bytes(1) || primitive-id(1) ||
 *   n0(1) || version u24 big-endian(3).
 * The lambda byte re-encodes the extractor output length (0x10 / 0x20); the
 * primitive id selects AES-DM (0x01) vs Grostl-256 (0x02); the n0 byte is the
 * literal block count (it claims the high byte of the former version u32, so
 * the version is now 24-bit).  For AES-DM this is the whole 16-byte IV; for
 * Grostl-256 it is zero-padded to 64 bytes.  Changing any byte is a
 * parameter-set-version change (it forks the cross-firewall contract with
 * voleith).
 */
#if SYNDROME_LAMBDA == 128
#define ARGUS_DS_LAMBDA_BYTE 0x10u
#define ARGUS_DS_PRIM_ID 0x01u
#else
#define ARGUS_DS_LAMBDA_BYTE 0x20u
#define ARGUS_DS_PRIM_ID 0x02u
#endif
#define ARGUS_DS_N0_BYTE ((uint8_t)(SYNDROME_N0))
static const uint8_t ARGUS_DS_IV[16] = {
    'T',
    'A',
    'L',
    'O',
    'S',
    'A',
    'r',
    'g',
    'u',
    's',
    ARGUS_DS_LAMBDA_BYTE,
    ARGUS_DS_PRIM_ID,
    ARGUS_DS_N0_BYTE,
    0x00,
    0x00,
    0x01 /* version = 1, u24 big-endian */
};

/* Label bound into the AES-CTR counter for the len(ID) > lambda extension. */
static const uint8_t ARGUS_CTR_LABEL[12] = "Argus-OTP-v1";

/*
 * Deserialize the private H index lists from the front of sk (sk = H | .. ).
 * Returns the OR of (index >= p) over all columns: nonzero iff sk is malformed
 * (an out-of-range column).  The caller folds it into the accept mask so a
 * malformed opener key fails safe (EUNOPENABLE) rather than opening under a wrong
 * key.  Constant-time: fixed-bound loop, branch-free range test.
 */
static uint32_t
deserialize_h(syndrome_qcmdpc_sk *qsk, const uint8_t *sk)
{
    size_t off = 0;
    uint32_t b, j;
    uint32_t bad = 0;

    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        for (j = 0; j < (uint32_t)SYNDROME_V; j++) {
            uint16_t c = (uint16_t)(sk[off] | ((uint16_t)sk[off + 1] << 8));

            qsk->cols[b][j] = c;
            bad |= ((uint32_t)SYNDROME_P - 1u - (uint32_t)c) >> 31;
            off += 2;
        }
    return bad;
}

/* 0xFFFFFFFF if a == b, else 0 -- branch-free (mirrors core/sample.c). */
static uint32_t
ct_mask_eq32(uint32_t a, uint32_t b)
{
    uint32_t x = a ^ b;
    uint32_t nz = (x | (0u - x)) >> 31; /* 1 if x != 0, else 0 */

    return nz - 1u;
}

/*
 * Collect the t set positions of e into idx, ascending: block b mapped to
 * b*p + [0, p), scanned in block order.  Called only after wt(e) == t is
 * verified, so exactly SYNDROME_T positions are written.
 *
 * Constant-time over the secret support (docs/CONSTANT_TIME.md, F2): the
 * recovered error reconstructs the de-anonymizing identity (K = H(support(e))),
 * so its access pattern must not leak -- the plaintext protected by the PKE is
 * held as secret as sk itself.  We therefore use oblivious compaction: scan
 * every position with a fixed-bound loop (no data-dependent branch, no early
 * exit), read the dense blocks at public sequential offsets only, and for each
 * set bit write its global position into output slot `count` by sweeping all t
 * slots under a constant-time equality mask (so the write touches every slot
 * identically regardless of the secret).  `count` is only ever compared, never
 * used as a memory index.  Cost is O(n0 * p * t), the offline-opener analogue
 * of the encap-side oblivious scatter.
 */
static void
extract_indices(uint32_t idx[SYNDROME_T],
                const uint8_t eb[][SYNDROME_BLOCK_BYTES])
{
    uint32_t count = 0; /* set bits seen so far == next output slot */
    uint32_t b, pos, j;

    for (j = 0; j < (uint32_t)SYNDROME_T; j++)
        idx[j] = 0;

    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        const uint8_t *e = eb[b];
        uint32_t base = b * (uint32_t)SYNDROME_P;

        for (pos = 0; pos < (uint32_t)SYNDROME_P; pos++) {
            uint32_t bit = (uint32_t)((e[pos >> 3] >> (pos & 7u)) & 1u);
            /*
             * Route the per-bit gate through ichor's opaque mask.  With the
             * plain (0u - bit) below, clang >= 17 proves the term is 0 when
             * bit == 0 and hoists a secret-dependent branch that skips the
             * inner masked write, leaking the support (dudect |t| ~3000-4900
             * on clang 17/19; gcc 14 and clang 14 stay branch-free).  The
             * out-of-line ichor_ct_mask64 the compiler cannot see through
             * keeps the blend unconditional; relies on ichor_ct_mask64 staying
             * out-of-line, i.e. no LTO on the release build.
             */
            uint32_t bitmask = (uint32_t)ichor_ct_mask64(bit);
            uint32_t global = base + pos;

            for (j = 0; j < (uint32_t)SYNDROME_T; j++) {
                uint32_t sel = bitmask & ct_mask_eq32(count, j);

                idx[j] = (idx[j] & ~sel) | (global & sel);
            }
            count += bit;
        }
    }
}

/*
 * root = H(support(e)): bit-pack idx to ARGUS_IDX_BITS-wide fields, then absorb
 * through the level's extractor with the DS IV and zero-pad-only finalize.  The
 * access pattern depends only on public shape (t, width), not the secret
 * indices, so bit-packing and absorption are constant-time over the support.
 */
static void
argus_kdf(uint8_t root[SYNDROME_ARGUS_KEY_BYTES],
          const uint32_t idx[SYNDROME_T])
{
    uint8_t msg[ARGUS_MSG_BYTES];

    ichor_bitpack_le32(msg, sizeof(msg), idx, SYNDROME_T, ARGUS_IDX_BITS);

#if SYNDROME_LAMBDA == 128
    {
        ichor_aesdm_ctx_t ctx;

        ichor_aesdm_init_iv(&ctx, ARGUS_DS_IV);
        ichor_aesdm_absorb(&ctx, msg, sizeof(msg));
        ichor_aesdm_finalize_fixed(&ctx, root);
        ichor_aesdm_clear(&ctx);
    }
#else
    {
        ichor_grostl_ctx_t ctx;
        uint8_t iv[64];

        memset(iv, 0, sizeof(iv));
        memcpy(iv, ARGUS_DS_IV, sizeof(ARGUS_DS_IV));
        ichor_grostl256_init_iv(&ctx, iv);
        ichor_grostl_absorb(&ctx, msg, sizeof(msg));
        ichor_grostl_finalize_fixed(&ctx, root);
        ichor_grostl_clear(&ctx);
    }
#endif
    ichor_secure_zero(msg, sizeof(msg));
}

/*
 * Fill pad[0:pad_len] with the one-time-pad keystream (DESIGN.md §6.2 DEM).  When
 * pad_len <= lambda bytes the pad is root itself; otherwise root keys AES-CTR
 * (AES-128 @ lambda128 / AES-256 @ lambda256) under ARGUS_CTR_LABEL and the
 * keystream fills pad.  pad_len (== identity_len) is public, so the branch is
 * not a side channel; a fresh e per seal gives a fresh root, so no keystream
 * repeats.
 */
static void
argus_otp(uint8_t *pad, size_t pad_len,
          const uint8_t root[SYNDROME_ARGUS_KEY_BYTES])
{
    ichor_aes_ctx_t actx;

    if (pad_len <= (size_t)SYNDROME_ARGUS_KEY_BYTES) {
        memcpy(pad, root, pad_len);
        return;
    }

    /*
     * The 12-byte ARGUS_CTR_LABEL is the CTR nonce; the 32-bit block counter
     * starts at 0.  pad_len (== identity_len) is bounded far below the 2^32
     * block (64 GiB) cap, so ichor_aes_ctr cannot exhaust the counter here;
     * the (void) makes the always-0 return explicit.
     */
    ichor_aes_key_expand(&actx, root, SYNDROME_LAMBDA);
    (void)ichor_aes_ctr(&actx, pad, NULL, pad_len, ARGUS_CTR_LABEL, 0);
    ichor_aes_ctx_clear(&actx);
}

/*
 * Scatter a weight-t index list over [0, n) into the n0 dense p-bit blocks,
 * in constant time over the secret support: each block b is filled by the
 * oblivious syndrome_sample_scatter (compare every position against every
 * index), addressed by subtracting b*p from every index so an index from any
 * other block falls outside [0, p) and matches no position there.  Mirrors
 * kem.c's errblocks_from_indices (the seal path shares the encap CT rule).
 */
static void
argus_errblocks_from_indices(uint8_t eb[][SYNDROME_BLOCK_BYTES],
                             const uint32_t *idx, uint32_t w)
{
    uint32_t idx_b[SYNDROME_T];
    uint32_t i, b;

    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        uint32_t base = b * (uint32_t)SYNDROME_P;

        for (i = 0; i < w; i++)
            idx_b[i] = idx[i] - base;
        syndrome_sample_scatter(eb[b], SYNDROME_BLOCK_BYTES, idx_b, w,
                                SYNDROME_P);
    }
    ichor_secure_zero(idx_b, sizeof(idx_b));
}

int
syndrome_argus_seal_derand(uint8_t *tag, const uint8_t pk[SYNDROME_PK_BYTES],
                           const uint8_t *identity, size_t identity_len,
                           syndrome_drbg *rng)
{
    uint32_t eidx[SYNDROME_T];
    uint32_t idx[SYNDROME_T];
    uint8_t eb[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint8_t kdf_root[SYNDROME_ARGUS_KEY_BYTES];
    uint8_t pad[SYNDROME_ARGUS_ID_MAX_BYTES];
    size_t i;
    uint32_t b;
    int ret = -1;

    if (tag == NULL || pk == NULL || identity == NULL || rng == NULL)
        return -1;
    if (identity_len == 0 || identity_len > (size_t)SYNDROME_ARGUS_ID_MAX_BYTES)
        return -1;

    /* Fresh weight-t error (D2; mandatory for one-time-pad and anonymity). */
    if (syndrome_sample_fixed_weight(eidx, SYNDROME_T, SYNDROME_N, rng) != 0)
        goto done;

    argus_errblocks_from_indices(eb, eidx, SYNDROME_T);
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        syndrome_gf2x_load(e[b], eb[b]);

    /* tag[0] = prim_id (KDF-hash selector); tag[1:1+CT] = s = M*e^T. */
    tag[0] = (uint8_t)ARGUS_DS_PRIM_ID;
    syndrome_pke_encrypt(tag + 1, pk, e);

    /* root = H(support(e)); tag[1+CT:] = identity XOR pad (one-time pad). */
    extract_indices(idx, eb);
    argus_kdf(kdf_root, idx);
    argus_otp(pad, identity_len, kdf_root);
    for (i = 0; i < identity_len; i++)
        tag[1 + SYNDROME_CT_BYTES + i] = (uint8_t)(identity[i] ^ pad[i]);

    ret = 0;

done:
    ichor_secure_zero(eidx, sizeof(eidx));
    ichor_secure_zero(idx, sizeof(idx));
    ichor_secure_zero(eb, sizeof(eb));
    ichor_secure_zero(e, sizeof(e));
    ichor_secure_zero(kdf_root, sizeof(kdf_root));
    ichor_secure_zero(pad, sizeof(pad));
    return ret;
}

/*
 * argus_tail - the post-decode Argus work, split out of
 * syndrome_argus_open_impl so the dudect harness (targets_syndrome.c
 * "argus_tail") can measure exactly this tail on a supplied decode result,
 * without re-timing the decoder (which has its own target) or its ichor-gated
 * gf2x/sample primitives.  Given the recovered error blocks eb and the
 * constant-time validity mask vmask (0x00.. per byte when the tag is not
 * openable, 0xFF.. when it is), extract the support, derive K = H(support(e')),
 * OTP-decrypt into identity_out under the mask, and return the branchless open
 * status.  Every step runs unconditionally, so openable and not-openable are
 * timing- and access-indistinguishable; the reaction-oracle rationale is on the
 * caller.
 */
static int
argus_tail(uint8_t *identity_out, size_t identity_len, const uint8_t *dem,
           const uint8_t eb[][SYNDROME_BLOCK_BYTES], uint32_t vmask)
{
    uint32_t idx[SYNDROME_T];
    uint8_t kdf_root[SYNDROME_ARGUS_KEY_BYTES];
    uint8_t pad[SYNDROME_ARGUS_ID_MAX_BYTES];
    uint8_t valid = (uint8_t)vmask;
    size_t i;
    int ret;

    extract_indices(idx, eb);
    argus_kdf(kdf_root, idx);
    argus_otp(pad, identity_len, kdf_root);
    for (i = 0; i < identity_len; i++)
        identity_out[i] = (uint8_t)((dem[i] ^ pad[i]) & valid);

    /*
     * Branchless status: SYNDROME_ARGUS_OK (== 0) if valid, else EUNOPENABLE.
     * (vmask & 1) is 1 when valid, so ((vmask & 1) - 1) masks EUNOPENABLE to 0.
     */
    ret = (int)((uint32_t)SYNDROME_ARGUS_EUNOPENABLE & ((vmask & 1u) - 1u));

    ichor_secure_zero(idx, sizeof(idx));
    ichor_secure_zero(kdf_root, sizeof(kdf_root));
    ichor_secure_zero(pad, sizeof(pad));
    return ret;
}

int
syndrome_argus_open_impl(uint8_t *identity_out, size_t identity_len,
                         const uint8_t *tag, size_t tag_len,
                         const uint8_t sk[SYNDROME_SK_BYTES])
{
    syndrome_qcmdpc_sk qsk;
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint8_t eb[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    const uint8_t *s, *dem;
    uint32_t padbits;
    uint8_t padmask;
    size_t w;
    uint32_t b;
    uint32_t vmask;
    uint32_t sk_bad;
    int ok = 0, ret;

    if (identity_out == NULL || tag == NULL || sk == NULL)
        return SYNDROME_ARGUS_EARGS;
    if (identity_len == 0 || identity_len > (size_t)SYNDROME_ARGUS_ID_MAX_BYTES)
        return SYNDROME_ARGUS_EARGS;
    if (tag_len != (size_t)1 + SYNDROME_CT_BYTES + identity_len)
        return SYNDROME_ARGUS_EARGS;

    /*
     * Fail closed on a prim_id this build does not implement.  tag[0] is the
     * KDF-hash selector; this build opens only its compiled default
     * (ARGUS_DS_PRIM_ID).  The byte is attacker-known public data, so branching
     * on it before any H-dependent work leaks nothing about H: same category as
     * the canonical-s EMALFORMED early return below, and the constant-time tail
     * (decode + KDF + OTP) stays unconditional.  Future-additive: with a second
     * hash compiled this becomes a switch(tag[0]) selecting the hash and DS-IV
     * prim_id, rejecting only ids absent from the registry; the read stays
     * public and pre-decode.
     */
    if (tag[0] != (uint8_t)ARGUS_DS_PRIM_ID)
        return SYNDROME_ARGUS_EUNSUPPORTED;

    /* tag = prim_id || s || ct; s and dem follow the one-byte selector. */
    s = tag + 1;
    dem = tag + 1 + SYNDROME_CT_BYTES;

    /* Reject a non-canonical syndrome (top padding bits of s must be zero). */
    padbits = (uint32_t)(8 * SYNDROME_BLOCK_BYTES - SYNDROME_P);
    padmask = (uint8_t)(padbits ? (0xffu << (8 - padbits)) : 0u);
    if ((s[SYNDROME_CT_BYTES - 1] & padmask) != 0)
        return SYNDROME_ARGUS_EMALFORMED;

    sk_bad = deserialize_h(&qsk, sk);

    /* Recover e; ok == "M*e'^T == s" (decoder residual private syndrome zero). */
    syndrome_pke_decrypt(r, &ok, &qsk, s);
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        syndrome_gf2x_store(eb[b], r[b]);

    w = 0;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        w += syndrome_bitvec_weight(eb[b], SYNDROME_P);

    /*
     * valid = (decoder ok) AND (wt(e') == t) AND (sk in range), as a
     * constant-time 0x00/0xFF mask.  A malformed opener key (out-of-range
     * column) forces the mask to 0, so the open fails safe (EUNOPENABLE).
     */
    vmask = ct_mask_eq32((uint32_t)ok, 1u) &
            ct_mask_eq32((uint32_t)w, (uint32_t)SYNDROME_T) &
            ct_mask_eq32(sk_bad, 0u);

    /*
     * Constant-time tail (argus_tail): support extraction, the KDF, and the OTP
     * run unconditionally so that "openable" and "not openable" are
     * indistinguishable in timing and memory-access pattern.  Gating this work
     * on the decode result would make the taken/skipped branch a one-bit
     * reaction oracle on H for adversarially crafted tags, observable by a
     * co-resident attacker (the honest-error/DFR bound does not apply to
     * adversarial input).  identity_out is written under the validity mask
     * (zeroed on failure); the openable bit survives only in the returned
     * status, which reaches the trusted caller, never the cache.  Calling
     * extract_indices when wt(e') != t is safe -- it writes at most t slots and
     * drops any surplus -- so the unconditional path has no out-of-bounds risk.
     */
    ret = argus_tail(identity_out, identity_len, dem, eb, vmask);

    ichor_secure_zero(&qsk, sizeof(qsk));
    ichor_secure_zero(r, sizeof(r));
    ichor_secure_zero(eb, sizeof(eb));
    return ret;
}
