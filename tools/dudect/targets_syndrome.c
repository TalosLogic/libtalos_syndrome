/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * libtalos_syndrome dudect targets: the secret-input entrypoints this
 * library implements itself (ichor's primitives are validated in ichor's
 * own harness; see docs/CONSTANT_TIME.md "Scope").  Each descriptor runs
 * one operation over two input classes; a constant-time operation must
 * yield |t| below the dudect threshold across the run.  The target set
 * mirrors docs/CONSTANT_TIME.md "Validation methodology":
 *
 *   sample_fixed_weight  -- masked Fisher-Yates: timing must not depend on
 *                           the drawn positions (two distinct RNG streams).
 *   bitflip_decode       -- the load-bearing decoder: fixed iterMax=3,
 *                           decode success/failure timing-indistinguishable
 *                           (two distinct private syndromes).
 *   kem_encap            -- validates the F1 oblivious error expansion on
 *                           the anonymity-critical path (two RNG streams =>
 *                           two fresh errors).
 *   kem_decap            -- the highest-value test: a valid (decoding)
 *                           ciphertext vs. a tampered (rejecting) one must
 *                           be byte-for-byte indistinguishable in timing
 *                           (constant-time implicit rejection, §4.6).
 *   argus_open           -- validates the F2 oblivious support extraction
 *                           and the constant-time tail: two distinct
 *                           openable tags must run in identical time (only
 *                           the §6.2 openable/not return value may vary).
 *                           Split into argus_tail (openable-bit + support
 *                           axes, both weight-t) and argus_tail_weight (adds
 *                           the residual-weight axis: weight-t vs off-weight).
 *   pubkey_from_sk       -- the Proteus seed API's public-key recovery
 *                           (M = H_{n0-1}^{-1} H): two distinct secret keys
 *                           must recompute M in identical time (§5).
 *
 * These validate syndrome's own code (sampler, decoder, KEM/Argus glue).  The
 * circulant gf2x ring (multiply, rotate, Itoh-Tsujii inverse) and AES/SHAKE
 * underneath are ichor's, validated (parity + CT) in ichor's own suite.  The
 * harness pins
 * ichor to its software fallback (dudect_main.c sets ICHOR_FORCE_BACKEND) so the
 * measured path is the at-risk hand-written scalar code, not the
 * CT-by-construction AES-NI/CLMUL instructions; a leak here is in syndrome's
 * code.
 */
#include "dudect_target.h"

#include "argus.h"
#include "code.h"
#include "core.h"
#include "kem.h"
#include "pke.h"

#include <stdint.h>
#include <string.h>

/* Visible side effect: every run folds an output byte here so the compiler
 * cannot dead-code-eliminate the measured work.
 */
static volatile uint8_t syndrome_target_sink;

/* ---- shared fixed key material (built once, outside any timer) -------- */

static struct {
    int ready;
    /* PKE key: qsk + dense H blocks, used by the decode target. */
    syndrome_qcmdpc_sk qsk;
    uint8_t pke_pk[SYNDROME_PK_BYTES];
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    /* KEM key (serialized), used by encap/decap/argus targets. */
    uint8_t kem_pk[SYNDROME_PK_BYTES];
    uint8_t kem_sk[SYNDROME_SK_BYTES];
    /* A second, distinct KEM secret key: the two classes of the pubkey_from_sk
     * test (its timing must not depend on which secret key it recomputes M for). */
    uint8_t kem_sk_b[SYNDROME_SK_BYTES];
    /* A valid ciphertext under kem_pk/kem_sk (class A of the decap test). */
    uint8_t valid_ct[SYNDROME_CT_BYTES];
} g_key;

static void
expand_h(uint64_t *h, const uint16_t *cols)
{
    uint8_t buf[SYNDROME_BLOCK_BYTES];
    uint32_t idx[SYNDROME_V];
    uint32_t i;

    for (i = 0; i < (uint32_t)SYNDROME_V; i++)
        idx[i] = cols[i];
    syndrome_sample_scatter(buf, sizeof(buf), idx, (uint32_t)SYNDROME_V,
                            (uint32_t)SYNDROME_P);
    syndrome_gf2x_load(h, buf);
}

static void
ensure_key(void)
{
    syndrome_drbg rng;
    uint8_t seed[48];
    uint8_t throwaway_k[SYNDROME_SS_BYTES];
    uint32_t b;

    if (g_key.ready)
        return;

    /* PKE key (fixed seed) -> qsk + dense H blocks. */
    memset(seed, 0x01, sizeof(seed));
    syndrome_drbg_init(&rng, seed);
    syndrome_pke_keygen(&g_key.qsk, g_key.pke_pk, &rng);
    syndrome_drbg_clear(&rng);
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        expand_h(g_key.h[b], g_key.qsk.cols[b]);

    /* KEM key (fixed seed) -> serialized pk/sk. */
    memset(seed, 0x02, sizeof(seed));
    syndrome_drbg_init(&rng, seed);
    syndrome_kem_keypair_derand(g_key.kem_pk, g_key.kem_sk, &rng);
    syndrome_drbg_clear(&rng);

    /* A second, independent KEM secret key (distinct fixed seed) for the two
     * classes of the pubkey_from_sk timing test.  pk is not needed. */
    {
        uint8_t throwaway_pk[SYNDROME_PK_BYTES];

        memset(seed, 0x04, sizeof(seed));
        syndrome_drbg_init(&rng, seed);
        syndrome_kem_keypair_derand(throwaway_pk, g_key.kem_sk_b, &rng);
        syndrome_drbg_clear(&rng);
    }

    /* A valid ciphertext for the decap test's accepting class. */
    memset(seed, 0x03, sizeof(seed));
    syndrome_drbg_init(&rng, seed);
    syndrome_kem_encap_derand(g_key.valid_ct, throwaway_k, g_key.kem_pk, &rng);
    syndrome_drbg_clear(&rng);

    g_key.ready = 1;
}

/* ---- sample_fixed_weight --------------------------------------------- */

typedef struct {
    uint8_t seed[48];
} seed_state_t;

static void
sample_setup(int cls, void *state)
{
    seed_state_t *s = (seed_state_t *)state;
    /* Two distinct (but fixed) RNG streams -> two distinct error supports. */
    memset(s->seed, cls ? 0xFF : 0x00, sizeof(s->seed));
}

static void
sample_run(const void *state)
{
    const seed_state_t *s = (const seed_state_t *)state;
    syndrome_drbg rng;
    uint32_t idx[SYNDROME_T];

    syndrome_drbg_init(&rng, s->seed);
    (void)syndrome_sample_fixed_weight(idx, (uint32_t)SYNDROME_T,
                                       (uint32_t)SYNDROME_N, &rng);
    syndrome_target_sink ^= (uint8_t)idx[0];
    syndrome_drbg_clear(&rng);
}

const dudect_target_t target_sample_fixed_weight = {
    .name = "sample_fixed_weight",
    .setup_class = sample_setup,
    .run = sample_run,
    .state_size = sizeof(seed_state_t),
    .reps_per_trial = 1,
};

/* ---- bitflip_decode -------------------------------------------------- */

typedef struct {
    uint64_t sp[SYNDROME_GF2X_LIMBS]; /* private syndrome s' = h_{n0-1}*s */
} decode_state_t;

static void
decode_setup(int cls, void *state)
{
    decode_state_t *st = (decode_state_t *)state;
    syndrome_drbg rng;
    uint8_t seed[48];
    uint32_t eidx[SYNDROME_T];
    uint32_t idx_b[SYNDROME_T];
    uint8_t eb[SYNDROME_BLOCK_BYTES];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t s[SYNDROME_GF2X_LIMBS];
    uint8_t ct[SYNDROME_CT_BYTES];
    uint32_t i, b;

    ensure_key();

    /* Two distinct weight-t errors -> two distinct private syndromes. */
    memset(seed, cls ? 0xC3 : 0x3C, sizeof(seed));
    syndrome_drbg_init(&rng, seed);
    syndrome_sample_fixed_weight(eidx, (uint32_t)SYNDROME_T,
                                 (uint32_t)SYNDROME_N, &rng);
    syndrome_drbg_clear(&rng);

    /* Split the global support into the n0 per-block error vectors (the F1
     * idiom: block b is addressed by subtracting b*p; out-of-range indices
     * never match a position, so each scatter sees only its own block).
     */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
        uint32_t base = b * (uint32_t)SYNDROME_P;

        for (i = 0; i < (uint32_t)SYNDROME_T; i++)
            idx_b[i] = eidx[i] - base;
        syndrome_sample_scatter(eb, sizeof(eb), idx_b, (uint32_t)SYNDROME_T,
                                (uint32_t)SYNDROME_P);
        syndrome_gf2x_load(e[b], eb);
    }

    /* s = M*e^T, then the private syndrome s' = h_{n0-1}*s the decoder consumes. */
    syndrome_pke_encrypt(ct, g_key.pke_pk, e);
    syndrome_gf2x_load(s, ct);
    syndrome_synmap_private(st->sp, g_key.h[SYNDROME_N0 - 1], s);
}

static void
decode_run(const void *state)
{
    const decode_state_t *st = (const decode_state_t *)state;
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint8_t acc;
    uint32_t b;
    int ok = 0;

    syndrome_bitflip_decode(r, &ok, g_key.h, g_key.qsk.cols, st->sp);
    acc = (uint8_t)ok;
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        acc ^= (uint8_t)r[b][0];
    syndrome_target_sink ^= acc;
}

const dudect_target_t target_bitflip_decode = {
    .name = "bitflip_decode",
    .setup_class = decode_setup,
    .run = decode_run,
    .state_size = sizeof(decode_state_t),
    .reps_per_trial = 1,
};

/* ---- kem_encap ------------------------------------------------------- */

static void
encap_setup(int cls, void *state)
{
    seed_state_t *s = (seed_state_t *)state;
    ensure_key();
    /* Two RNG streams -> two fresh weight-t errors (F1 path). */
    memset(s->seed, cls ? 0xFF : 0x00, sizeof(s->seed));
}

static void
encap_run(const void *state)
{
    const seed_state_t *s = (const seed_state_t *)state;
    syndrome_drbg rng;
    uint8_t ct[SYNDROME_CT_BYTES];
    uint8_t k[SYNDROME_SS_BYTES];

    syndrome_drbg_init(&rng, s->seed);
    (void)syndrome_kem_encap_derand(ct, k, g_key.kem_pk, &rng);
    syndrome_target_sink ^= (uint8_t)(ct[0] ^ k[0]);
    syndrome_drbg_clear(&rng);
}

const dudect_target_t target_kem_encap = {
    .name = "kem_encap",
    .setup_class = encap_setup,
    .run = encap_run,
    .state_size = sizeof(seed_state_t),
    .reps_per_trial = 1,
};

/* ---- kem_decap ------------------------------------------------------- */

typedef struct {
    uint8_t ct[SYNDROME_CT_BYTES];
} ct_state_t;

static void
decap_setup(int cls, void *state)
{
    ct_state_t *st = (ct_state_t *)state;

    ensure_key();
    memcpy(st->ct, g_key.valid_ct, sizeof(st->ct));
    if (cls) {
        /* Tamper a data bit so this ciphertext fails to decode and routes
         * through implicit rejection.  Must be timing-indistinguishable
         * from the accepting class above.
         */
        st->ct[0] ^= 0x01;
    }
}

static void
decap_run(const void *state)
{
    const ct_state_t *st = (const ct_state_t *)state;
    uint8_t k[SYNDROME_SS_BYTES];

    (void)syndrome_kem_decap_impl(k, st->ct, g_key.kem_sk);
    syndrome_target_sink ^= k[0];
}

const dudect_target_t target_kem_decap = {
    .name = "kem_decap",
    .setup_class = decap_setup,
    .run = decap_run,
    .state_size = sizeof(ct_state_t),
    .reps_per_trial = 1,
};

/* ---- argus_tail (post-decode Argus work, decoder excluded) ----------- */
/*
 * The decoder inside argus_open has its own target (bitflip_decode) and its
 * gf2x/sample primitives are dudect-gated in libtalos_ichor, so measuring the
 * full open re-times the decoder and buries the tail in its variance.  This
 * target exercises ONLY argus_tail: extract_indices + KDF + OTP + the masked
 * write + the branchless status.  Both classes use a PRODUCIBLE input, a real
 * weight-t error (what the decoder always yields), and differ in the two
 * dimensions a real open must keep timing-independent: the secret support (two
 * distinct fixed draws) and the openable mask (class 0 vmask all-ones, class 1
 * vmask zero).  Neither may move the timing; the tail is fixed-work by
 * construction.  An earlier class 1 used a dense random block (~n/2 set bits),
 * an input the decoder can never produce; on a small-footprint set (AES-DM KDF,
 * lambda 128) that impossible weight difference registered as a large |t|
 * through otherwise branch-free code.  The decode that would produce eb runs in
 * setup (untimed), never in the measured path.
 */
typedef struct {
    uint8_t eb[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint8_t dem[SYNDROME_ARGUS_KEY_BYTES];
    uint32_t vmask;
} tail_state_t;

static void
argus_tail_setup(int cls, void *state)
{
    tail_state_t *st = (tail_state_t *)state;
    syndrome_drbg rng;
    uint8_t seed[48];
    uint32_t eidx[SYNDROME_T];
    uint32_t b, k;

    /* Distinct fixed seed per class -> a distinct fixed weight-t support. */
    memset(seed, cls ? 0x3c : 0xc3, sizeof(seed));
    syndrome_drbg_init(&rng, seed);

    /* Both classes: a producible weight-t error scattered into the n0 blocks. */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(st->eb[b], 0, SYNDROME_BLOCK_BYTES);
    (void)syndrome_sample_fixed_weight(eidx, (uint32_t)SYNDROME_T,
                                       (uint32_t)SYNDROME_N, &rng);
    for (k = 0; k < (uint32_t)SYNDROME_T; k++) {
        uint32_t blk = eidx[k] / (uint32_t)SYNDROME_P;
        uint32_t pos = eidx[k] % (uint32_t)SYNDROME_P;

        st->eb[blk][pos >> 3] |= (uint8_t)(1u << (pos & 7u));
    }

    /* Class 0 openable (mask all-ones), class 1 unopenable (mask zero). */
    st->vmask = cls ? 0u : 0xFFFFFFFFu;

    (void)syndrome_drbg_generate(&rng, st->dem, sizeof(st->dem));
    syndrome_drbg_clear(&rng);
}

static void
argus_tail_run(const void *state)
{
    const tail_state_t *st = (const tail_state_t *)state;
    uint8_t out[SYNDROME_ARGUS_KEY_BYTES];

    (void)argus_tail(out, SYNDROME_ARGUS_KEY_BYTES, st->dem, st->eb, st->vmask);
    syndrome_target_sink ^= out[0];
}

const dudect_target_t target_argus_tail = {
    .name = "argus_tail",
    .setup_class = argus_tail_setup,
    .run = argus_tail_run,
    .state_size = sizeof(tail_state_t),
    .reps_per_trial = 1,
};

/* ---- argus_tail_weight (off-weight residual axis) -------------------- */
/*
 * Companion to argus_tail: the same tail (extract_indices + KDF + OTP + masked
 * write + branchless status), but the unopenable class feeds an off-weight
 * sparse error (weight != t) instead of a second weight-t draw.  This adds the
 * residual-weight axis on top of argus_tail's openable-bit and support-position
 * axes: extract_indices scans every position and writes all T slots regardless
 * of how many bits are set, so the tail must run in identical time whether the
 * error has weight t (a successful open) or an off-weight residual (the sparse,
 * bounded shape a rejected or partly-decoded tag leaves).  A random-syndrome
 * decode was deliberately not used to source the residual: that leaves a DENSE
 * (~n/2) block, an input the bounded decoder never yields on a near miss and the
 * same non-producible pitfall argus_tail's note describes.  Class 0 is the
 * openable weight-t case (vmask all-ones); class 1 is the off-weight (7t/8)
 * unopenable case (vmask zero); both supports are producible sparse errors.
 */
static void
argus_tail_weight_setup(int cls, void *state)
{
    tail_state_t *st = (tail_state_t *)state;
    syndrome_drbg rng;
    uint8_t seed[48];
    uint32_t eidx[SYNDROME_T];
    uint32_t w = cls ? ((uint32_t)SYNDROME_T * 7u / 8u) : (uint32_t)SYNDROME_T;
    uint32_t b, k;

    /* Distinct fixed seed per class -> a distinct fixed support. */
    memset(seed, cls ? 0x5a : 0xa5, sizeof(seed));
    syndrome_drbg_init(&rng, seed);

    /* Class 0: producible weight-t error.  Class 1: producible off-weight
     * (7t/8) sparse error, scattered into the n0 blocks the same way. */
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(st->eb[b], 0, SYNDROME_BLOCK_BYTES);
    (void)syndrome_sample_fixed_weight(eidx, w, (uint32_t)SYNDROME_N, &rng);
    for (k = 0; k < w; k++) {
        uint32_t blk = eidx[k] / (uint32_t)SYNDROME_P;
        uint32_t pos = eidx[k] % (uint32_t)SYNDROME_P;

        st->eb[blk][pos >> 3] |= (uint8_t)(1u << (pos & 7u));
    }

    /* Class 0 openable (mask all-ones), class 1 unopenable (mask zero). */
    st->vmask = cls ? 0u : 0xFFFFFFFFu;

    (void)syndrome_drbg_generate(&rng, st->dem, sizeof(st->dem));
    syndrome_drbg_clear(&rng);
}

const dudect_target_t target_argus_tail_weight = {
    .name = "argus_tail_weight",
    .setup_class = argus_tail_weight_setup,
    .run = argus_tail_run,
    .state_size = sizeof(tail_state_t),
    .reps_per_trial = 1,
};

/* ---- pubkey_from_sk -------------------------------------------------- *
 * The Proteus seed API's public-key recovery (M_b = H_{n0-1}^{-1} H_b) runs on
 * the secret sk: deserialize + validate the H index lists, expand the blocks,
 * invert the last, re-derive M.  For a well-formed key the index-validity check
 * never branches, so recovery must run in identical time for any secret key.
 * (keypair_from_seed / keep_seed are NOT dudect targets: they run the keygen
 * H_1-resample loop, which is intentionally variable-time -- DESIGN.md §5 --
 * the same reason there is no plain keypair target.)
 */
typedef struct {
    uint8_t sk[SYNDROME_SK_BYTES];
} sk_state_t;

static void
pubkey_setup(int cls, void *state)
{
    sk_state_t *st = (sk_state_t *)state;

    ensure_key();
    /* Two distinct secret keys; recomputing M must take the same time for
     * either.  Copy so the timed call reads only from the per-trial state. */
    memcpy(st->sk, cls ? g_key.kem_sk_b : g_key.kem_sk, sizeof(st->sk));
}

static void
pubkey_run(const void *state)
{
    const sk_state_t *st = (const sk_state_t *)state;
    uint8_t pk[SYNDROME_PK_BYTES];

    (void)syndrome_kem_pubkey_from_sk_impl(pk, st->sk);
    syndrome_target_sink ^= pk[0];
}

const dudect_target_t target_pubkey_from_sk = {
    .name = "pubkey_from_sk",
    .setup_class = pubkey_setup,
    .run = pubkey_run,
    .state_size = sizeof(sk_state_t),
    .reps_per_trial = 1,
};
