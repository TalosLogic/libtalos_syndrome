/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_dfr_probe.c - real-p PKE round-trip failure dissector.
 *
 * Diagnostic for the intermittent honest-round-trip failure (decap K != encap K
 * ~1/64 in test_kem).  Unlike test_dfr_mc, which validates the decoder against
 * the closed-form model at a REDUCED waterfall p and forms the private syndrome
 * sp = sum_b h[b]*e[b] DIRECTLY, this harness runs the full PKE round-trip at
 * the set's REAL p: keygen -> sample weight-t e -> pke_encrypt (public M via
 * synmap_encode) -> the decrypt path (synmap_private -> production decoder).  So
 * it also exercises the ct formation and the ct->sp map that test_dfr_mc skips.
 *
 * On each round-trip failure it classifies the layer, so one run says where the
 * fault is (all four are mutually exclusive except the undetected tally, which
 * is orthogonal):
 *   - synmap mismatch (sp != sum_b h[b]*e[b])  => ct formation / ct->sp map bug
 *   - production decode fails AND dense fails   => intrinsic DFR / error floor
 *                                                  (the algorithm, not this code)
 *   - production fails but the dense oracle     => production decoder bug
 *     (compute_flip_dense) recovers e              (large-p path divergence)
 *   - ok == 1 but recovered e != sampled e      => undetected miscorrection
 *
 * This is a PKE-level probe: it does not exercise the KEM FO / accept_kdf layer.
 * At the real p the model DFR is ~2^-lambda, so a correct decoder+map yields
 * ZERO failures however long it runs -- which itself would point the finger at
 * the FO/K-derivation layer above the PKE round-trip.  An OBSERVABLE failure
 * rate here localizes the bug via the breakdown.
 *
 * Test-only; force-includes the per-set bodies; non-constant-time by design (it
 * inspects failures).  No gate: it reports an empirical real-p DFR and the
 * classification breakdown and exits 0.  Threading mirrors test_dfr_mc: trials
 * are partitioned by per-key batch, and each batch's seed is a pure function of
 * its index, so the outcome is independent of the thread count.
 *
 * Usage: test_dfr_probe [trials [trials_per_key [threads]]]
 * Defaults: 100000 trials, 1000 trials/key, threads = online CPU count (or the
 * SYNDROME_DFR_THREADS env var; threads=1 is the serial path).
 */
#define _POSIX_C_SOURCE 200809L

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core.h"
#include "decoder.h"

#define PROBE_DEFAULT_TRIALS 100000ul
#define PROBE_DEFAULT_TRIALS_PER_KEY 1000ul

/* Failure classes, for the first-failure capture. */
enum {
    PROBE_CLASS_SYNMAP =
        0,                /* ct<->sp map produced the wrong private syndrome */
    PROBE_CLASS_BOTH = 1, /* production and dense both fail: intrinsic DFR    */
    PROBE_CLASS_PRODBUG =
        2 /* production fails, dense recovers e: decoder bug  */
};

static void make_seed(uint8_t[48], uint32_t);
static int sample_error(uint64_t (*)[SYNDROME_GF2X_LIMBS], syndrome_drbg *);
static void dense_decode(uint64_t (*)[SYNDROME_GF2X_LIMBS], int *,
                         const uint64_t (*)[SYNDROME_GF2X_LIMBS],
                         const uint64_t *);

/*
 * Deterministic per-key-batch seed: the house byte ramp with the batch counter
 * and the real p folded in, so every batch (and every set) draws an independent
 * reproducible stream and a caught failure can be replayed from its batch index.
 */
static void
make_seed(uint8_t seed[48], uint32_t batch)
{
    int i;

    for (i = 0; i < 48; i++)
        seed[i] = (uint8_t)i;
    seed[0] = (uint8_t)(batch & 0xffu);
    seed[1] = (uint8_t)((batch >> 8) & 0xffu);
    seed[2] = (uint8_t)((batch >> 16) & 0xffu);
    seed[3] = (uint8_t)((batch >> 24) & 0xffu);
    seed[4] = (uint8_t)(SYNDROME_P & 0xffu);
    seed[5] = (uint8_t)((SYNDROME_P >> 8) & 0xffu);
}

/*
 * Sample a weight-t error over n = n0*p through the production sampler and split
 * it into the n0 dense blocks: index j lands in block j/p at position j%p.  Non
 * oblivious bit-set (test code measuring failure rates, not a CT path).
 */
static int
sample_error(uint64_t e[][SYNDROME_GF2X_LIMBS], syndrome_drbg *rng)
{
    uint8_t ebuf[SYNDROME_N0][SYNDROME_BLOCK_BYTES];
    uint32_t eidx[SYNDROME_T];
    uint32_t i, b;

    if (syndrome_sample_fixed_weight(eidx, SYNDROME_T, SYNDROME_N, rng) != 0)
        return -1;

    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(ebuf[b], 0, SYNDROME_BLOCK_BYTES);
    for (i = 0; i < (uint32_t)SYNDROME_T; i++) {
        uint32_t j = eidx[i];
        uint32_t blk = j / (uint32_t)SYNDROME_P;
        uint32_t pos = j % (uint32_t)SYNDROME_P;

        ebuf[blk][pos >> 3] |= (uint8_t)(1u << (pos & 7u));
    }
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        syndrome_gf2x_load(e[b], ebuf[b]);
    return 0;
}

/*
 * Dense-oracle full decode: the same fixed 3-iteration bit-flip algorithm as the
 * production decoder, but using the dense popcount compute_flip_dense (the
 * independent reference the diff self-test pins the production path against).
 * So a failure that the production path shows and the dense path does not is a
 * production bug; a failure both show is a property of the algorithm (intrinsic
 * DFR), not of this implementation.
 */
static void
dense_decode(uint64_t r[][SYNDROME_GF2X_LIMBS], int *ok,
             const uint64_t h[][SYNDROME_GF2X_LIMBS], const uint64_t *sp)
{
    uint64_t s[SYNDROME_GF2X_LIMBS];
    uint64_t flip[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t tmp[SYNDROME_GF2X_LIMBS];
    unsigned it;
    uint32_t b;

    memcpy(s, sp, sizeof(s));
    for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
        memset(r[b], 0, SYNDROME_GF2X_LIMBS * sizeof(uint64_t));

    for (it = 1; it <= SYNDROME_ITERMAX; it++) {
        unsigned th = syndrome_threshold(it);

        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            compute_flip_dense(flip[b], s, h[b], th);
        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            syndrome_gf2x_add(r[b], r[b], flip[b]);
        for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
            syndrome_gf2x_mul(tmp, h[b], flip[b]);
            syndrome_gf2x_add(s, s, tmp);
        }
    }
    *ok = ct_is_zero(s);
}

/*
 * Per-thread work item: run the batches [batch_lo, batch_hi) and accumulate a
 * local tally.  Each batch keygens once (amortized over per_key trials) and runs
 * min(per_key, trials - base) round-trips under make_seed(batch), so the
 * batch->trials mapping, and therefore the outcome, is independent of how the
 * batches are partitioned across threads.  All scratch is thread-local.
 */
typedef struct {
    unsigned long batch_lo;
    unsigned long batch_hi;
    unsigned long per_key;
    unsigned long trials;
    unsigned long done;
    unsigned long failures;
    unsigned long synmap_fail;
    unsigned long both_fail;
    unsigned long prod_bug;
    unsigned long undetected;
    int error;
    /* First caught failure, for reproduction / a quick look. */
    int have_fail;
    int fail_class;
    int fail_ok;
    int fail_ok_dense;
    unsigned long fail_batch;
    unsigned long fail_trial;
} probe_ctx;

static void *
probe_worker(void *arg)
{
    probe_ctx *ctx = arg;
    syndrome_qcmdpc_sk sk;
    uint8_t pk[SYNDROME_PK_BYTES];
    uint8_t ct[SYNDROME_CT_BYTES];
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t rd[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t spub[SYNDROME_GF2X_LIMBS];
    uint64_t sp[SYNDROME_GF2X_LIMBS];
    uint64_t spi[SYNDROME_GF2X_LIMBS];
    uint64_t tmp[SYNDROME_GF2X_LIMBS];
    syndrome_drbg rng;
    uint8_t seed[48];
    unsigned long batch, i, cnt, base;
    uint32_t b;
    int ok, ok_dense;

    for (batch = ctx->batch_lo; batch < ctx->batch_hi; batch++) {
        base = batch * ctx->per_key;
        if (base >= ctx->trials)
            break;
        cnt = ctx->trials - base;
        if (cnt > ctx->per_key)
            cnt = ctx->per_key;

        make_seed(seed, (uint32_t)batch);
        syndrome_drbg_init(&rng, seed);

        if (syndrome_pke_keygen(&sk, pk, &rng) != 0) {
            ctx->error = 1;
            return NULL;
        }
        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            expand_block(h[b], sk.cols[b]);

        for (i = 0; i < cnt; i++, ctx->done++) {
            int mismatch, dense_match, cls;

            if (sample_error(e, &rng) != 0) {
                ctx->error = 1;
                return NULL;
            }

            /* Encrypt through the public key, then run the decrypt path open:
             * ct -> public syndrome -> private syndrome sp -> production decode. */
            syndrome_pke_encrypt(ct, pk, e);
            syndrome_gf2x_load(spub, ct);
            syndrome_synmap_private(sp, h[SYNDROME_N0 - 1], spub);
            syndrome_bitflip_decode(r, &ok, h, sk.cols, sp);

            mismatch = 0;
            for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
                if (memcmp(r[b], e[b], sizeof(r[b])) != 0)
                    mismatch = 1;
            if (!mismatch)
                continue;

            ctx->failures++;
            if (ok == 1)
                ctx->undetected++; /* zeroed the syndrome with the wrong e */

            /* (1) ct<->sp map: sp must equal the ideal private syndrome. */
            memset(spi, 0, sizeof(spi));
            for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
                syndrome_gf2x_mul(tmp, h[b], e[b]);
                syndrome_gf2x_add(spi, spi, tmp);
            }
            if (memcmp(sp, spi, sizeof(sp)) != 0) {
                ctx->synmap_fail++;
                cls = PROBE_CLASS_SYNMAP;
                ok_dense = -1;
            } else {
                /* (2) dense oracle on the SAME private syndrome. */
                dense_decode(rd, &ok_dense, h, sp);
                dense_match = 1;
                for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
                    if (memcmp(rd[b], e[b], sizeof(rd[b])) != 0)
                        dense_match = 0;
                if (dense_match) {
                    ctx->prod_bug++;
                    cls = PROBE_CLASS_PRODBUG;
                } else {
                    ctx->both_fail++;
                    cls = PROBE_CLASS_BOTH;
                }
            }

            if (!ctx->have_fail) {
                ctx->have_fail = 1;
                ctx->fail_class = cls;
                ctx->fail_ok = ok;
                ctx->fail_ok_dense = ok_dense;
                ctx->fail_batch = batch;
                ctx->fail_trial = i;
            }
        }
    }
    return NULL;
}

int
main(int argc, char **argv)
{
    struct timespec ts_start, ts_now;
    probe_ctx *ctx;
    pthread_t *threads;
    unsigned long trials, per_key, nthreads, nbatches, lo;
    unsigned long done, failures, synmap_fail, both_fail, prod_bug, undetected;
    double phat, elapsed;
    long online;
    const char *env;
    unsigned long t;
    int any_error, first_class, first_ok, first_ok_dense;
    unsigned long first_batch, first_trial;
    int have_first;

    trials = PROBE_DEFAULT_TRIALS;
    per_key = PROBE_DEFAULT_TRIALS_PER_KEY;
    nthreads = 0;
    if (argc >= 2) {
        trials = strtoul(argv[1], NULL, 10);
        if (trials == 0) {
            fprintf(stderr, "usage: %s [trials [trials_per_key [threads]]]\n",
                    argv[0]);
            return 1;
        }
    }
    if (argc >= 3) {
        per_key = strtoul(argv[2], NULL, 10);
        if (per_key == 0) {
            fprintf(stderr, "usage: %s [trials [trials_per_key [threads]]]\n",
                    argv[0]);
            return 1;
        }
    }
    if (argc >= 4)
        nthreads = strtoul(argv[3], NULL, 10);

    if (nthreads == 0) {
        env = getenv("SYNDROME_DFR_THREADS");
        if (env != NULL)
            nthreads = strtoul(env, NULL, 10);
    }
    if (nthreads == 0) {
        online = sysconf(_SC_NPROCESSORS_ONLN);
        nthreads = (online > 0) ? (unsigned long)online : 1ul;
    }

    nbatches = (trials + per_key - 1) / per_key;
    if (nthreads > nbatches)
        nthreads = nbatches;
    if (nthreads == 0)
        nthreads = 1;

    printf("dfr_probe: lambda=%d n0=%d p=%d v=%d t=%d th=%u/%u/%u (REAL p) "
           "trials=%lu trials_per_key=%lu threads=%lu\n",
           SYNDROME_LAMBDA, SYNDROME_N0, SYNDROME_P, SYNDROME_V, SYNDROME_T,
           syndrome_threshold(1), syndrome_threshold(2), syndrome_threshold(3),
           trials, per_key, nthreads);

    /* Warm ichor's clmul dispatch before spawning (avoid a first-call race on
     * the atomic init; harmless if already resolved). */
    {
        uint64_t wa[SYNDROME_GF2X_LIMBS] = {0};
        uint64_t wb[SYNDROME_GF2X_LIMBS];

        syndrome_gf2x_mul(wb, wa, wa);
    }

    ctx = calloc(nthreads, sizeof(*ctx));
    threads = calloc(nthreads, sizeof(*threads));
    if (ctx == NULL || threads == NULL) {
        fprintf(stderr, "dfr_probe: out of memory\n");
        free(ctx);
        free(threads);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    lo = 0;
    for (t = 0; t < nthreads; t++) {
        unsigned long span = nbatches / nthreads + (t < nbatches % nthreads);

        ctx[t].batch_lo = lo;
        ctx[t].batch_hi = lo + span;
        ctx[t].per_key = per_key;
        ctx[t].trials = trials;
        lo += span;
        if (pthread_create(&threads[t], NULL, probe_worker, &ctx[t]) != 0) {
            fprintf(stderr, "dfr_probe: pthread_create failed\n");
            while (t-- > 0)
                pthread_join(threads[t], NULL);
            free(ctx);
            free(threads);
            return 1;
        }
    }

    done = failures = synmap_fail = both_fail = prod_bug = undetected = 0;
    any_error = 0;
    have_first = 0;
    first_class = first_ok = first_ok_dense = 0;
    first_batch = first_trial = 0;
    for (t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
        done += ctx[t].done;
        failures += ctx[t].failures;
        synmap_fail += ctx[t].synmap_fail;
        both_fail += ctx[t].both_fail;
        prod_bug += ctx[t].prod_bug;
        undetected += ctx[t].undetected;
        any_error |= ctx[t].error;
        if (ctx[t].have_fail && !have_first) {
            have_first = 1;
            first_class = ctx[t].fail_class;
            first_ok = ctx[t].fail_ok;
            first_ok_dense = ctx[t].fail_ok_dense;
            first_batch = ctx[t].fail_batch;
            first_trial = ctx[t].fail_trial;
        }
    }

    free(ctx);
    free(threads);

    if (any_error) {
        fprintf(stderr, "dfr_probe: sampling/keygen failed\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    elapsed = (double)(ts_now.tv_sec - ts_start.tv_sec) +
              (double)(ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;

    phat = (double)failures / (double)done;
    printf("dfr_probe: %lu round-trips, %lu failures, %.1f s (%.0f trips/s)\n",
           done, failures, elapsed,
           elapsed > 0.0 ? (double)done / elapsed : 0.0);
    if (failures > 0)
        printf("dfr_probe: empirical real-p DFR = %.6e (2^%.2f)\n", phat,
               log2(phat));
    else
        printf("dfr_probe: empirical real-p DFR = 0 over %lu round-trips\n",
               done);
    printf(
        "dfr_probe: breakdown: synmap-map-bug=%lu  intrinsic(both fail)=%lu  "
        "production-decoder-bug=%lu  undetected-miscorrection=%lu\n",
        synmap_fail, both_fail, prod_bug, undetected);

    if (have_first)
        printf("dfr_probe: first failure: class=%s ok=%d ok_dense=%d "
               "batch=%lu trial=%lu (replay: seed from this batch index)\n",
               first_class == PROBE_CLASS_SYNMAP    ? "synmap-map-bug"
               : first_class == PROBE_CLASS_PRODBUG ? "production-decoder-bug"
                                                    : "intrinsic",
               first_ok, first_ok_dense, first_batch, first_trial);

    /* Verdict (diagnostic; always exits 0). */
    if (failures == 0)
        printf(
            "dfr_probe: VERDICT: no PKE-level failure seen; if test_kem still "
            "fails, the fault is in the KEM FO / accept_kdf layer above this "
            "probe.\n");
    else if (synmap_fail > 0)
        printf(
            "dfr_probe: VERDICT: ct<->sp map bug (synmap_encode/private).\n");
    else if (prod_bug > 0)
        printf(
            "dfr_probe: VERDICT: production decoder bug (dense oracle recovers "
            "e where the production path does not).\n");
    else
        printf(
            "dfr_probe: VERDICT: intrinsic DFR / error floor at real p (both "
            "the production and dense decoders fail on the same honest "
            "error); a cryptographic parameter finding, not a code bug.\n");

    return 0;
}
