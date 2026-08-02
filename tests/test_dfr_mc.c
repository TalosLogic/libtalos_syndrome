/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_dfr_mc.c - statistical (Monte-Carlo) DFR validation against the
 * closed-form model of ePrint 2025/1043 (docs/DESIGN.md §3.2;
 * docs/TESTING.md).
 *
 * Compiles the core and decoder sources directly with a reduced block size
 * p (SYNDROME_TESTONLY_WATERFALL_P) in the measurable-DFR waterfall regime,
 * keeping the set's own v, t and pinned thresholds, which is the paper's own
 * validation setup (Fig. 8a).  Each trial samples a fresh weight-t error
 * through the production sampler, computes the private syndrome
 * s = sum_b h[b]*e[b] over the n0 blocks, and runs the production decoder; the
 * key H is resampled every trials_per_key trials so the run averages over keys
 * as the DFR bound does.  The public systematic form M is never needed: the DFR
 * is a property of (H, e) and the decoder alone.  The harness is n0-generic
 * (runs for the n0=2 and n0=5 sets); the (lambda, n0) it validates comes from
 * the force-included bodies plus the reduced p.
 *
 * Failure criterion (matches the model): the recovered error differs from
 * the sampled one.  A residual-zero decode of the wrong error (an undetected
 * miscorrection) counts as a failure and is also reported separately.
 *
 * Acceptance: FAIL only if the one-sided 99% lower confidence bound on the
 * empirical DFR exceeds the model prediction, i.e. this implementation
 * fails significantly MORE often than the model says it should, which would
 * mean the closed-form bound does not transfer to this decoder.  An
 * empirical rate below the model is consistent with the model's designed
 * conservatism and passes.
 *
 * Usage: test_dfr_mc [trials [trials_per_key [threads]]]
 * Defaults: 10000 trials, 1000 trials per key, threads = online CPU count
 * (override also via the SYNDROME_DFR_THREADS environment variable; threads=1
 * is the serial path).  SYNDROME_DFR_TRIALS, when set, caps the trial count
 * regardless of the argument (for constrained CI runs such as the sanitize
 * pipeline, which must run every test but cheaply).  The trials are partitioned
 * by per-key batch across
 * worker threads; because each batch's DRBG seed is a pure function of its batch
 * index, the result (failure count, gate decision) is bit-identical regardless
 * of the thread count.
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

#ifndef SYNDROME_TESTONLY_WATERFALL_P
#error "test_dfr_mc must be compiled with -DSYNDROME_TESTONLY_WATERFALL_P=<p>"
#endif

/*
 * Model predictions, pinned per (n0, p) test point.  Each value is the DFR
 * column of the authors' closed-form model tool (ePrint 2025/1043 companion,
 * model_DFR_3it, in third_party/model_DFR_3it; see docs/DESIGN.md section 4.2
 * for provenance), run at the set's own (v, t, thresholds) as:
 *
 *   ./model_DFR <n0> <p> <v> <t> 1 <th1> <th2> <th3> 1
 *
 * n0=2 captured 2026-07-10; n0=5 captured 2026-07-19.  Every p here is prime
 * with ord_p(2) = p - 1, the same side condition the shipped sets satisfy.  To
 * add a test point: pick such a prime, run the model at the set's v/t/thresholds,
 * and pin its DFR value under the matching n0.
 */
#if SYNDROME_N0 == 2
/* v=69 t=130 th=41/35/35: ./model_DFR 2 <p> 69 130 1 41 35 35 1 */
#if SYNDROME_P == 10909
#define DFR_MODEL 1.25857969e-02 /* 2^-6.31 */
#elif SYNDROME_P == 10949
#define DFR_MODEL 8.17432152e-03 /* 2^-6.93 */
#elif SYNDROME_P == 11003
#define DFR_MODEL 4.39839743e-03 /* 2^-7.83 */
#elif SYNDROME_P == 11131
#define DFR_MODEL 8.48039041e-04 /* 2^-10.20 */
#elif SYNDROME_P == 11171
#define DFR_MODEL 4.80684688e-04 /* 2^-11.02 */
#elif SYNDROME_P == 11437
#define DFR_MODEL 5.65332514e-06 /* 2^-17.43 */
#else
#error                                                                         \
    "no pinned n0=2 model prediction for this p; run model_DFR and pin it here"
#endif

#elif SYNDROME_N0 == 5
#if SYNDROME_LAMBDA == 128
/* v=83 t=57 th=49/42/42: ./model_DFR 5 <p> 83 57 1 49 42 42 1 */
#if SYNDROME_P == 6053
#define DFR_MODEL 1.01027829e-02 /* 2^-6.63 (shallow wired gate) */
#elif SYNDROME_P == 6163
#define DFR_MODEL 1.65762357e-03 /* 2^-9.24 */
#elif SYNDROME_P == 6221
#define DFR_MODEL 5.97443855e-04 /* 2^-10.71 */
#elif SYNDROME_P == 6299
#define DFR_MODEL 1.16092546e-04 /* 2^-13.07 */
#else
#error "no pinned n0=5 lambda-128 model prediction for this p; run model_DFR"
#endif
#elif SYNDROME_LAMBDA == 256
/* v=165 t=113 th=93/85/84: ./model_DFR 5 <p> 165 113 1 93 85 84 1 */
#if SYNDROME_P == 19603
#define DFR_MODEL 1.45288888e-02 /* 2^-6.10 */
#elif SYNDROME_P == 19717
#define DFR_MODEL 6.96591424e-03 /* 2^-7.17 */
#elif SYNDROME_P == 19949
#define DFR_MODEL 1.16294563e-03 /* 2^-9.75 */
#else
#error "no pinned n0=5 lambda-256 model prediction for this p; run model_DFR"
#endif
#else
#error "no n0=5 waterfall test points for this lambda"
#endif

#else
#error "test_dfr_mc has no model-prediction table for this n0"
#endif

#define DFR_DEFAULT_TRIALS 10000ul
#define DFR_DEFAULT_TRIALS_PER_KEY 1000ul

/* One-sided 99% standard-normal quantile, for the Wilson score bound. */
#define DFR_Z99 2.3263478740

static void make_seed(uint8_t[48], uint32_t);
static int sample_h_block(uint64_t *, uint16_t *, syndrome_drbg *);
static int sample_error(uint64_t (*)[SYNDROME_GF2X_LIMBS], syndrome_drbg *);
static double wilson_lower(double, double);

/*
 * Deterministic per-key-batch seed: the house fixed byte ramp, with the
 * batch counter and the test-point p folded into the first bytes so every
 * batch, and every test point, draws an independent reproducible stream.
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
 * Sample one weight-v private H block as a dense ring element, through the
 * production fixed-weight sampler and oblivious scatter.  Invertibility is
 * irrelevant here (the public key is never formed), so unlike keygen there
 * is no resample loop.
 */
static int
sample_h_block(uint64_t *h, uint16_t *supp, syndrome_drbg *rng)
{
    uint8_t buf[SYNDROME_BLOCK_BYTES];
    uint32_t idx[SYNDROME_V];
    uint32_t i;

    if (syndrome_sample_fixed_weight(idx, SYNDROME_V, SYNDROME_P, rng) != 0)
        return -1;
    for (i = 0; i < (uint32_t)SYNDROME_V; i++)
        supp[i] = (uint16_t)idx[i];
    syndrome_sample_scatter(buf, SYNDROME_BLOCK_BYTES, idx, SYNDROME_V,
                            SYNDROME_P);
    syndrome_gf2x_load(h, buf);
    return 0;
}

/*
 * Sample a weight-t error over n = n0*p through the production sampler and
 * split it into the n0 dense blocks: index j lands in block j/p at position
 * j%p.  The split is plain (non-oblivious) bit setting: this is test code
 * measuring failure rates, not a constant-time path.
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
 * One-sided lower confidence bound on a binomial proportion (Wilson score).
 * phat is the observed proportion over n trials; the bound uses the normal
 * quantile DFR_Z99, adequate at the failure counts this harness targets.
 */
static double
wilson_lower(double phat, double n)
{
    double z = DFR_Z99;
    double denom, center, half;

    denom = 1.0 + z * z / n;
    center = phat + z * z / (2.0 * n);
    half = z * sqrt((phat * (1.0 - phat) + z * z / (4.0 * n)) / n);
    return (center - half) / denom;
}

/*
 * Per-thread work item: run the batches [batch_lo, batch_hi) and accumulate a
 * local failure tally.  Each batch b runs min(per_key, trials - b*per_key)
 * trials under make_seed(b), so the batch->trials mapping (and therefore the
 * outcome) is independent of how batches are partitioned across threads.  All
 * scratch is thread-local (on this function's stack); the only shared reads are
 * const set parameters and ichor's lock-free clmul dispatch.
 */
typedef struct {
    unsigned long batch_lo;
    unsigned long batch_hi;
    unsigned long per_key;
    unsigned long trials;
    unsigned long done;
    unsigned long failures;
    unsigned long undetected;
    int error; /* set nonzero on a sampler failure */
} dfr_worker_ctx;

static void *
dfr_worker(void *arg)
{
    dfr_worker_ctx *ctx = arg;
    uint64_t h[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint16_t supp[SYNDROME_N0][SYNDROME_V];
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint64_t tmp[SYNDROME_GF2X_LIMBS];
    uint64_t s[SYNDROME_GF2X_LIMBS];
    syndrome_drbg rng;
    uint8_t seed[48];
    unsigned long batch, i, cnt, base;
    uint32_t b;
    int ok, mismatch;

    for (batch = ctx->batch_lo; batch < ctx->batch_hi; batch++) {
        base = batch * ctx->per_key;
        if (base >= ctx->trials)
            break;
        cnt = ctx->trials - base;
        if (cnt > ctx->per_key)
            cnt = ctx->per_key;

        make_seed(seed, (uint32_t)batch);
        syndrome_drbg_init(&rng, seed);

        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            if (sample_h_block(h[b], supp[b], &rng) != 0) {
                ctx->error = 1;
                return NULL;
            }

        for (i = 0; i < cnt; i++, ctx->done++) {
            if (sample_error(e, &rng) != 0) {
                ctx->error = 1;
                return NULL;
            }

            /* Private syndrome s = sum_b h[b]*e[b], the decoder's input. */
            memset(s, 0, sizeof(s));
            for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
                syndrome_gf2x_mul(tmp, h[b], e[b]);
                syndrome_gf2x_add(s, s, tmp);
            }

            syndrome_bitflip_decode(r, &ok, h, supp, s);

            mismatch = 0;
            for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
                if (memcmp(r[b], e[b], sizeof(r[b])) != 0)
                    mismatch = 1;
            if (mismatch) {
                ctx->failures++;
                if (ok == 1)
                    ctx->undetected++;
            }
        }
    }
    return NULL;
}

int
main(int argc, char **argv)
{
    struct timespec ts_start, ts_now;
    dfr_worker_ctx *ctx;
    pthread_t *threads;
    unsigned long trials, per_key, nthreads, nbatches, lo;
    unsigned long done, failures, undetected;
    double phat, lower, elapsed, expected;
    long online;
    const char *env;
    unsigned long t;
    int any_error;

    trials = DFR_DEFAULT_TRIALS;
    per_key = DFR_DEFAULT_TRIALS_PER_KEY;
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

    /*
     * CI override: a run that must execute the whole suite but cheaply (the
     * sanitize pipeline, which cannot skip slow tests) can cap the trial count
     * via SYNDROME_DFR_TRIALS, exercising every code path for ASan/UBSan without
     * the full statistical sweep.  It wins over the argv/default count.  The
     * one-sided gate stays sound: a small sample only widens the confidence
     * interval, so it never spuriously fails, and real memory/UB bugs are caught
     * by the sanitizer regardless of the failure count.
     */
    env = getenv("SYNDROME_DFR_TRIALS");
    if (env != NULL) {
        unsigned long cap = strtoul(env, NULL, 10);

        if (cap > 0)
            trials = cap;
    }

    /* Thread count: CLI arg, else env, else all online CPUs, else 1. */
    if (nthreads == 0) {
        env = getenv("SYNDROME_DFR_THREADS");
        if (env != NULL)
            nthreads = strtoul(env, NULL, 10);
    }
    if (nthreads == 0) {
        online = sysconf(_SC_NPROCESSORS_ONLN);
        nthreads = (online > 0) ? (unsigned long)online : 1ul;
    }

    /* No point spawning more threads than there are per-key batches. */
    nbatches = (trials + per_key - 1) / per_key;
    if (nthreads > nbatches)
        nthreads = nbatches;
    if (nthreads == 0)
        nthreads = 1;

    printf("dfr_mc: lambda=%d n0=%d p=%d v=%d t=%d th=%u/%u/%u trials=%lu "
           "trials_per_key=%lu threads=%lu\n",
           SYNDROME_LAMBDA, SYNDROME_N0, SYNDROME_P, SYNDROME_V, SYNDROME_T,
           syndrome_threshold(1), syndrome_threshold(2), syndrome_threshold(3),
           trials, per_key, nthreads);
    printf("dfr_mc: model DFR=%.8e (2^%.2f)\n", (double)DFR_MODEL,
           log2(DFR_MODEL));

    expected = (double)trials * (double)DFR_MODEL;
    if (expected < 20.0)
        printf("dfr_mc: WARNING: only %.1f failures expected; the sample is "
               "thin, grow trials for a meaningful bound\n",
               expected);

    /* Warm up ichor's clmul dispatch before spawning (avoid a first-call race
     * on the atomic init; harmless if already resolved). */
    {
        uint64_t wa[SYNDROME_GF2X_LIMBS] = {0};
        uint64_t wb[SYNDROME_GF2X_LIMBS];

        syndrome_gf2x_mul(wb, wa, wa);
    }

    ctx = calloc(nthreads, sizeof(*ctx));
    threads = calloc(nthreads, sizeof(*threads));
    if (ctx == NULL || threads == NULL) {
        fprintf(stderr, "dfr_mc: out of memory\n");
        free(ctx);
        free(threads);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* Partition the batch range [0, nbatches) into contiguous per-thread runs. */
    lo = 0;
    for (t = 0; t < nthreads; t++) {
        unsigned long span = nbatches / nthreads + (t < nbatches % nthreads);

        ctx[t].batch_lo = lo;
        ctx[t].batch_hi = lo + span;
        ctx[t].per_key = per_key;
        ctx[t].trials = trials;
        lo += span;
        if (pthread_create(&threads[t], NULL, dfr_worker, &ctx[t]) != 0) {
            fprintf(stderr, "dfr_mc: pthread_create failed\n");
            /* Join whatever already started, then bail. */
            while (t-- > 0)
                pthread_join(threads[t], NULL);
            free(ctx);
            free(threads);
            return 1;
        }
    }

    done = failures = undetected = 0;
    any_error = 0;
    for (t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
        done += ctx[t].done;
        failures += ctx[t].failures;
        undetected += ctx[t].undetected;
        any_error |= ctx[t].error;
    }

    free(ctx);
    free(threads);

    if (any_error) {
        fprintf(stderr, "dfr_mc: sampling failed\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    elapsed = (double)(ts_now.tv_sec - ts_start.tv_sec) +
              (double)(ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;
    fprintf(stderr,
            "dfr_mc: %lu trials, %lu failures, %.1f s elapsed "
            "(%.1f trials/s)\n",
            done, failures, elapsed,
            elapsed > 0.0 ? (double)done / elapsed : 0.0);

    phat = (double)failures / (double)trials;
    lower = failures > 0 ? wilson_lower(phat, (double)trials) : 0.0;

    printf("dfr_mc: failures=%lu (undetected miscorrections=%lu)\n", failures,
           undetected);
    if (failures > 0)
        printf("dfr_mc: empirical DFR=%.8e (2^%.2f), model=%.8e (2^%.2f), "
               "delta=%.2f bits\n",
               phat, log2(phat), (double)DFR_MODEL, log2(DFR_MODEL),
               log2(phat) - log2(DFR_MODEL));
    else
        printf("dfr_mc: empirical DFR=0 over %lu trials, model=%.8e\n", trials,
               (double)DFR_MODEL);
    printf("dfr_mc: one-sided 99%% lower bound=%.8e\n", lower);

    if (lower > (double)DFR_MODEL) {
        fprintf(stderr,
                "dfr_mc: FAILED: empirical DFR significantly exceeds the "
                "model prediction; the closed-form bound does not transfer "
                "to this decoder\n");
        return 1;
    }

    printf("dfr_mc: OK (empirical rate consistent with, or below, the "
           "model)\n");
    return 0;
}
