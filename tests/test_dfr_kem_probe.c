/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_dfr_kem_probe.c - real-p KEM round-trip failure dissector.
 *
 * Companion to test_dfr_probe (the PKE-level probe).  Where that one stops at
 * the decoder (keygen -> encrypt -> decode, checks the recovered error), this
 * one runs the full KEM round-trip at the set's REAL p and compares the shared
 * secret, exactly as test_kem does: the FO / accept_kdf / implicit-rejection
 * layer that the PKE probe does not touch.
 *
 * Per trial it keygens (per key batch), then faithfully replicates encap
 * (sample weight-t e -> errblocks_from_indices -> pke_encrypt -> accept_kdf) so
 * it KNOWS the true error blocks, and runs the real decap.  On a K mismatch it
 * re-runs the decode open (deserialize sk -> pke_decrypt) and classifies:
 *
 *   - DECODER      : ok==0 or wt(e_rec) != t (the decoder itself failed; a PKE-
 *                    probe-visible fault)
 *   - NONCANON     : the ciphertext's top byte has padding bits set (an encrypt
 *                    / ct-formation fault)
 *   - MISCORRECT   : ok==1, wt==t, but e_rec != the true error (a different
 *                    weight-t error with the same syndrome; ~2^-lambda rare)
 *   - FO           : ok==1, wt==t, e_rec == the true error, yet K mismatched --
 *                    decode recovered the genuine error but the shared secret
 *                    still differs.  This is the FO / accept_kdf / valid-mask
 *                    layer, the one the PKE probe cannot see.  On the first such
 *                    failure it also records whether accept_kdf(e_rec) would
 *                    equal encap's K (=> decap wrongly took the reject branch,
 *                    a valid-mask bug) or not (=> a KDF-input mismatch, e.g. the
 *                    sk-stored hpk), to narrow it further.
 *
 * Test-only; force-includes the per-set bodies; non-constant-time by design.
 * No gate: reports an empirical real-p KEM failure rate, the breakdown, and a
 * verdict, and exits 0.  Threading / seeding match test_dfr_probe, so the
 * outcome is independent of the thread count.
 *
 * Usage: test_dfr_kem_probe [trials [trials_per_key [threads]]]
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

#define KPROBE_DEFAULT_TRIALS 100000ul
#define KPROBE_DEFAULT_TRIALS_PER_KEY 1000ul

enum {
    KCLASS_DECODER = 0,
    KCLASS_NONCANON = 1,
    KCLASS_MISCORRECT = 2,
    KCLASS_FO = 3
};

static void make_seed(uint8_t[48], uint32_t);

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

typedef struct {
    unsigned long batch_lo;
    unsigned long batch_hi;
    unsigned long per_key;
    unsigned long trials;
    unsigned long done;
    unsigned long failures;
    unsigned long decoder;
    unsigned long noncanon;
    unsigned long miscorrect;
    unsigned long fo;
    int error;
    /* First caught failure. */
    int have_fail;
    int fail_class;
    int fail_ok;
    unsigned long fail_weight;
    int fo_kdf_would_match; /* for an FO failure: accept_kdf(e_rec) == encap K? */
    int fo_hpk_ok; /* sk-stored hpk == compute_hpk(pk)?                */
    unsigned long fail_batch;
    unsigned long fail_trial;
} kprobe_ctx;

static void *
kprobe_worker(void *arg)
{
    kprobe_ctx *ctx = arg;
    uint8_t pk[SYNDROME_PK_BYTES];
    uint8_t sk[SYNDROME_SK_BYTES];
    syndrome_qcmdpc_sk qsk;
    uint8_t hpk[SYNDROME_PKHASH_BYTES];
    uint32_t eidx[SYNDROME_T];
    uint8_t eb[SYNDROME_N0][SYNDROME_BLOCK_BYTES]; /* true error blocks     */
    uint64_t e[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint8_t ct[SYNDROME_CT_BYTES];
    uint8_t k1[SYNDROME_SS_BYTES];
    uint8_t k2[SYNDROME_SS_BYTES];
    uint8_t ks[SYNDROME_SS_BYTES];
    uint64_t r[SYNDROME_N0][SYNDROME_GF2X_LIMBS];
    uint8_t eb_rec[SYNDROME_N0]
                  [SYNDROME_BLOCK_BYTES]; /* recovered error blocks */
    syndrome_drbg rng;
    uint8_t seed[48];
    unsigned long batch, i, cnt, base;
    uint32_t b, j;
    size_t off;
    unsigned padbits;
    uint8_t padmask;
    int ok;

    padbits = (unsigned)(8 * SYNDROME_BLOCK_BYTES - SYNDROME_P);
    padmask = (uint8_t)(padbits ? (0xffu << (8 - padbits)) : 0u);

    for (batch = ctx->batch_lo; batch < ctx->batch_hi; batch++) {
        base = batch * ctx->per_key;
        if (base >= ctx->trials)
            break;
        cnt = ctx->trials - base;
        if (cnt > ctx->per_key)
            cnt = ctx->per_key;

        make_seed(seed, (uint32_t)batch);
        syndrome_drbg_init(&rng, seed);

        if (syndrome_kem_keypair_derand(pk, sk, &rng) != 0) {
            ctx->error = 1;
            return NULL;
        }
        /* Deserialize sk -> qsk (the H index lists) for the open re-decode. */
        off = SK_OFF_H;
        for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
            for (j = 0; j < (uint32_t)SYNDROME_V; j++) {
                qsk.cols[b][j] =
                    (uint16_t)(sk[off] | ((uint16_t)sk[off + 1] << 8));
                off += 2;
            }
        compute_hpk(hpk, pk);

        for (i = 0; i < cnt; i++, ctx->done++) {
            unsigned long w;
            int miscorrect, cls;

            /* ---- encap, replicated faithfully so we keep the true error ---- */
            if (syndrome_sample_fixed_weight(eidx, SYNDROME_T, SYNDROME_N,
                                             &rng) != 0) {
                ctx->error = 1;
                return NULL;
            }
            errblocks_from_indices(eb, eidx, SYNDROME_T);
            for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
                syndrome_gf2x_load(e[b], eb[b]);
            syndrome_pke_encrypt(ct, pk, e);
            accept_kdf(k1, eb, ct, hpk);

            /* ---- real decap ---- */
            if (syndrome_kem_decap_impl(k2, ct, sk) != 0) {
                ctx->error =
                    1; /* decap never returns an error on honest input */
                return NULL;
            }

            if (memcmp(k1, k2, sizeof(k1)) == 0)
                continue;

            /* ---- failure: dissect ---- */
            ctx->failures++;

            syndrome_pke_decrypt(r, &ok, &qsk, ct, NULL);
            w = 0;
            for (b = 0; b < (uint32_t)SYNDROME_N0; b++) {
                syndrome_gf2x_store(eb_rec[b], r[b]);
                w += syndrome_bitvec_weight(eb_rec[b], SYNDROME_P);
            }
            miscorrect = 0;
            for (b = 0; b < (uint32_t)SYNDROME_N0; b++)
                if (memcmp(eb_rec[b], eb[b], SYNDROME_BLOCK_BYTES) != 0)
                    miscorrect = 1;

            if (ok != 1 || w != (unsigned long)SYNDROME_T) {
                ctx->decoder++;
                cls = KCLASS_DECODER;
            } else if ((ct[SYNDROME_CT_BYTES - 1] & padmask) != 0) {
                ctx->noncanon++;
                cls = KCLASS_NONCANON;
            } else if (miscorrect) {
                ctx->miscorrect++;
                cls = KCLASS_MISCORRECT;
            } else {
                /* decode recovered the genuine error, yet K differs: FO layer. */
                ctx->fo++;
                cls = KCLASS_FO;
            }

            if (!ctx->have_fail) {
                ctx->have_fail = 1;
                ctx->fail_class = cls;
                ctx->fail_ok = ok;
                ctx->fail_weight = w;
                ctx->fail_batch = batch;
                ctx->fail_trial = i;
                if (cls == KCLASS_FO) {
                    /* Would the honest acceptance KDF on the recovered (=true)
                     * error reproduce encap's K?  If yes, decap wrongly chose
                     * the reject branch (valid-mask bug); if no, the KDF inputs
                     * differ (e.g. the sk-stored hpk). */
                    accept_kdf(ks, eb_rec, ct, hpk);
                    ctx->fo_kdf_would_match = (memcmp(ks, k1, sizeof(ks)) == 0);
                    ctx->fo_hpk_ok = (memcmp(sk + SK_OFF_HPK, hpk,
                                             SYNDROME_PKHASH_BYTES) == 0);
                }
            }
        }
    }
    return NULL;
}

int
main(int argc, char **argv)
{
    struct timespec ts_start, ts_now;
    kprobe_ctx *ctx;
    pthread_t *threads;
    unsigned long trials, per_key, nthreads, nbatches, lo;
    unsigned long done, failures, decoder, noncanon, miscorrect, fo;
    double phat, elapsed;
    long online;
    const char *env;
    unsigned long t;
    int any_error, have_first, first_class, first_ok, first_kdf, first_hpk;
    unsigned long first_weight, first_batch, first_trial;

    trials = KPROBE_DEFAULT_TRIALS;
    per_key = KPROBE_DEFAULT_TRIALS_PER_KEY;
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

    printf("dfr_kem_probe: lambda=%d n0=%d p=%d t=%d (REAL p) trials=%lu "
           "trials_per_key=%lu threads=%lu\n",
           SYNDROME_LAMBDA, SYNDROME_N0, SYNDROME_P, SYNDROME_T, trials,
           per_key, nthreads);

    {
        uint64_t wa[SYNDROME_GF2X_LIMBS] = {0};
        uint64_t wb[SYNDROME_GF2X_LIMBS];

        syndrome_gf2x_mul(wb, wa, wa);
    }

    ctx = calloc(nthreads, sizeof(*ctx));
    threads = calloc(nthreads, sizeof(*threads));
    if (ctx == NULL || threads == NULL) {
        fprintf(stderr, "dfr_kem_probe: out of memory\n");
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
        if (pthread_create(&threads[t], NULL, kprobe_worker, &ctx[t]) != 0) {
            fprintf(stderr, "dfr_kem_probe: pthread_create failed\n");
            while (t-- > 0)
                pthread_join(threads[t], NULL);
            free(ctx);
            free(threads);
            return 1;
        }
    }

    done = failures = decoder = noncanon = miscorrect = fo = 0;
    any_error = 0;
    have_first = 0;
    first_class = first_ok = first_kdf = first_hpk = 0;
    first_weight = first_batch = first_trial = 0;
    for (t = 0; t < nthreads; t++) {
        pthread_join(threads[t], NULL);
        done += ctx[t].done;
        failures += ctx[t].failures;
        decoder += ctx[t].decoder;
        noncanon += ctx[t].noncanon;
        miscorrect += ctx[t].miscorrect;
        fo += ctx[t].fo;
        any_error |= ctx[t].error;
        if (ctx[t].have_fail && !have_first) {
            have_first = 1;
            first_class = ctx[t].fail_class;
            first_ok = ctx[t].fail_ok;
            first_weight = ctx[t].fail_weight;
            first_kdf = ctx[t].fo_kdf_would_match;
            first_hpk = ctx[t].fo_hpk_ok;
            first_batch = ctx[t].fail_batch;
            first_trial = ctx[t].fail_trial;
        }
    }

    free(ctx);
    free(threads);

    if (any_error) {
        fprintf(stderr,
                "dfr_kem_probe: keygen/sample/decap reported an error\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    elapsed = (double)(ts_now.tv_sec - ts_start.tv_sec) +
              (double)(ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;

    phat = (double)failures / (double)done;
    printf("dfr_kem_probe: %lu round-trips, %lu K-mismatches, %.1f s "
           "(%.0f trips/s)\n",
           done, failures, elapsed,
           elapsed > 0.0 ? (double)done / elapsed : 0.0);
    if (failures > 0)
        printf("dfr_kem_probe: empirical real-p KEM failure rate = %.6e "
               "(2^%.2f)\n",
               phat, log2(phat));
    else
        printf("dfr_kem_probe: empirical real-p KEM failure rate = 0 over %lu "
               "round-trips\n",
               done);
    printf("dfr_kem_probe: breakdown: decoder=%lu  noncanon=%lu  "
           "miscorrect=%lu  fo-layer=%lu\n",
           decoder, noncanon, miscorrect, fo);

    if (have_first) {
        const char *cname = first_class == KCLASS_DECODER      ? "DECODER"
                            : first_class == KCLASS_NONCANON   ? "NONCANON"
                            : first_class == KCLASS_MISCORRECT ? "MISCORRECT"
                                                               : "FO";

        printf("dfr_kem_probe: first failure: class=%s ok=%d wt=%lu "
               "batch=%lu trial=%lu\n",
               cname, first_ok, first_weight, first_batch, first_trial);
        if (first_class == KCLASS_FO)
            printf(
                "dfr_kem_probe:   FO detail: accept_kdf(e_rec)==encapK? %s ; "
                "sk.hpk==compute_hpk(pk)? %s\n",
                first_kdf ? "YES (decap took the reject branch: valid-mask bug)"
                          : "NO (KDF inputs differ)",
                first_hpk ? "yes" : "NO (sk hpk serialization bug)");
    }

    if (failures == 0)
        printf(
            "dfr_kem_probe: VERDICT: no KEM failure seen at this trial count; "
            "grow trials, or the rate is below what this run can resolve.\n");
    else if (fo == failures)
        printf("dfr_kem_probe: VERDICT: FO / accept_kdf / valid-mask layer: "
               "decode recovered the genuine error but the shared secret still "
               "differs.\n");
    else if (decoder > 0)
        printf("dfr_kem_probe: VERDICT: decoder failures present (should also "
               "appear in test_dfr_probe for this set).\n");
    else
        printf("dfr_kem_probe: VERDICT: mixed; see the breakdown and the first-"
               "failure detail.\n");

    return 0;
}
