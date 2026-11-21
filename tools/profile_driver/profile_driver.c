/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * profile_driver.c - a standalone timing workload over the public syndrome
 * KEM + Argus API, for hotspot profiling and benchmarking.
 *
 * This is measurement scaffolding, deliberately built on the PUBLIC API only
 * (talos_syndrome.h): it drives keypair / encap / decap / argus_open in tight
 * per-set loops so a profiler has something dense to attribute.  Unlike the
 * dudect harness it does not force-include the per-set algorithm bodies; it
 * dispatches to every built (lambda, n0) set at runtime through the public
 * entry points.
 *
 * It is useful three ways, and the first needs no external tooling at all, so
 * it works on any system whether or not perf or the LLVM tools are installed:
 *
 *   1. On its own it is a micro-benchmark: per-op min and median wall-clock
 *      time and throughput for every built set.
 *   2. Under perf (where installed):  perf record -g ./syndrome_profile
 *      The target always carries -g and frame pointers (its CMakeLists sets
 *      them unconditionally), so symbolized sampling works even in a plain,
 *      uninstrumented build.
 *   3. Under LLVM instrumentation:  configure the tree with
 *      -DSYNDROME_PROFILE=xray or =coverage (top-level CMakeLists) and point
 *      llvm-xray / llvm-cov at this binary.
 *
 * Argus note: a genuinely openable tag needs the sealing side, which is
 * voleith's job and not part of syndrome's public API, so argus_open is
 * exercised on a canonical tag: the set's per-lambda default prim_id byte,
 * then a zero syndrome and zero ct.  The prim_id byte is mandatory here: the
 * fail-closed prim_id gate rejects any other id with EUNSUPPORTED before the
 * decode path is reached.  The constant-time opener then runs its full decode
 * + KDF + OTP path regardless of openability (fixed iterMax, data-independent
 * control flow), so the timing is representative; it returns EUNOPENABLE, the
 * expected result here, not an error.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <ichor/pool.h>

#include "talos_syndrome.h"

#define WARMUP_ITERS 2
#define DEFAULT_ITERS 50
#define MAX_ITERS 1000000u

static double
now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int
cmp_double(const void *a, const void *b)
{
    const double da = *(const double *)a;
    const double db = *(const double *)b;
    return (da > db) - (da < db);
}

/* Sort the samples in place, then print min / median / throughput.  n >= 1.
 * The caller overwrites the buffer before the next op, so the in-place sort is
 * harmless. */
static void
report(const char *op, double *samples, size_t n)
{
    double min = samples[0];
    double median;
    size_t i;

    for (i = 1; i < n; i++)
        if (samples[i] < min)
            min = samples[i];
    qsort(samples, n, sizeof samples[0], cmp_double);
    median = samples[n / 2];
    printf("    %-11s  min %9.2f us   median %9.2f us   %11.1f op/s\n", op,
           min * 1e6, median * 1e6, median > 0.0 ? 1.0 / median : 0.0);
}

/* Is operation `name` selected?  op == NULL means "run all". */
static int
op_selected(const char *op, const char *name)
{
    return op == NULL || strcmp(op, name) == 0;
}

/*
 * Run the selected op (or all) for one set.  Prerequisites always run as
 * untimed setup so a single op can be profiled in isolation: keypair always
 * runs (every op needs sk/pk), and encap runs whenever decap is profiled (decap
 * needs a ciphertext).  Only the selected op's timed loop and report execute,
 * so a `decap`-only run leaves the profiler samples dominated by decap.
 */
static int
run_set(syndrome_set_id set, const char *name, uint8_t prim_id, size_t iters,
        double *samples, const char *op, const syndrome_opts_t *opts)
{
    uint8_t pk[SYNDROME_MAX_PK_BYTES];
    uint8_t sk[SYNDROME_MAX_SK_BYTES];
    uint8_t ct[SYNDROME_MAX_CT_BYTES];
    uint8_t k_enc[SYNDROME_MAX_SS_BYTES];
    uint8_t k_dec[SYNDROME_MAX_SS_BYTES];
    uint8_t identity[SYNDROME_MAX_ARGUS_ID_MAX_BYTES];
    uint8_t tag[SYNDROME_MAX_ARGUS_TAG_BYTES(SYNDROME_MAX_ARGUS_ID_MAX_BYTES)];
    size_t ss_len = syndrome_ss_bytes(set);
    size_t id_len = syndrome_argus_id_max_bytes(set);
    size_t tag_len = 1u + syndrome_ct_bytes(set) + id_len; /* prim_id||s||ct */
    /* encap is a decap prerequisite (supplies the ciphertext). */
    int need_encap = op_selected(op, "encap") || op_selected(op, "decap");
    size_t w, i;
    double t0;
    int rc;

    printf("  set %s  (pk %zu, ct %zu, sk %zu B)\n", name,
           syndrome_pk_bytes(set), syndrome_ct_bytes(set),
           syndrome_sk_bytes(set));

    /* keypair -- always run (setup for every op); timed only if selected. */
    for (w = 0; w < WARMUP_ITERS; w++)
        if ((rc = syndrome_kem_keypair(set, pk, sk)) != 0)
            goto op_failed;
    if (op_selected(op, "keygen")) {
        for (i = 0; i < iters; i++) {
            t0 = now_seconds();
            rc = syndrome_kem_keypair(set, pk, sk);
            samples[i] = now_seconds() - t0;
            if (rc != 0)
                goto op_failed;
        }
        report("keypair", samples, iters);
    }

    /* encap, against the last keypair's public key. */
    if (need_encap) {
        for (w = 0; w < WARMUP_ITERS; w++)
            if ((rc = syndrome_kem_encap(set, ct, k_enc, pk)) != 0)
                goto op_failed;
        if (op_selected(op, "encap")) {
            for (i = 0; i < iters; i++) {
                t0 = now_seconds();
                rc = syndrome_kem_encap(set, ct, k_enc, pk);
                samples[i] = now_seconds() - t0;
                if (rc != 0)
                    goto op_failed;
            }
            report("encap", samples, iters);
        }
    }

    /* decap, against the last encap's ciphertext. */
    if (op_selected(op, "decap")) {
        for (w = 0; w < WARMUP_ITERS; w++)
            if ((rc = syndrome_kem_decap_ex(set, k_dec, ct, sk, opts)) != 0)
                goto op_failed;
        for (i = 0; i < iters; i++) {
            t0 = now_seconds();
            rc = syndrome_kem_decap_ex(set, k_dec, ct, sk, opts);
            samples[i] = now_seconds() - t0;
            if (rc != 0)
                goto op_failed;
        }
        report("decap", samples, iters);

        /* Correctness smoke: decap must recover encap's shared secret. */
        if (memcmp(k_enc, k_dec, ss_len) != 0) {
            fprintf(stderr, "  ERROR: decap secret mismatch (set %s)\n", name);
            return -1;
        }
    }

    /* argus_open on a canonical tag (see the file header): the per-lambda
     * default prim_id byte, then a zero syndrome and ct.  A zero or other
     * prim_id fails the fail-closed prim_id gate with EUNSUPPORTED before the
     * decode path; the default reaches it and returns EUNOPENABLE, expected. */
    if (op_selected(op, "argus")) {
        memset(tag, 0, tag_len);
        tag[0] = prim_id;
        for (w = 0; w < WARMUP_ITERS; w++) {
            rc = syndrome_argus_open_ex(set, identity, id_len, tag, tag_len, sk,
                                        SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED,
                                        opts);
            if (rc != SYNDROME_ARGUS_OK && rc != SYNDROME_ARGUS_EUNOPENABLE)
                goto op_failed;
        }
        for (i = 0; i < iters; i++) {
            t0 = now_seconds();
            rc = syndrome_argus_open_ex(set, identity, id_len, tag, tag_len, sk,
                                        SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED,
                                        opts);
            samples[i] = now_seconds() - t0;
            if (rc != SYNDROME_ARGUS_OK && rc != SYNDROME_ARGUS_EUNOPENABLE)
                goto op_failed;
        }
        report("argus_open", samples, iters);
    }

    return 0;

op_failed:
    fprintf(stderr, "  ERROR: operation returned %d (set %s)\n", rc, name);
    return -1;
}

int
main(int argc, char **argv)
{
    static const struct {
        syndrome_set_id id;
        const char *name;
        uint8_t prim_id; /* per-lambda default KDF hash (ARGUS_DS_PRIM_ID): */
    } sets[] = {
        {SYNDROME_SET_128_2, "128_2",
         0x01}, /* 0x01 = AES-DM     @ lambda 128 */
        {SYNDROME_SET_128_5, "128_5",
         0x01}, /* 0x01 = AES-DM     @ lambda 128 */
        {SYNDROME_SET_256_2, "256_2",
         0x02}, /* 0x02 = Grostl-256 @ lambda 256 */
        {SYNDROME_SET_256_5, "256_5",
         0x02}, /* 0x02 = Grostl-256 @ lambda 256 */
        {SYNDROME_SET_128_3, "128_3",
         0x01}, /* 0x01 = AES-DM     @ lambda 128 */
        {SYNDROME_SET_128_4, "128_4",
         0x01}, /* 0x01 = AES-DM     @ lambda 128 */
        {SYNDROME_SET_192_2, "192_2",
         0x02}, /* 0x02 = Grostl-256 @ lambda 192 */
        {SYNDROME_SET_192_3, "192_3",
         0x02}, /* 0x02 = Grostl-256 @ lambda 192 */
        {SYNDROME_SET_192_4, "192_4",
         0x02}, /* 0x02 = Grostl-256 @ lambda 192 */
        {SYNDROME_SET_192_5, "192_5",
         0x02}, /* 0x02 = Grostl-256 @ lambda 192 */
        {SYNDROME_SET_256_3, "256_3",
         0x02}, /* 0x02 = Grostl-256 @ lambda 256 */
        {SYNDROME_SET_256_4, "256_4",
         0x02}, /* 0x02 = Grostl-256 @ lambda 256 */
    };
    const size_t nsets = sizeof sets / sizeof sets[0];
    size_t iters = DEFAULT_ITERS;
    const char *filter = NULL;
    const char *op = NULL;
    double *samples;
    syndrome_opts_t opts;
    const syndrome_opts_t *opts_ptr = NULL;
    ichor_pool_t *borrowed = NULL;
    unsigned threads = 0;
    int borrow = 0;
    int any = 0;
    size_t s;

    if (argc >= 2) {
        char *end;
        unsigned long v = strtoul(argv[1], &end, 10);
        if (*end != '\0' || v == 0 || v > MAX_ITERS) {
            fprintf(
                stderr,
                "usage: %s [iterations] [set] [op] [threads] [pool]\n"
                "  iterations: 1..%u (default %u)\n"
                "  set:        128_2 | 128_3 | 128_4 | 128_5 |\n"
                "              192_2 | 192_3 | 192_4 | 192_5 |\n"
                "              256_2 | 256_3 | 256_4 | 256_5 (default all)\n"
                "  op:         keygen | encap | decap | argus (default all;\n"
                "              prerequisites still run untimed for "
                "isolation)\n"
                "  threads:    worker threads for decap / argus_open (0/1 =\n"
                "              serial, the default; >1 uses the _ex API)\n"
                "  pool:       literal 'pool' to supply ONE caller-owned pool\n"
                "              (opts.pool) reused across every timed call;\n"
                "              omitted = library creates+destroys an internal\n"
                "              pool per call.  Needs threads > 1.\n",
                argv[0], MAX_ITERS, DEFAULT_ITERS);
            return 2;
        }
        iters = (size_t)v;
    }
    if (argc >= 3 && strcmp(argv[2], "-") != 0)
        filter = argv[2];
    if (argc >= 4) {
        op = argv[3];
        if (strcmp(op, "keygen") != 0 && strcmp(op, "encap") != 0 &&
            strcmp(op, "decap") != 0 && strcmp(op, "argus") != 0) {
            fprintf(stderr,
                    "unknown op '%s' (keygen | encap | decap | argus)\n", op);
            return 2;
        }
    }
    if (argc >= 5) {
        char *end;
        unsigned long v = strtoul(argv[4], &end, 10);
        if (*end != '\0' || v > 1024ul) {
            fprintf(stderr, "threads: 0..1024 (0/1 = serial)\n");
            return 2;
        }
        threads = (unsigned)v;
    }
    if (argc >= 6) {
        if (strcmp(argv[5], "pool") != 0) {
            fprintf(stderr, "pool: literal 'pool' or omit\n");
            return 2;
        }
        borrow = 1;
    }
    if (borrow && threads <= 1u) {
        fprintf(stderr, "pool mode needs threads > 1\n");
        return 2;
    }
    if (threads > 1u) {
        syndrome_opts_init(&opts);
        opts.thread_count = threads;
        /*
         * pool mode: create one caller-owned pool and hang it on opts.pool, so
         * the library borrows it for every timed call (thread spin-up paid once
         * here, not per call).  A creation failure falls back to the per-call
         * internal pool rather than aborting the benchmark.
         */
        if (borrow && ichor_pool_create(&borrowed, threads) == 0)
            opts.pool = borrowed;
        opts_ptr = &opts;
    }

    samples = calloc(iters, sizeof *samples);
    if (samples == NULL) {
        fprintf(stderr, "out of memory for %zu samples\n", iters);
        ichor_pool_destroy(borrowed);
        return 1;
    }

    printf("syndrome profile driver: %zu iterations per op%s%s", iters,
           op != NULL ? ", op=" : "", op != NULL ? op : "");
    if (threads > 1u)
        printf(", threads=%u", threads);
    if (opts_ptr != NULL && opts.pool != NULL)
        printf(", pool=borrowed");
    else if (threads > 1u)
        printf(", pool=per-call");
    printf("\n");

    for (s = 0; s < nsets; s++) {
        if (!syndrome_set_enabled(sets[s].id))
            continue;
        if (filter != NULL && strcmp(filter, sets[s].name) != 0)
            continue;
        any = 1;
        if (run_set(sets[s].id, sets[s].name, sets[s].prim_id, iters, samples,
                    op, opts_ptr) != 0) {
            free(samples);
            ichor_pool_destroy(borrowed);
            return 1;
        }
    }

    free(samples);
    ichor_pool_destroy(borrowed);
    if (!any) {
        fprintf(stderr, "no matching enabled set%s%s\n",
                filter != NULL ? " for filter " : "",
                filter != NULL ? filter : "");
        return 2;
    }
    return 0;
}
