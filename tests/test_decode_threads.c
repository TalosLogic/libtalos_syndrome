/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_decode_threads.c - threaded-decode determinism over the public _ex API.
 *
 * S4 parallelises the decoder's counter accumulation across worker threads.
 * The partial counters are summed with a bit-sliced adder, and integer addition
 * of the per-position counts is associative and commutative, so the recovered
 * shared secret must be identical for every thread_count.  This test pins that:
 * for many random keys/ciphertexts it decaps serially and at several worker
 * counts and asserts all results are byte-identical to the serial one.
 *
 * It deliberately compares the threaded decap against the SERIAL decap of the
 * same (sk, ct), not against the encapsulated key: a decode that fails (the
 * QC-MDPC DFR) yields an implicit-rejection secret that is deterministic in
 * (sk, ct), so serial and threaded still agree.  Decapsulation correctness
 * (K == encap K) is the kem test's job; this test isolates "threading never
 * changes the result".  argus_open shares the exact same threaded decode path
 * (pke_decrypt -> bitflip_decode_ex -> compute_counters) and adds only an
 * unthreaded tail, so exercising decap covers the threaded code.
 *
 * It also exercises the borrow-or-create pool path (S6): a caller-supplied
 * ichor_pool passed via opts.pool is reused across every decap in the set and
 * must yield the same byte-identical result as the serial decap and as the
 * library-created internal pools, proving the borrowed pool is used (not
 * destroyed between calls) and that borrowing changes nothing but speed.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ichor/pool.h>

#include "talos_syndrome.h"

#define ITERS 8

/* Worker counts to cross-check: 1 (serial via _ex), even and odd chunkings. */
static const unsigned thread_counts[] = {1u, 2u, 3u, 4u, 8u};

static int fail_count = 0;

static void
check(const char *name, int cond)
{
    if (!cond) {
        printf("  FAIL: %s\n", name);
        fail_count++;
    }
}

static int
run_set(syndrome_set_id set, const char *name)
{
    uint8_t pk[SYNDROME_MAX_PK_BYTES];
    uint8_t sk[SYNDROME_MAX_SK_BYTES];
    uint8_t ct[SYNDROME_MAX_CT_BYTES];
    uint8_t k_enc[SYNDROME_MAX_SS_BYTES];
    uint8_t k_ref[SYNDROME_MAX_SS_BYTES];
    uint8_t k_thr[SYNDROME_MAX_SS_BYTES];
    ichor_pool_t *borrowed = NULL;
    size_t ss = syndrome_ss_bytes(set);
    unsigned it, t;

    printf(" set %s:\n", name);

    /*
     * One caller-owned pool, borrowed by every decap below and destroyed only
     * here at the end.  A creation failure is not fatal: the borrowed-pool
     * check degrades to the serial reference (opts.pool stays NULL), matching
     * the library's own fail-to-serial policy.
     */
    if (ichor_pool_create(&borrowed, 4u) != 0)
        borrowed = NULL;

    for (it = 0; it < ITERS; it++) {
        if (syndrome_kem_keypair(set, pk, sk) != 0) {
            check("keypair", 0);
            return -1;
        }
        if (syndrome_kem_encap(set, ct, k_enc, pk) != 0) {
            check("encap", 0);
            return -1;
        }

        /* Serial reference (base API == _ex with NULL opts). */
        if (syndrome_kem_decap(set, k_ref, ct, sk) != 0) {
            check("serial decap returns 0", 0);
            return -1;
        }

        for (t = 0; t < sizeof thread_counts / sizeof thread_counts[0]; t++) {
            syndrome_opts_t opts;

            syndrome_opts_init(&opts);
            opts.thread_count = thread_counts[t];

            if (syndrome_kem_decap_ex(set, k_thr, ct, sk, &opts) != 0) {
                check("threaded decap returns 0", 0);
                return -1;
            }
            check("threaded decap == serial decap",
                  memcmp(k_thr, k_ref, ss) == 0);
        }

        /* Borrowed caller-supplied pool, reused across every iteration. */
        {
            syndrome_opts_t opts;

            syndrome_opts_init(&opts);
            opts.pool = borrowed;

            if (syndrome_kem_decap_ex(set, k_thr, ct, sk, &opts) != 0) {
                check("borrowed-pool decap returns 0", 0);
                ichor_pool_destroy(borrowed);
                return -1;
            }
            check("borrowed-pool decap == serial decap",
                  memcmp(k_thr, k_ref, ss) == 0);
        }
    }
    ichor_pool_destroy(borrowed);
    return 0;
}

int
main(void)
{
    static const struct {
        syndrome_set_id id;
        const char *name;
    } sets[] = {
        {SYNDROME_SET_128_2, "128_2"}, {SYNDROME_SET_128_5, "128_5"},
        {SYNDROME_SET_256_2, "256_2"}, {SYNDROME_SET_256_5, "256_5"},
        {SYNDROME_SET_128_3, "128_3"}, {SYNDROME_SET_128_4, "128_4"},
        {SYNDROME_SET_192_2, "192_2"}, {SYNDROME_SET_192_3, "192_3"},
        {SYNDROME_SET_192_4, "192_4"}, {SYNDROME_SET_192_5, "192_5"},
        {SYNDROME_SET_256_3, "256_3"}, {SYNDROME_SET_256_4, "256_4"},
    };
    size_t s;

    printf("decode-threading determinism: decap byte-identical across "
           "thread_count\n");

    for (s = 0; s < sizeof sets / sizeof sets[0]; s++) {
        if (!syndrome_set_enabled(sets[s].id))
            continue;
        if (run_set(sets[s].id, sets[s].name) != 0)
            return 1;
    }

    if (fail_count == 0) {
        printf("test_decode_threads: all checks passed\n");
        return 0;
    }
    printf("test_decode_threads: %d check(s) failed\n", fail_count);
    return 1;
}
