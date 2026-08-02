/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_bitflip.c - harness hook for decoder/bitflip.c.
 *
 * The checks live in syndrome_bitflip_selftest (round-trip decode of a
 * freshly sampled weight-t error, and a zero-syndrome sanity sub-check),
 * syndrome_bitflip_ctr_selftest (the bit-sliced counter add and threshold
 * compare), and syndrome_bitflip_diff_selftest (the rotated-syndrome counter
 * path against the dense popcount oracle); this runs them as a CTest gate.
 */
#include <stdio.h>

#include "decoder.h"

int
main(void)
{
    printf("bitflip tests:\n");
    if (syndrome_bitflip_selftest() != 0) {
        fprintf(stderr, "bitflip: selftest FAILED\n");
        return 1;
    }
    if (syndrome_bitflip_ctr_selftest() != 0) {
        fprintf(stderr, "bitflip: counter selftest FAILED\n");
        return 1;
    }
    if (syndrome_bitflip_diff_selftest() != 0) {
        fprintf(stderr, "bitflip: differential selftest FAILED\n");
        return 1;
    }
    printf("bitflip: OK\n");
    return 0;
}
