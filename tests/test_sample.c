/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_sample.c - harness hook for core/sample.c.
 *
 * The checks live in syndrome_sample_selftest (exact weight, distinctness and
 * range for both the weight-t error and the weight-v H block, scatter weight
 * and bit placement, determinism, and seed divergence); this runs it as a
 * CTest gate.
 */
#include <stdio.h>

#include "core.h"

int
main(void)
{
    printf("sample tests:\n");
    if (syndrome_sample_selftest() != 0) {
        fprintf(stderr, "sample: selftest FAILED\n");
        return 1;
    }
    printf("sample: OK\n");
    return 0;
}
