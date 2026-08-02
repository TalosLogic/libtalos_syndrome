/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_threshold.c - harness hook for decoder/threshold.c.
 *
 * The checks live in syndrome_threshold_selftest (pinned per-iteration
 * thresholds, majority invariant, column-weight bound, non-increasing
 * sequence); this runs it as a CTest gate.
 */
#include <stdio.h>

#include "decoder.h"

int
main(void)
{
    printf("threshold tests:\n");
    if (syndrome_threshold_selftest() != 0) {
        fprintf(stderr, "threshold: selftest FAILED\n");
        return 1;
    }
    printf("threshold: OK\n");
    return 0;
}
