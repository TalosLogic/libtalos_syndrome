/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_bitvec.c - harness hook for core/bitvec.c.
 *
 * The exhaustive checks live in syndrome_bitvec_selftest (accessors, weight
 * with tail masking, xor); this runs it as a CTest gate.
 */
#include <stdio.h>

#include "core.h"

int
main(void)
{
    printf("bitvec tests:\n");
    if (syndrome_bitvec_selftest() != 0) {
        fprintf(stderr, "bitvec: selftest FAILED\n");
        return 1;
    }
    printf("bitvec: OK\n");
    return 0;
}
