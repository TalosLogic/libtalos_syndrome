/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_niederreiter.c - harness hook for pke/niederreiter.c.
 *
 * The checks live in syndrome_niederreiter_selftest (a full encrypt/decrypt
 * round-trip of a weight-t error through the public M and the private H,
 * exercising the M_0 = H_1^{-1} H_0 relation, the private-syndrome map, and
 * the bit-flipping decoder); this runs it as a CTest gate.
 */
#include <stdio.h>

#include "pke.h"

int
main(void)
{
    printf("niederreiter tests:\n");
    if (syndrome_niederreiter_selftest() != 0) {
        fprintf(stderr, "niederreiter: selftest FAILED\n");
        return 1;
    }
    printf("niederreiter: OK\n");
    return 0;
}
