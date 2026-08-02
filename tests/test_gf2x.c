/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf2x.c - harness hook for core/gf2x.c.
 *
 * The exhaustive checks live in syndrome_gf2x_selftest (add, load/store,
 * multiply identity, the (1+x)^2 and x^{p-1}*x == 1 cyclic-reduction KATs,
 * commutativity, distributivity, and the Itoh-Tsujii inverse round-trip);
 * this runs it as a CTest gate.
 */
#include <stdio.h>

#include "core.h"

int
main(void)
{
    printf("gf2x tests:\n");
    if (syndrome_gf2x_selftest() != 0) {
        fprintf(stderr, "gf2x: selftest FAILED\n");
        return 1;
    }
    printf("gf2x: OK\n");
    return 0;
}
