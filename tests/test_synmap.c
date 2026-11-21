/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_synmap.c - harness hook for code/synmap_impl.inc.
 *
 * The checks live in syndrome_synmap_selftest (the s' = H_0*e_0 + H_1*e_1
 * composition invariant, and a zero-error sanity sub-check); this runs it
 * as a CTest gate.
 */
#include <stdio.h>

#include "code.h"

int
main(void)
{
    printf("synmap tests:\n");
    if (syndrome_synmap_selftest() != 0) {
        fprintf(stderr, "synmap: selftest FAILED\n");
        return 1;
    }
    printf("synmap: OK\n");
    return 0;
}
