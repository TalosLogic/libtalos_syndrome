/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_qcmdpc.c - harness hook for code/qcmdpc.c.
 *
 * The checks live in syndrome_qcmdpc_selftest (weight invariants on each H
 * block, the H_1 * M_0 = H_0 round-trip, and determinism under a fixed
 * seed); this runs it as a CTest gate.
 */
#include <stdio.h>

#include "code.h"

int
main(void)
{
    printf("qcmdpc tests:\n");
    if (syndrome_qcmdpc_selftest() != 0) {
        fprintf(stderr, "qcmdpc: selftest FAILED\n");
        return 1;
    }
    printf("qcmdpc: OK\n");
    return 0;
}
