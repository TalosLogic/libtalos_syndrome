# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# dudect timing-validation harness (the empirical gate complementing the
# source-level constant-time audit).  Lives outside the test pipeline -- enable
# with -DSYNDROME_BUILD_DUDECT=ON and run the binary manually; see README.md.
# Opt-in because a full run takes minutes and wants a quiet, frequency-pinned
# machine.
#
# This gate validates that syndrome's OWN code is constant-time: the masked
# fixed-weight sampler, the schoolbook gf2x multiply/reduce/inverse loops, the
# bit-flip decoder, and the KEM/Argus glue.  The carry-less multiply primitive
# and AES/SHAKE underneath come from ichor, which validates HW/fallback parity
# and constant-timeness in its own suite.  Here the harness pins ichor to its
# software fallback (aes:bitsliced,clmul:scalar via ICHOR_FORCE_BACKEND, set in
# dudect_main.c) so the sign-off measures the at-risk hand-written scalar path
# rather than the CT-by-construction AES-NI/CLMUL instructions.  That is why
# the top-level CMakeLists enables ichor's force hook whenever dudect is built.
# A leak this harness reports is in syndrome's code, which is what we check.
#
# Per the per-set library model (docs/IMPLEMENTATION_PLAN_1_0_0.md P1.3), the
# algorithm bodies are all-static functions in *_impl.inc, materialized by
# force-including sets/set_bodies.inc with a set's SYNDROME_LAMBDA / SYNDROME_N0
# -- exactly like the per-set test binaries (tests/CMakeLists.txt).  So we build
# one harness per built set, syndrome_dudect_<lambda>_<n0>; the sentinel targets
# are set-independent, and each syndrome target validates that set's code.

set(_SYN_ROOT ${CMAKE_SOURCE_DIR})
set(ICHOR_DUDECT ${_SYN_ROOT}/third_party/libtalos_ichor/tools/dudect)

# Internal headers the targets reach (mirrors tests' _syn_test_includes).
set(_dudect_includes
    ${_SYN_ROOT}/include
    ${_SYN_ROOT}/core
    ${_SYN_ROOT}/code
    ${_SYN_ROOT}/decoder
    ${_SYN_ROOT}/pke
    ${_SYN_ROOT}/kem
    ${_SYN_ROOT}/opener
    ${_SYN_ROOT}/sets
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ICHOR_DUDECT})

# targets_syndrome.c carries one set's static algorithm bodies via the force-
# included bundle, so most of the bundle is unused in it -- suppress that, and
# force-include the bundle.  A source-file option is emitted after the interface
# -Wall (see the note in tests/CMakeLists.txt), and after the per-exe -D
# (SYNDROME_LAMBDA/N0 via target_compile_definitions), so the bundle sees the
# right set constants.  Shared across the per-set exes; each exe's own -D selects
# the set, so the single -include is correct for all of them.  dudect_main.c and
# the ichor runner sources are set-independent and compile without the bundle.
set_source_files_properties(targets_syndrome.c PROPERTIES
    COMPILE_OPTIONS "-include;${_SYN_ROOT}/sets/set_bodies.inc;-Wno-unused-function")

foreach(_setnum ${SYNDROME_BUILT_SETNUMS})
    string(REPLACE "_" ";" _lp "${_setnum}")
    list(GET _lp 0 _lam)
    list(GET _lp 1 _n0)
    set(_tgt syndrome_dudect_${_setnum})

    # Reuse ichor's generic harness infrastructure and self-test sentinels
    # verbatim (single source of truth); only the registry main and the syndrome
    # targets are ours.
    add_executable(${_tgt}
        ${ICHOR_DUDECT}/dudect_runner.c
        ${ICHOR_DUDECT}/dudect_timer.c
        ${ICHOR_DUDECT}/dudect_platform.c
        ${ICHOR_DUDECT}/targets_sentinel.c
        dudect_main.c
        targets_syndrome.c)

    target_compile_definitions(${_tgt} PRIVATE
        SYNDROME_LAMBDA=${_lam} SYNDROME_N0=${_n0})
    target_include_directories(${_tgt} PRIVATE ${_dudect_includes})

    # talos_syndrome supplies the shared, parameter-free symbols the force-
    # included bodies still call out to (DRBG, bit vectors, dispatch); ichor
    # supplies clmul/AES/SHAKE; libm for sqrt() in the t-statistic.
    target_link_libraries(${_tgt} PRIVATE
        talos_syndrome ichor syndrome_warnings)
    if(NOT APPLE)
        target_link_libraries(${_tgt} PRIVATE m)
    endif()

    set_target_properties(${_tgt} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools/dudect)
endforeach()
