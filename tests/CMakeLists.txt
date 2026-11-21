# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

#
# Test harness.  Binaries build into build/tests/ (docs/TESTING.md).  The user
# builds and runs tests manually; this file does not invoke ctest itself.
#
# Two shapes of test, matching the per-set library structure (P1.3/P1.4):
#
#   - Public / shared tests link talos_syndrome and use only the public set-id
#     API (or the shared, parameter-free DRBG / bit-vector symbols).  One binary,
#     iterating the enabled sets at runtime.
#
#   - Per-set component / KAT tests reach the internal (now static) selftests and
#     derand seams.  They force-include sets/set_bodies.inc (-include) with
#     -DSYNDROME_LAMBDA / -DSYNDROME_N0, so the test TU carries its own static
#     copy of one set's algorithm; the shared DRBG + bit vectors still come from
#     talos_syndrome.  One binary per built set, named <test>_<lambda>_<n0>.
#
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

set(_syn_test_includes
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/code
    ${CMAKE_SOURCE_DIR}/decoder
    ${CMAKE_SOURCE_DIR}/pke
    ${CMAKE_SOURCE_DIR}/kem
    ${CMAKE_SOURCE_DIR}/opener
    ${CMAKE_SOURCE_DIR}/sets)

#
# Add one per-set body-including test.  Usage:
#   syndrome_add_set_test(<name> <setnum> [SLOW])
# builds test_<name>.c into test_<name>_<setnum> for set "<lambda>_<n0>".
#
function(syndrome_add_set_test name setnum)
    string(REPLACE "_" ";" _lp "${setnum}")
    list(GET _lp 0 _lam)
    list(GET _lp 1 _n0)
    set(_tgt test_${name}_${setnum})

    add_executable(${_tgt} test_${name}.c)
    # Force-include the set's implementation bodies, compiled with this set's
    # constants; -D must precede the -include (the compiler applies -D first).
    target_compile_options(${_tgt} PRIVATE
        -include ${CMAKE_SOURCE_DIR}/sets/set_bodies.inc)
    # The force-included body bundle leaves most functions unused in any one
    # test TU.  -Wno-unused-function must beat syndrome_warnings' -Wall (which
    # re-enables -Wunused-function); target options are emitted BEFORE the
    # interface -Wall, so apply it as a source-file option, which is emitted
    # after it (same fix as the library wrappers in the top-level CMakeLists).
    set_source_files_properties(test_${name}.c PROPERTIES
        COMPILE_OPTIONS -Wno-unused-function)
    target_compile_definitions(${_tgt} PRIVATE
        SYNDROME_LAMBDA=${_lam} SYNDROME_N0=${_n0})
    target_include_directories(${_tgt} PRIVATE ${_syn_test_includes})
    target_link_libraries(${_tgt} PRIVATE talos_syndrome syndrome_warnings ichor)

    add_test(NAME ${name}_${setnum} COMMAND ${_tgt})
    if("${ARGN}" MATCHES "SLOW")
        set_tests_properties(${name}_${setnum} PROPERTIES LABELS "slow")
    endif()

    # Scheduling cost (approx wall-seconds from a sanitize run) so `ctest -j`
    # launches the long-pole tests first: better makespan, and it keeps the
    # RUN_SERIAL DFR gates from stranding cores at the tail.  Only the notably
    # slow 256-set KAT tests need it; the 128 sets are all <= 12 s and stay at
    # the default COST 0.  Refresh if timings drift materially.
    set(_cost 0)
    if(setnum STREQUAL "256_2")
        if(name STREQUAL "argus_kat")
            set(_cost 186)
        elseif(name STREQUAL "kem_kat")
            set(_cost 129)
        elseif(name STREQUAL "decode_kat")
            set(_cost 64)
        elseif(name STREQUAL "argus")
            set(_cost 34)
        endif()
    elseif(setnum STREQUAL "256_5")
        if(name STREQUAL "argus_kat")
            set(_cost 105)
        elseif(name STREQUAL "kem_kat")
            set(_cost 80)
        elseif(name STREQUAL "decode_kat")
            set(_cost 47)
        elseif(name STREQUAL "argus")
            set(_cost 38)
        endif()
    endif()
    if(_cost GREATER 0)
        set_tests_properties(${name}_${setnum} PROPERTIES COST ${_cost})
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Public / shared tests (one binary, iterate enabled sets at runtime).
# ---------------------------------------------------------------------------

# Smoke: library links, ichor wired, dispatch reports >=1 enabled set.
add_executable(test_smoke test_smoke.c)
target_link_libraries(test_smoke PRIVATE talos_syndrome syndrome_warnings ichor)
add_test(NAME smoke COMMAND test_smoke)

# KEM property battery over the public set-id API.
add_executable(test_kem test_kem.c)
target_link_libraries(test_kem PRIVATE talos_syndrome syndrome_warnings)
add_test(NAME kem COMMAND test_kem)
# Runs keygen/encap/decap across all sets, so it is one of the longer tests;
# front-load it under `ctest -j` (see the COST note in syndrome_add_set_test).
set_tests_properties(kem PROPERTIES COST 49)

# Proteus seed API (keypair_from_seed / keep_seed / pubkey_from_sk) over the
# public set-id API.  Does several keygens per set, so it is one of the longer
# tests; front-load it under `ctest -j`.
add_executable(test_seed test_seed.c)
target_link_libraries(test_seed PRIVATE talos_syndrome syndrome_warnings ichor)
add_test(NAME seed COMMAND test_seed)
set_tests_properties(seed PROPERTIES COST 120)

# Argus fail-closed signature-verification gate on the public dispatch.
add_executable(test_argus_gate test_argus_gate.c)
target_link_libraries(test_argus_gate PRIVATE talos_syndrome syndrome_warnings)
add_test(NAME argus_gate COMMAND test_argus_gate)

# NULL-buffer argument validation at the public KEM / seed API boundary.
add_executable(test_null_args test_null_args.c)
target_link_libraries(test_null_args PRIVATE talos_syndrome syndrome_warnings)
add_test(NAME null_args COMMAND test_null_args)

# DRBG (AES-256 CTR_DRBG): NIST KAT + determinism.  Shared, parameter-free.
add_executable(test_rng test_rng.c)
target_link_libraries(test_rng PRIVATE talos_syndrome syndrome_warnings)
target_include_directories(test_rng PRIVATE ${CMAKE_SOURCE_DIR}/core)
add_test(NAME rng COMMAND test_rng)

# Bit-vector helpers: accessors, constant-time weight, xor.  Shared.
add_executable(test_bitvec test_bitvec.c)
target_link_libraries(test_bitvec PRIVATE talos_syndrome syndrome_warnings)
target_include_directories(test_bitvec PRIVATE ${CMAKE_SOURCE_DIR}/core)
add_test(NAME bitvec COMMAND test_bitvec)

# Bit-sliced counter merge (ctr_merge): partial counters sum to the serial
# accumulation, any partition / fold order.  Shared, parameter-free.
add_executable(test_ctr_merge test_ctr_merge.c)
target_link_libraries(test_ctr_merge PRIVATE talos_syndrome syndrome_warnings)
target_include_directories(test_ctr_merge PRIVATE ${CMAKE_SOURCE_DIR}/decoder)
add_test(NAME ctr_merge COMMAND test_ctr_merge)

# Threaded-decode determinism: decap byte-identical across thread_count (S4).
# Public API only; links ichor for the thread pool the _ex path spins up.
add_executable(test_decode_threads test_decode_threads.c)
target_link_libraries(test_decode_threads PRIVATE talos_syndrome syndrome_warnings ichor)
add_test(NAME decode_threads COMMAND test_decode_threads)

# ---------------------------------------------------------------------------
# Per-set component / KAT tests (one binary per built set).
# ---------------------------------------------------------------------------
foreach(_setnum ${SYNDROME_BUILT_SETNUMS})
    # Component selftests + wire-format freeze.
    syndrome_add_set_test(gf2x        ${_setnum})
    syndrome_add_set_test(bitflip     ${_setnum})
    syndrome_add_set_test(threshold   ${_setnum})
    syndrome_add_set_test(qcmdpc      ${_setnum})
    syndrome_add_set_test(synmap      ${_setnum})
    syndrome_add_set_test(sample      ${_setnum})
    syndrome_add_set_test(sample_equiv ${_setnum})
    syndrome_add_set_test(niederreiter ${_setnum})
    syndrome_add_set_test(wire        ${_setnum})
    syndrome_add_set_test(argus       ${_setnum})

    # Fixed-seed KAT / regression gates (heavier; some labelled slow).
    syndrome_add_set_test(sample_kat  ${_setnum})
    # decode_kat consumes pinned input vectors (decode_kat_vectors.h) with
    # from-spec oracle outcomes (tools/decode_oracle), generated for all twelve
    # parameter sets.
    syndrome_add_set_test(decode_kat  ${_setnum} SLOW)
    syndrome_add_set_test(kem_kat     ${_setnum} SLOW)
    syndrome_add_set_test(argus_kat   ${_setnum} SLOW)

    # NIST-format KAT vector emitter (a tool that self-checks its digest).
    add_executable(kem_kat_gen_${_setnum} kem_kat_gen.c)
    string(REPLACE "_" ";" _lp "${_setnum}")
    list(GET _lp 0 _lam)
    list(GET _lp 1 _n0)
    target_compile_options(kem_kat_gen_${_setnum} PRIVATE
        -include ${CMAKE_SOURCE_DIR}/sets/set_bodies.inc)
    set_source_files_properties(kem_kat_gen.c PROPERTIES
        COMPILE_OPTIONS -Wno-unused-function)
    target_compile_definitions(kem_kat_gen_${_setnum} PRIVATE
        SYNDROME_LAMBDA=${_lam} SYNDROME_N0=${_n0})
    target_include_directories(kem_kat_gen_${_setnum} PRIVATE ${_syn_test_includes})
    target_link_libraries(kem_kat_gen_${_setnum} PRIVATE
        talos_syndrome syndrome_warnings ichor)
    add_test(NAME kem_kat_gen_${_setnum}
        COMMAND kem_kat_gen_${_setnum} kem_kat_${_setnum})
    # Emits + round-trips all cases: heavy for the 256 sets (see the COST note
    # in syndrome_add_set_test).
    if(_setnum STREQUAL "256_2")
        set_tests_properties(kem_kat_gen_${_setnum} PROPERTIES COST 110)
    elseif(_setnum STREQUAL "256_5")
        set_tests_properties(kem_kat_gen_${_setnum} PROPERTIES COST 42)
    endif()

    # Argus cross-firewall vector emitter (prints C arrays for voleith to pin).
    # A build-only tool: run the binary directly to capture its stdout; no
    # add_test (it is a generator, not a pass/fail gate).
    add_executable(argus_vectors_${_setnum} test_argus_vectors.c)
    target_compile_options(argus_vectors_${_setnum} PRIVATE
        -include ${CMAKE_SOURCE_DIR}/sets/set_bodies.inc)
    set_source_files_properties(test_argus_vectors.c PROPERTIES
        COMPILE_OPTIONS -Wno-unused-function)
    target_compile_definitions(argus_vectors_${_setnum} PRIVATE
        SYNDROME_LAMBDA=${_lam} SYNDROME_N0=${_n0})
    target_include_directories(argus_vectors_${_setnum} PRIVATE ${_syn_test_includes})
    target_link_libraries(argus_vectors_${_setnum} PRIVATE
        talos_syndrome syndrome_warnings ichor)
endforeach()

# ---------------------------------------------------------------------------
# Statistical (Monte-Carlo) DFR validation vs the closed-form model of
# ePrint 2025/1043 (docs/DESIGN.md section 4.2) -- REQUIRED before a release tag.
# Labelled `slow`: run the quick suite with `ctest -LE slow`, this with
# `ctest -L slow`.
#
# It needs a reduced waterfall-regime block size p, supplied via
# SYNDROME_TESTONLY_WATERFALL_P (which set_params.h honours for the lambda-128 /
# n0=2 set and for the n0=5 sets, keeping v/t/thresholds).  Like the other
# per-set tests it force-includes the bodies; -UNDEBUG re-arms the override's
# release-build refusal.  The harness carries its own (lambda, n0) via the
# force-include and links only the shared parameter-free DRBG / bit vectors from
# talos_syndrome, so a target is gated only on the matching lambda being present
# (via that lambda's shipped n0=2 setnum), not on its own set being built.
# Model DFR predictions per (n0, p) point are pinned in test_dfr_mc.c.
# ---------------------------------------------------------------------------
# The DFR Monte-Carlo harness partitions its trials across worker threads.
find_package(Threads REQUIRED)

function(syndrome_add_dfr_test lambda n0 p)
    set(_tgt test_dfr_mc_${lambda}_${n0}_p${p})
    add_executable(${_tgt} test_dfr_mc.c)
    target_compile_options(${_tgt} PRIVATE
        -include ${CMAKE_SOURCE_DIR}/sets/set_bodies.inc -UNDEBUG)
    set_source_files_properties(test_dfr_mc.c PROPERTIES
        COMPILE_OPTIONS -Wno-unused-function)
    # _POSIX_C_SOURCE must precede any system header; the -include bundle pulls
    # them in before test_dfr_mc.c's own #define, so set it here.
    target_compile_definitions(${_tgt} PRIVATE
        _POSIX_C_SOURCE=200809L
        SYNDROME_LAMBDA=${lambda} SYNDROME_N0=${n0}
        SYNDROME_TESTONLY_WATERFALL_P=${p})
    # On Darwin, strict _POSIX_C_SOURCE hides the sysconf(_SC_NPROCESSORS_ONLN)
    # extension the harness uses for thread auto-detection; _DARWIN_C_SOURCE
    # re-exposes it (must be a -D, like _POSIX_C_SOURCE, to beat the bundle's
    # system-header includes).
    if(APPLE)
        target_compile_definitions(${_tgt} PRIVATE _DARWIN_C_SOURCE)
    endif()
    target_include_directories(${_tgt} PRIVATE ${_syn_test_includes})
    target_link_libraries(${_tgt} PRIVATE
        talos_syndrome syndrome_warnings ichor m Threads::Threads)
endfunction()

# The DFR gates are RUN_SERIAL because the harness is itself multi-threaded (it
# grabs every core), so ctest -j must not run other tests alongside them.  A
# capped run that forces the harness single-threaded (the sanitize job, via
# SYNDROME_DFR_TRIALS below per_key -> one batch) does NOT need that exclusivity
# and should pack in parallel; such a build configures with
# -DSYNDROME_DFR_RUN_SERIAL=OFF.
option(SYNDROME_DFR_RUN_SERIAL
    "Mark the multi-threaded DFR gates RUN_SERIAL (turn OFF for capped/single-threaded runs)"
    ON)

# lambda-128 n0=2 waterfall points (p=10909 -> 2^-6.31 wired as the slow gate).
# The harness parallelizes over per-key batches (nbatches = trials/per_key), so
# per_key=500 gives 56 batches: a clean multiple of 8 cores, ~350 expected
# failures, ~90 s on an 8-core box (well under a 2-minute target; faster on more
# cores, TIMEOUT covers low-core CI).
if("128_2" IN_LIST SYNDROME_BUILT_SETNUMS)
    syndrome_add_dfr_test(128 2 10909)
    syndrome_add_dfr_test(128 2 11131)
    add_test(NAME dfr_mc_128_2_p10909
        COMMAND test_dfr_mc_128_2_p10909 28000 500)
    # RUN_SERIAL: the harness is itself multi-threaded (auto-detects cores at
    # runtime), so ctest -j must not run other tests alongside it; it never
    # oversubscribes and needs no hardcoded PROCESSORS count.
    # High COST so ctest -j starts this RUN_SERIAL (multi-threaded) gate early,
    # before it would otherwise strand cores at the tail.
    set_tests_properties(dfr_mc_128_2_p10909
        PROPERTIES LABELS "slow" TIMEOUT 7200
        RUN_SERIAL ${SYNDROME_DFR_RUN_SERIAL} COST 88)

    # n0=5 lambda-128 waterfall (subtask 2.4).  Wired gate: p=6053 -> model DFR
    # 2^-6.63, the shallow analog of the n0=2 gate (p=10909, 2^-6.31).  The
    # one-sided gate's power comes from the expected failure count; per_key=500
    # gives 72 batches (a multiple of 8 cores), ~360 expected failures, ~90 s on
    # an 8-core box.  Deeper points p=6163 (2^-9.24) and p=6299 (2^-13.07) are
    # built for manual by-hand runs with a larger trial count.
    syndrome_add_dfr_test(128 5 6053)
    syndrome_add_dfr_test(128 5 6163)
    syndrome_add_dfr_test(128 5 6299)
    add_test(NAME dfr_mc_128_5_p6053
        COMMAND test_dfr_mc_128_5_p6053 36000 500)
    set_tests_properties(dfr_mc_128_5_p6053
        PROPERTIES LABELS "slow" TIMEOUT 7200
        RUN_SERIAL ${SYNDROME_DFR_RUN_SERIAL} COST 66)
endif()

# n0=5 lambda-256 waterfall (subtask 2.4).  Decode at these p is expensive, so
# (like the n0=2 lambda-256 case) the points are built for manual runs on a fast
# box, not wired as a default ctest.  p=19603 -> 2^-6.10, p=19717 -> 2^-7.17.
if("256_2" IN_LIST SYNDROME_BUILT_SETNUMS)
    syndrome_add_dfr_test(256 5 19603)
    syndrome_add_dfr_test(256 5 19717)
endif()

# ---------------------------------------------------------------------------
# Real-p PKE round-trip failure dissector (test_dfr_probe) -- diagnostic for the
# intermittent honest-round-trip failure (decap K != encap K in test_kem).
# Unlike dfr_mc (reduced waterfall p, model gate), this runs the FULL PKE round-
# trip at the set's REAL p and, on each failure, classifies the layer: ct<->sp
# map bug / intrinsic floor (both decoders fail) / production decoder bug (dense
# oracle recovers e) / undetected miscorrection.  Built per set but NOT wired as
# a default ctest: it is a long-running manual probe (the real-p DFR is tiny, so
# it needs many trials).  Run e.g. ./test_dfr_probe_256_2 2000000.
# ---------------------------------------------------------------------------
function(syndrome_add_dfr_probe lambda n0)
    set(_tgt test_dfr_probe_${lambda}_${n0})
    add_executable(${_tgt} test_dfr_probe.c)
    target_compile_options(${_tgt} PRIVATE
        -include ${CMAKE_SOURCE_DIR}/sets/set_bodies.inc -UNDEBUG)
    set_source_files_properties(test_dfr_probe.c PROPERTIES
        COMPILE_OPTIONS -Wno-unused-function)
    target_compile_definitions(${_tgt} PRIVATE
        _POSIX_C_SOURCE=200809L
        SYNDROME_LAMBDA=${lambda} SYNDROME_N0=${n0})
    if(APPLE)
        target_compile_definitions(${_tgt} PRIVATE _DARWIN_C_SOURCE)
    endif()
    target_include_directories(${_tgt} PRIVATE ${_syn_test_includes})
    target_link_libraries(${_tgt} PRIVATE
        talos_syndrome syndrome_warnings ichor m Threads::Threads)
endfunction()

foreach(_setnum ${SYNDROME_BUILT_SETNUMS})
    string(REPLACE "_" ";" _probe_parts ${_setnum})
    list(GET _probe_parts 0 _probe_lam)
    list(GET _probe_parts 1 _probe_n0)
    syndrome_add_dfr_probe(${_probe_lam} ${_probe_n0})
endforeach()

# ---------------------------------------------------------------------------
# KEM-level round-trip dissector (test_dfr_kem_probe) -- same build shape as the
# PKE probe above, but runs the FULL KEM round-trip (keygen/encap/decap, compares
# K) and, on a mismatch, classifies decoder vs the FO / accept_kdf / valid-mask
# layer that the PKE probe cannot see.  Manual diagnostic, not a default ctest.
# Run e.g. ./test_dfr_kem_probe_256_2 2000000.
# ---------------------------------------------------------------------------
function(syndrome_add_kem_probe lambda n0)
    set(_tgt test_dfr_kem_probe_${lambda}_${n0})
    add_executable(${_tgt} test_dfr_kem_probe.c)
    target_compile_options(${_tgt} PRIVATE
        -include ${CMAKE_SOURCE_DIR}/sets/set_bodies.inc -UNDEBUG)
    set_source_files_properties(test_dfr_kem_probe.c PROPERTIES
        COMPILE_OPTIONS -Wno-unused-function)
    target_compile_definitions(${_tgt} PRIVATE
        _POSIX_C_SOURCE=200809L
        SYNDROME_LAMBDA=${lambda} SYNDROME_N0=${n0})
    if(APPLE)
        target_compile_definitions(${_tgt} PRIVATE _DARWIN_C_SOURCE)
    endif()
    target_include_directories(${_tgt} PRIVATE ${_syn_test_includes})
    target_link_libraries(${_tgt} PRIVATE
        talos_syndrome syndrome_warnings ichor m Threads::Threads)
endfunction()

foreach(_setnum ${SYNDROME_BUILT_SETNUMS})
    string(REPLACE "_" ";" _kprobe_parts ${_setnum})
    list(GET _kprobe_parts 0 _kprobe_lam)
    list(GET _kprobe_parts 1 _kprobe_n0)
    syndrome_add_kem_probe(${_kprobe_lam} ${_kprobe_n0})
endforeach()
