# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.16)

project(libtalos_syndrome
    VERSION 1.0.0
    DESCRIPTION "Clean-room QC-MDPC Niederreiter post-quantum KEM (ePrint 2025/1043)"
    LANGUAGES C)

#
# Language standard: C17, strict, no compiler extensions, no external deps.
#
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

#
# Options.
#
#
# Set-selection (liboqs OQS_MINIMAL_BUILD analog).  The library carries a
# caller-selected subset of the four (lambda, n0) sets.  SYNDROME_MINIMAL_BUILD
# is a ';'-separated token list; empty or OFF means "all sets".  Token grammar:
# SYN_<lambda>_<n0>.  Downstream per-set compilation and the dispatch registry
# iterate the surviving SYNDROME_ENABLE_SYN_* flags.
#
set(SYNDROME_MINIMAL_BUILD "" CACHE STRING
    "';'-separated list of sets to build (e.g. SYN_128_2;SYN_256_5); empty = all")

set(SYNDROME_ALL_SETS SYN_128_2 SYN_128_5 SYN_256_2 SYN_256_5)

option(SYNDROME_ENABLE_SYN_128_2 "Build the (lambda=128, n0=2) set" ON)
option(SYNDROME_ENABLE_SYN_128_5 "Build the (lambda=128, n0=5) set" ON)
option(SYNDROME_ENABLE_SYN_256_2 "Build the (lambda=256, n0=2) set" ON)
option(SYNDROME_ENABLE_SYN_256_5 "Build the (lambda=256, n0=5) set" ON)

# Force every set OFF, then re-enable exactly the listed tokens.  Errors on an
# unknown token and on an empty (zero-set) result.
function(filter_sets setlist)
    foreach(_set ${SYNDROME_ALL_SETS})
        set(SYNDROME_ENABLE_${_set} OFF PARENT_SCOPE)
    endforeach()
    foreach(_tok ${setlist})
        list(FIND SYNDROME_ALL_SETS "${_tok}" _idx)
        if(_idx EQUAL -1)
            message(FATAL_ERROR
                "SYNDROME_MINIMAL_BUILD: unknown set '${_tok}' (valid: ${SYNDROME_ALL_SETS})")
        endif()
        set(SYNDROME_ENABLE_${_tok} ON PARENT_SCOPE)
    endforeach()
endfunction()

if(NOT (SYNDROME_MINIMAL_BUILD STREQUAL "" OR SYNDROME_MINIMAL_BUILD STREQUAL "OFF"))
    filter_sets("${SYNDROME_MINIMAL_BUILD}")
endif()

# At least one set must survive.
set(_syndrome_enabled_sets "")
foreach(_set ${SYNDROME_ALL_SETS})
    if(SYNDROME_ENABLE_${_set})
        list(APPEND _syndrome_enabled_sets ${_set})
    endif()
endforeach()
if(_syndrome_enabled_sets STREQUAL "")
    message(FATAL_ERROR "SYNDROME_MINIMAL_BUILD enabled zero sets")
endif()
message(STATUS "syndrome sets (enabled): ${_syndrome_enabled_sets}")

#
# Map enabled sets to per-set wrapper TUs.  A wrapper is compiled only for a set
# that is both enabled and IMPLEMENTED.  All four (lambda, n0) sets are
# implemented; a set that is enabled but not in this list is reported and skipped
# rather than failing the configure.  Each compiled wrapper gets
# SYNDROME_BUILT_SYN_<set>=1, which the dispatch (syndrome.c) and set_vtable.h
# key on.
#
set(SYNDROME_IMPLEMENTED_SETS SYN_128_2 SYN_128_5 SYN_256_2 SYN_256_5)
set(_syndrome_wrappers "")
set(_syndrome_built_defs "")
set(SYNDROME_BUILT_SETNUMS "") # "<lambda>_<n0>" tokens, for the test harness
foreach(_set ${_syndrome_enabled_sets})
    list(FIND SYNDROME_IMPLEMENTED_SETS "${_set}" _impl_idx)
    if(_impl_idx EQUAL -1)
        message(STATUS "syndrome set ${_set} enabled but not yet implemented (Phase 2); skipped")
    else()
        string(TOLOWER "${_set}" _set_lc)
        list(APPEND _syndrome_wrappers "sets/${_set_lc}.c")
        list(APPEND _syndrome_built_defs "SYNDROME_BUILT_${_set}=1")
        string(REPLACE "SYN_" "" _setnum "${_set}") # SYN_128_2 -> 128_2
        list(APPEND SYNDROME_BUILT_SETNUMS "${_setnum}")
    endif()
endforeach()
if(_syndrome_wrappers STREQUAL "")
    message(FATAL_ERROR "no implemented syndrome set is enabled in this build")
endif()
message(STATUS "syndrome sets (built): ${_syndrome_built_defs}")

option(SYNDROME_BUILD_TESTING "Build the test harness" ON)
option(SYNDROME_BUILD_DUDECT "Build the dudect constant-time timing harness (tools/dudect)" OFF)
option(SYNDROME_BUILD_PROFILE_DRIVER "Build the standalone profiling/benchmark driver (tools/profile_driver)" OFF)

#
# Warning flags.  -Werror is on: the tree is fully implemented, so a new warning
# is a defect to fix rather than noise to tolerate.  The per-set wrapper TUs opt
# out of -Wunused-function only (they force-include the component selftests,
# which the library never calls; see the wrapper properties below).
#
include(CheckCCompilerFlag)
add_library(syndrome_warnings INTERFACE)
foreach(flag -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Werror)
    string(MAKE_C_IDENTIFIER "HAVE${flag}" flag_var)
    check_c_compiler_flag("${flag}" ${flag_var})
    if(${flag_var})
        target_compile_options(syndrome_warnings INTERFACE ${flag})
    endif()
endforeach()

#
# Memory-hardening flags.  This library's whole job is handling key material, so
# it is compiled with cheap exploit-mitigation defense-in-depth: stack canaries,
# stack-clash protection where the toolchain supports it, and glibc FORTIFY on
# optimized builds (where it is meaningful).  Position-independent code is set on
# the library target below.  Final-link hardening (RELRO/BIND_NOW, PIE) is the
# consuming executable's responsibility: this is a static archive and performs no
# link of its own.
#
add_library(syndrome_hardening INTERFACE)
# Probe each flag under -Werror.  Apple clang accepts -fstack-clash-protection
# at the driver but does not apply it, emitting only -Wunused-command-line-
# argument; without -Werror in the probe the check passes, the flag is added,
# and the real build (which carries -Werror via syndrome_warnings) then makes
# that warning fatal.  Forcing the probe to treat the warning as an error means
# a flag the toolchain merely tolerates is correctly rejected here.
set(_syn_hardening_saved_req "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Werror")
foreach(flag -fstack-protector-strong -fstack-clash-protection)
    string(MAKE_C_IDENTIFIER "HAVE${flag}" flag_var)
    check_c_compiler_flag("${flag}" ${flag_var})
    if(${flag_var})
        target_compile_options(syndrome_hardening INTERFACE ${flag})
    endif()
endforeach()
set(CMAKE_REQUIRED_FLAGS "${_syn_hardening_saved_req}")
# FORTIFY needs an optimizer, so enable it only for non-Debug configs; undefine
# first so a distro that already predefines _FORTIFY_SOURCE does not trip a
# redefinition warning (which -Werror would make fatal).
target_compile_options(syndrome_hardening INTERFACE
    "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=2>")

#
# Profiling / hotspot-analysis build (opt-in, measurement only, never shipped).
#
# SYNDROME_PROFILE turns on one LLVM instrumentation mode across the whole
# stack in a single configure: the library, the ichor ExternalProject sub-build
# (so its AES / CLMUL / Grostl kernels are attributed too, not a black box), and
# the test drivers.  It is measurement scaffolding, not an optimizer: it never
# changes shipped codegen (no PGO), so the loop is profile, read, hand-optimize
# the source, rebuild clean, then re-run the dudect gate.
#
#   off       (default) no instrumentation.
#   xray      -fxray-instrument, function entry/exit tracing.  After a run:
#               llvm-xray account xray-log.* --sort=sum --instr_map <exe>
#               llvm-xray graph   xray-log.* --instr_map <exe> | dot -Tsvg >cg.svg
#   coverage  -fprofile-instr-generate -fcoverage-mapping, region hit counts
#             (a coarse profiler and a coverage view).  After a run:
#               LLVM_PROFILE_FILE=run.profraw <exe>
#               llvm-profdata merge -sparse run.profraw -o run.profdata
#               llvm-cov report <exe> -instr-profile=run.profdata
#
# Cycle-level analysis of one hot loop needs no build option: pipe
# `clang -O3 -S <tu>` into llvm-mca.  perf is the sampling route once installed
# (this build adds -g -fno-omit-frame-pointer for it and for symbolization).
#
set(_syn_profile_cflags_str "")   # forwarded verbatim into the ichor sub-build
set(SYNDROME_PROFILE "off" CACHE STRING
    "LLVM profiling instrumentation: off | xray | coverage")
set_property(CACHE SYNDROME_PROFILE PROPERTY STRINGS off xray coverage)

# Attribution mode for SYNDROME_PROFILE=xray.  The hot paths (decrypt, the
# bit-flip decoder, the syndrome map) inline their static helpers at -O2/-O3, so
# an ordinary xray trace collapses their cost into one enclosing frame.  Turning
# this ON adds -fno-inline and lowers the sled threshold to 1, so every helper
# survives as a real, individually-sledded function and the account/graph views
# break the decoder open.  It changes codegen, so absolute times are no longer
# representative: use it for attribution, not for the headline benchmark.
option(SYNDROME_PROFILE_NOINLINE
    "-fno-inline so inlined helpers are sampled (perf) or traced (xray) separately"
    OFF)

if(NOT SYNDROME_PROFILE STREQUAL "off")
    # Instrumentation perturbs timing, so a profiling artifact must never be the
    # binary the constant-time sign-off measures.  Refuse the unsafe combination
    # rather than silently emit a corrupt dudect verdict.
    if(SYNDROME_BUILD_DUDECT)
        message(FATAL_ERROR
            "SYNDROME_PROFILE=${SYNDROME_PROFILE} cannot be combined with "
            "SYNDROME_BUILD_DUDECT: instrumentation perturbs timing and would "
            "invalidate the constant-time measurement.  Profile in a separate "
            "build directory.")
    endif()
    # XRay and source-based coverage are Clang/LLVM features.
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "SYNDROME_PROFILE requires Clang (got '${CMAKE_C_COMPILER_ID}'); "
            "reconfigure with -DCMAKE_C_COMPILER=clang.")
    endif()

    # -g for symbolization and source mapping, frame pointers for clean stack
    # unwinding (and any later perf sampling).  Present in every mode.
    set(_syn_profile_cflags -g -fno-omit-frame-pointer)
    set(_syn_profile_ldflags "")

    if(SYNDROME_PROFILE STREQUAL "xray")
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
            message(FATAL_ERROR
                "SYNDROME_PROFILE=xray is wired for Linux only; use coverage "
                "elsewhere.")
        endif()
        if(SYNDROME_PROFILE_NOINLINE)
            # Attribution mode: keep static helpers as real functions
            # (-fno-inline) and sled all of them (threshold 1) so the trace can
            # see inside decrypt / the decoder.  Distorts absolute timing.
            list(APPEND _syn_profile_cflags
                -fxray-instrument -fxray-instruction-threshold=1 -fno-inline)
            message(STATUS
                "syndrome profiling: xray attribution mode "
                "(-fno-inline, full sled coverage; timing not representative)")
        else()
            # Default: sled only functions of >= 200 instructions so the trace
            # lands on the macro structure (keygen, decode, syndrome map)
            # instead of every inlined field op, and codegen stays realistic.
            list(APPEND _syn_profile_cflags
                -fxray-instrument -fxray-instruction-threshold=200)
        endif()
        list(APPEND _syn_profile_ldflags -fxray-instrument)
    elseif(SYNDROME_PROFILE STREQUAL "coverage")
        if(SYNDROME_PROFILE_NOINLINE)
            message(WARNING
                "SYNDROME_PROFILE_NOINLINE has no effect with "
                "SYNDROME_PROFILE=coverage; it applies to xray only.")
        endif()
        list(APPEND _syn_profile_cflags
            -fprofile-instr-generate -fcoverage-mapping)
        list(APPEND _syn_profile_ldflags -fprofile-instr-generate)
    else()
        message(FATAL_ERROR
            "SYNDROME_PROFILE: unknown mode '${SYNDROME_PROFILE}' "
            "(valid: off, xray, coverage)")
    endif()

    # Compile and link every target defined in this tree and its subdirs
    # (library, tests).  ichor is a separate ExternalProject and is instrumented
    # through its forwarded CMAKE_C_FLAGS at the ExternalProject_Add below, using
    # the space-joined string form.
    add_compile_options(${_syn_profile_cflags})
    add_link_options(${_syn_profile_ldflags})
    string(JOIN " " _syn_profile_cflags_str ${_syn_profile_cflags})

    message(STATUS
        "syndrome profiling: ${SYNDROME_PROFILE} (measurement build; not for "
        "shipping or the dudect gate)")
elseif(SYNDROME_PROFILE_NOINLINE)
    # No LLVM instrumentation, just de-inline so a sampling profiler (perf)
    # attributes decrypt / decoder internals to their own symbols instead of
    # folding them into one enclosing frame.  Stock GCC/Clang flag; forwarded to
    # ichor too so its kernels (clmul, AES, Grostl) de-inline as well.  Changes
    # codegen, so absolute timing is not representative: attribution only.
    set(_syn_noinline_flags -g -fno-omit-frame-pointer -fno-inline)
    add_compile_options(${_syn_noinline_flags})
    string(JOIN " " _syn_profile_cflags_str ${_syn_noinline_flags})
    message(STATUS
        "syndrome profiling: de-inline for perf (-fno-inline; no LLVM "
        "instrumentation, timing not representative)")
endif()

#
# Shared symmetric primitives (AES, SHAKE/SHA-3, constant-time util, CPU
# dispatch) come from libtalos_ichor, vendored as a submodule under
# third_party/ and built from source via ExternalProject as an isolated
# sub-build (the libtalos_geryon / libsodium pattern): ichor configures and
# builds with its own CMake in its own binary dir, and syndrome consumes the
# resulting static archive through an IMPORTED target named `ichor`, so
# neither project's cache variables, options, or global flags leak into the
# other.  Built without ichor's test suite.  ichor types never appear in the
# public talos_syndrome.h surface, but the link is PUBLIC so internal-header
# consumers (the test suite includes core/core.h, which references
# <ichor/version.h> for the version guard) inherit the include dir.
#
# Dependency injection: a parent project that already builds ichor (e.g.
# libtalos_voleith embedding both syndrome and ichor as ExternalProjects)
# passes -DSYNDROME_ICHOR_LIB=<libtalos_ichor.a> and
# -DSYNDROME_ICHOR_INCLUDE_DIR=<ichor include/> to skip the sub-build here.
# This avoids compiling ichor twice and, more importantly, guarantees exactly
# one ichor version in the final link: libtalos_syndrome.a does not embed
# ichor's objects, so whichever ichor the top-level project links satisfies
# syndrome's references too, and two differently-pinned submodule builds in
# one process would be a silent version skew.
#
# All SIMD acceleration (PCLMULQDQ/PMULL carry-less multiply, AES-NI/ARMv8
# AES) and its portable software fallback live in ichor: the only carry-less
# multiply syndrome performs is ichor_clmul64 (core/gf2x.c), dispatched at
# runtime by ichor_clmul64_resolve().  syndrome carries no hardware intrinsics
# of its own and so needs no SIMD build flags; ichor selects and validates the
# backend (ichor's test_clmul KAT and dudect harness prove HW/fallback parity).
#
set(SYNDROME_ICHOR_LIB "" CACHE FILEPATH
    "Prebuilt libtalos_ichor.a to link instead of building the submodule")
set(SYNDROME_ICHOR_INCLUDE_DIR "" CACHE PATH
    "Include directory for the prebuilt ichor (its include/)")

# Test-only: compile ichor's ICHOR_FORCE_BACKEND env override into the sub-build
# so CI can force the constant-time software fallback (ICHOR_FORCE_BACKEND=
# "aes:bitsliced,clmul:scalar") on an accelerated runner and re-run the suite
# over it -- fallback paths get primary-path validation.  OFF by default: a
# shipped build must never read the environment for backend dispatch.  Ignored
# when ichor is injected (SYNDROME_ICHOR_LIB); the parent owns that build.
option(SYNDROME_ICHOR_ENABLE_FORCE_BACKEND
    "Compile ichor's software-fallback force hook (test/CI only; leave OFF for release)"
    OFF)

# Supported ichor version range: semver SameMajorVersion, i.e.
# [MIN, MAX) with MAX exclusive.  Enforced below against the version the
# ichor headers in use declare (submodule or injected alike), and again at
# compile time by the #error guard in core/core.h.  Raise MIN when syndrome
# starts depending on a feature added in a later 1.x; MAX moves only when
# syndrome is ported to a new ichor major.  MIN is 1.1.0: syndrome's gf2x,
# fixed-weight sampler, and scatter delegate to ichor's <ichor/gf2x.h> /
# <ichor/sample.h>, added in ichor 1.1.0 (absent from 1.0.0).
set(SYNDROME_ICHOR_VERSION_MIN 1.1.0)
set(SYNDROME_ICHOR_VERSION_MAX 2.0.0)

# The dudect harness pins ichor to its software fallback at startup, because the
# constant-time sign-off must measure the at-risk hand-written path, not the
# CT-by-construction AES-NI/CLMUL instructions (tools/dudect/README.md).  That
# needs ichor's ICHOR_FORCE_BACKEND hook compiled in, so enable it whenever
# dudect is built, on top of the explicit test/CI opt-in above.
set(_syn_ichor_force_backend ${SYNDROME_ICHOR_ENABLE_FORCE_BACKEND})
if(SYNDROME_BUILD_DUDECT)
    set(_syn_ichor_force_backend ON)
endif()

if(SYNDROME_ICHOR_LIB OR SYNDROME_ICHOR_INCLUDE_DIR)
    # Injected: both halves are required, and must exist.
    if(NOT SYNDROME_ICHOR_LIB OR NOT SYNDROME_ICHOR_INCLUDE_DIR)
        message(FATAL_ERROR "SYNDROME_ICHOR_LIB and SYNDROME_ICHOR_INCLUDE_DIR must be set together")
    endif()
    if(NOT EXISTS "${SYNDROME_ICHOR_INCLUDE_DIR}/ichor/util.h")
        message(FATAL_ERROR "SYNDROME_ICHOR_INCLUDE_DIR does not contain ichor/util.h: '${SYNDROME_ICHOR_INCLUDE_DIR}'")
    endif()

    add_library(ichor STATIC IMPORTED GLOBAL)
    set_target_properties(ichor PROPERTIES
        IMPORTED_LOCATION             "${SYNDROME_ICHOR_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${SYNDROME_ICHOR_INCLUDE_DIR}")

    set(_ichor_effective_include_dir "${SYNDROME_ICHOR_INCLUDE_DIR}")

    # An injected ichor is the parent's build; syndrome cannot add the force
    # hook to it.  If dudect is being built against one, the harness's
    # software-fallback pin is a no-op unless that ichor already carries
    # ICHOR_ENABLE_FORCE_BACKEND, and the sign-off would silently measure the
    # hardware backend instead.
    if(SYNDROME_BUILD_DUDECT)
        message(WARNING
            "SYNDROME_BUILD_DUDECT with an injected ichor (SYNDROME_ICHOR_LIB): "
            "the dudect harness forces the software fallback via "
            "ICHOR_FORCE_BACKEND, which is a no-op unless the injected ichor was "
            "built with ICHOR_ENABLE_FORCE_BACKEND.  Rebuild that ichor with the "
            "hook, or the constant-time sign-off will measure the hardware "
            "backend.")
    endif()
else()
    # Standalone: build the vendored submodule.
    include(ExternalProject)

    set(ICHOR_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libtalos_ichor")
    set(ICHOR_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/ichor-build")
    set(ICHOR_INCLUDE_DIR "${ICHOR_SOURCE_DIR}/include")
    set(ICHOR_LIB "${ICHOR_BINARY_DIR}/libtalos_ichor.a")

    ExternalProject_Add(ichor_build
        SOURCE_DIR "${ICHOR_SOURCE_DIR}"
        BINARY_DIR "${ICHOR_BINARY_DIR}"

        UPDATE_COMMAND ""
        PATCH_COMMAND  ""

        CMAKE_ARGS
            "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DCMAKE_C_FLAGS=${CMAKE_C_FLAGS} ${_syn_profile_cflags_str}"
            "-DICHOR_BUILD_TESTS=OFF"
            "-DICHOR_ENABLE_FORCE_BACKEND=${_syn_ichor_force_backend}"

        # ichor has no install rules; consume the archive from its binary dir.
        INSTALL_COMMAND ""

        # Unlike a pinned upstream (geryon's libsodium), ichor is co-developed
        # with syndrome, so re-run its build every time; a no-op rebuild is
        # cheap and edits to the submodule are never served stale.
        BUILD_ALWAYS TRUE

        BUILD_BYPRODUCTS "${ICHOR_LIB}"
    )

    add_library(ichor STATIC IMPORTED GLOBAL)
    add_dependencies(ichor ichor_build)
    set_target_properties(ichor PROPERTIES
        IMPORTED_LOCATION             "${ICHOR_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${ICHOR_INCLUDE_DIR}")

    set(_ichor_effective_include_dir "${ICHOR_INCLUDE_DIR}")
endif()

# Enforce the supported ichor version range against the headers in use.
# ichor/version.h is authoritative for the ichor version (its CMake checks it
# against project(VERSION) on ichor's side); an ichor too old to ship the
# header predates 1.0.0 and is out of range by definition.
set(_ichor_version_h "${_ichor_effective_include_dir}/ichor/version.h")
if(NOT EXISTS "${_ichor_version_h}")
    message(FATAL_ERROR "ichor/version.h not found under '${_ichor_effective_include_dir}'; this ichor predates ${SYNDROME_ICHOR_VERSION_MIN} (update the submodule pin or inject a newer ichor)")
endif()
file(STRINGS "${_ichor_version_h}" _ichor_ver_lines
    REGEX "#define ICHOR_VERSION_(MAJOR|MINOR|PATCH)")
string(REGEX MATCH "ICHOR_VERSION_MAJOR ([0-9]+)" _ "${_ichor_ver_lines}")
set(_ichor_major "${CMAKE_MATCH_1}")
string(REGEX MATCH "ICHOR_VERSION_MINOR ([0-9]+)" _ "${_ichor_ver_lines}")
set(_ichor_minor "${CMAKE_MATCH_1}")
string(REGEX MATCH "ICHOR_VERSION_PATCH ([0-9]+)" _ "${_ichor_ver_lines}")
set(_ichor_patch "${CMAKE_MATCH_1}")
if(_ichor_major STREQUAL "" OR _ichor_minor STREQUAL "" OR _ichor_patch STREQUAL "")
    message(FATAL_ERROR "could not parse ICHOR_VERSION_* from '${_ichor_version_h}'")
endif()
set(ICHOR_VERSION "${_ichor_major}.${_ichor_minor}.${_ichor_patch}")
if(ICHOR_VERSION VERSION_LESS SYNDROME_ICHOR_VERSION_MIN OR
   NOT ICHOR_VERSION VERSION_LESS SYNDROME_ICHOR_VERSION_MAX)
    message(FATAL_ERROR "ichor ${ICHOR_VERSION} is outside the supported range [${SYNDROME_ICHOR_VERSION_MIN}, ${SYNDROME_ICHOR_VERSION_MAX})")
endif()
message(STATUS "ichor ${ICHOR_VERSION} (supported range [${SYNDROME_ICHOR_VERSION_MIN}, ${SYNDROME_ICHOR_VERSION_MAX}))")

#
# The library.  One static archive: the two parameter-free shared TUs (DRBG +
# bit vectors), the public dispatch layer, and one wrapper TU per enabled +
# implemented set.  Each wrapper #includes the generic *_impl.inc bodies with
# its own (lambda, n0) constants, so the per-set algorithm code is not listed
# here directly.  The public header in include/ is the only consumer surface.
#
add_library(talos_syndrome STATIC
    core/bitvec.c
    core/rng.c
    syndrome.c
    ${_syndrome_wrappers})

# Each per-set wrapper force-includes set_bodies.inc (the full impl-body bundle)
# but references only the five vtable ops, so the bundled component selftests
# (syndrome_*_selftest) are intentionally dead in the library and trip
# -Wunused-function.  Suppress it for the wrapper TUs only -- exactly as the
# per-set test targets do (tests/CMakeLists.txt) -- keeping full unused-function
# checking on the real library sources (core/*, syndrome.c).
set_source_files_properties(${_syndrome_wrappers} PROPERTIES
    COMPILE_OPTIONS -Wno-unused-function)

target_include_directories(talos_syndrome
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core
            ${CMAKE_CURRENT_SOURCE_DIR}/code
            ${CMAKE_CURRENT_SOURCE_DIR}/decoder
            ${CMAKE_CURRENT_SOURCE_DIR}/pke
            ${CMAKE_CURRENT_SOURCE_DIR}/kem
            ${CMAKE_CURRENT_SOURCE_DIR}/opener
            ${CMAKE_CURRENT_SOURCE_DIR}/sets)

target_compile_definitions(talos_syndrome PRIVATE ${_syndrome_built_defs})
# ichor is PUBLIC for its include dir: the internal headers the test suite
# consumes (core/core.h) reference <ichor/version.h> for the version guard.
# ichor types still never appear in the public talos_syndrome.h surface, and
# the archive itself already propagated transitively for linking either way.
# Emit position-independent objects so a downstream PIE or shared library can
# link this static archive without recompiling it.
set_target_properties(talos_syndrome PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(talos_syndrome PRIVATE syndrome_warnings syndrome_hardening)
target_link_libraries(talos_syndrome PUBLIC ichor)

if(SYNDROME_BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

#
# Constant-time timing-validation harness (the empirical dudect gate that
# complements the source-level constant-time audit).  Opt-in and outside the
# test pipeline: a full run takes minutes and wants a quiet, frequency-pinned
# machine.  See tools/dudect/README.md.
#
if(SYNDROME_BUILD_DUDECT)
    add_subdirectory(tools/dudect)
endif()

#
# Standalone profiling / benchmark driver (a public-API workload for perf,
# XRay, llvm-cov, or plain wall-clock timing).  Opt-in and outside the test
# pipeline; independent of the SYNDROME_PROFILE instrumentation switch above.
#
if(SYNDROME_BUILD_PROFILE_DRIVER)
    add_subdirectory(tools/profile_driver)
endif()
