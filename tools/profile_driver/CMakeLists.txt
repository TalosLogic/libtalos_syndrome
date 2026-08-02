# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
#
# Standalone profiling / benchmark driver over the public syndrome API.  Opt in
# with -DSYNDROME_BUILD_PROFILE_DRIVER=ON and run the binary manually; it is
# outside the test pipeline.
#
# Deliberately independent of SYNDROME_PROFILE (the top-level instrumentation
# switch): it links only the public library and is a plain wall-clock benchmark
# on its own, so it is useful on any system with no external tooling.  It always
# carries -g and frame pointers so `perf record` yields symbolized samples even
# in a default, uninstrumented build, whether or not perf is present.  Layer
# -DSYNDROME_PROFILE=xray|coverage on top to add LLVM instrumentation for
# llvm-xray / llvm-cov; the flags there apply to this target too.
#
# Unlike tools/dudect this needs no force-included per-set bodies: the driver
# reaches every built set at runtime through the public entry points, so it
# depends only on the public header and the archive.

add_executable(syndrome_profile profile_driver.c)

# Public API only.  talos_syndrome PUBLIC-exports include/, so linking it
# supplies talos_syndrome.h transitively (correct even when syndrome is embedded
# as a subproject).  syndrome_warnings keeps the driver under the same -Werror
# discipline as the rest of the tree.
target_link_libraries(syndrome_profile PRIVATE
    talos_syndrome ichor syndrome_warnings)

# Perf-ready on any system, independent of the instrumentation mode: debug line
# tables for symbolization and frame pointers for cheap stack unwinding.
target_compile_options(syndrome_profile PRIVATE -g -fno-omit-frame-pointer)

set_target_properties(syndrome_profile PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tools/profile_driver)
