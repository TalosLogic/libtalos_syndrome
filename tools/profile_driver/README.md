<!--
Copyright (c) 2026 Jason Crawford
SPDX-License-Identifier: AGPL-3.0-only
-->

# profile_driver

A standalone timing workload over the public syndrome KEM + Argus API, for
hotspot profiling and benchmarking. It drives `keypair` / `encap` / `decap` /
`argus_open` in tight per-set loops so a profiler has something dense to
attribute, and it prints per-op min / median / throughput on its own.

It is built on the public API only (`talos_syndrome.h`), so it dispatches to
every built `(lambda, n0)` set at runtime; it does not force-include per-set
algorithm bodies the way `tools/dudect` does.

## Build

Opt in, then build; it is outside the test pipeline.

```sh
cmake -S . -B build-prof -DSYNDROME_BUILD_PROFILE_DRIVER=ON
cmake --build build-prof
```

The binary lands at `build-prof/tools/profile_driver/syndrome_profile`.

```
usage: syndrome_profile [iterations] [set] [op]
  iterations: 1..1000000 (default 50)
  set:        {128,192,256}_{2,3,4,5} (default all enabled; "-" also = all)
  op:         keygen | encap | decap | argus (default all)
```

Only sets compiled into this build (see `SYNDROME_MINIMAL_BUILD`) are run; a
filter naming a disabled set exits non-zero.

**Isolating one op for attribution.** Pass an `op` to time and profile a single
operation. Prerequisites still run, untimed, so the op works in isolation
(keypair always runs; encap runs when decap is profiled, to supply a
ciphertext), but only the selected op's loop is timed, so under a profiler the
samples are dominated by that op. Use `-` as the set to keep all sets while
naming an op:

```sh
./build-prof/tools/profile_driver/syndrome_profile 500 256_2 decap
./build-prof/tools/profile_driver/syndrome_profile 500 -     keygen
```

## Three ways to use it

The driver is decoupled from perf and from the `SYNDROME_PROFILE` instrumentation
switch, so the first mode needs no external tooling and works on any system.

### 1. Plain benchmark (no tooling)

```sh
./build-prof/tools/profile_driver/syndrome_profile 100
./build-prof/tools/profile_driver/syndrome_profile 200 256_5
```

Prints min / median wall-clock time and ops/sec per operation, per set.

### 2. perf (where installed)

The target always carries `-g` and frame pointers, so symbolized sampling works
even in this default, uninstrumented build.

```sh
# whole workload
perf record -g ./build-prof/tools/profile_driver/syndrome_profile 500 256_5
# one op in isolation (samples dominated by decap)
perf record -g ./build-prof/tools/profile_driver/syndrome_profile 500 256_2 decap
perf report            # or: perf report --stdio
```

perf is not required; its absence only removes this mode.

**Seeing inside an inlined frame.** At `-O2`/`-O3` the hot paths inline their
static helpers, so perf attributes everything to one enclosing symbol (e.g. all
of decode collapses into `syndrome_pke_decrypt`). To break that open for perf
without switching to xray, configure with `-DSYNDROME_PROFILE_NOINLINE=ON`: it
adds `-fno-inline` (stock GCC/Clang, forwarded to ichor too) so every helper
survives as its own sampled symbol. It changes codegen, so absolute times are
not representative: use it for attribution, then drop back to the default build
for timing.

```sh
cmake -S . -B build-perf -DSYNDROME_BUILD_PROFILE_DRIVER=ON -DSYNDROME_PROFILE_NOINLINE=ON
cmake --build build-perf
perf record -g ./build-perf/tools/profile_driver/syndrome_profile 500 256_2 decap
perf report   # attributes to gf2x_rotl_fixed / gf2x_reduce / bitflip_ctr_add / clmul64_pclmul
```

### 3. LLVM instrumentation

Layer the top-level `SYNDROME_PROFILE` switch on top; its flags reach this target
too, and they instrument the ichor sub-build as well, so the AES / CLMUL / Grostl
kernels are attributed rather than opaque.

XRay (function entry/exit tracing, Linux):

```sh
cmake -S . -B build-xray -DSYNDROME_BUILD_PROFILE_DRIVER=ON -DSYNDROME_PROFILE=xray
cmake --build build-xray
cd build-xray/tools/profile_driver
XRAY_OPTIONS="patch_premain=true xray_mode=xray-basic" ./syndrome_profile 200 256_5
llvm-xray account xray-log.* --sort=sum --top=25 --instr_map ./syndrome_profile
llvm-xray graph   xray-log.* --instr_map ./syndrome_profile | dot -Tsvg > cg.svg
```

By default only functions of >= 200 instructions are sledded, so the trace lands
on the macro structure (keygen, decode, syndrome map). The hot paths inline
their static helpers at `-O2`/`-O3`, so their cost collapses into one enclosing
frame (e.g. almost everything shows up under `syndrome_pke_decrypt`). To break
that open, add `-DSYNDROME_PROFILE_NOINLINE=ON`: it compiles with `-fno-inline`
and lowers the sled threshold to 1, so each helper (`syndrome_bitflip_decode`,
`syndrome_synmap_private`, `expand_block`, and ichor's kernels) survives as its
own traced function. That changes codegen, so absolute times are no longer
representative: use it for attribution, then drop back to the default build for
timing. Keep the traced iteration count low (e.g. `./syndrome_profile 5`),
because `xray-basic` logs every instrumented call.

Coverage (region execution counts):

```sh
cmake -S . -B build-cov -DSYNDROME_BUILD_PROFILE_DRIVER=ON -DSYNDROME_PROFILE=coverage
cmake --build build-cov
cd build-cov/tools/profile_driver
LLVM_PROFILE_FILE=run.profraw ./syndrome_profile 200 256_5
llvm-profdata merge -sparse run.profraw -o run.profdata
llvm-cov report ./syndrome_profile -instr-profile=run.profdata
```

On distributions that suffix the LLVM tools by version, use the suffixed names
(e.g. `llvm-xray-14`, `llvm-cov-14`, `llvm-profdata-14`).

For cycle-level analysis of a single hot loop, `llvm-mca` needs no build option:
pipe `clang -O3 -S <tu>` into it.

## Notes

- **Argus is profiled on a canonical tag.** A genuinely openable tag needs the
  sealing side, which is voleith's job and not part of syndrome's public API, so
  the driver builds the set's per-lambda default `prim_id` byte (`0x01` AES-DM at
  lambda 128, `0x02` Grostl-256 at lambda 256) followed by a zero syndrome and
  ct. The `prim_id` byte is mandatory: the fail-closed `prim_id` gate rejects any
  other id with `EUNSUPPORTED` before the decode path is reached. The
  constant-time opener then runs its full decode + KDF + OTP path regardless of
  openability (fixed iterMax, data-independent control flow), so the timing is
  representative; it returns `EUNOPENABLE`, expected here, not an error. `decap`
  on a real ciphertext is the honest decoder hot path and shares the same
  machinery.

- **Correctness smoke.** The driver checks that `decap` recovers `encap`'s shared
  secret and exits non-zero on mismatch.

- **Not a constant-time measurement.** This is a throughput / hotspot tool. It
  cannot be combined with `SYNDROME_BUILD_DUDECT`, and a `SYNDROME_PROFILE` build
  is refused for the dudect gate: instrumentation perturbs timing. Constant-time
  sign-off is `tools/dudect`, a separate build. The loop is profile here, hand-
  optimize the source, rebuild a clean Release, then re-run the dudect gate.
