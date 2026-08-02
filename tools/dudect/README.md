# dudect: empirical constant-time validation (libtalos_syndrome)

A [dudect](https://github.com/oreparaz/dudect)-style timing-leakage harness
for the **secret-input entrypoints this library implements itself**. It is
gate 2 of `docs/CONSTANT_TIME.md`: the source audit (gate 1) proves the code
has no secret-dependent branch or memory access; this harness is the
empirical backstop that catches a leak a compiler may have re-introduced.

Each target times a function under two input classes (A and B), then applies
Welch's two-sample *t*-test to the cropped cycle samples. A small `|t|` over
many samples is evidence of no secret-dependent timing; a large `|t|` is
evidence of a leak.

Constant-time is a **security requirement** here, not a performance nicety:
this scheme leaks the private key on an observed decoding failure, so a
timing leak below the KEM boundary is a key-recovery side channel.

## Scope

Only **this library's** crypto. ichor's AES, SHAKE/SHA-3, AES-DM, Hirose,
and constant-time helpers are validated in ichor's own dudect harness
(`third_party/libtalos_ichor/tools/dudect/`); we consume them, we do not
re-validate them (`docs/CONSTANT_TIME.md` "Scope").

What this validates is that **syndrome's own code** is constant-time: the
masked fixed-weight sampler, the schoolbook gf2x multiply/reduce/inverse
loops, the bit-flip decoder, and the KEM/Argus glue. The carry-less multiply
primitive and AES/SHAKE underneath are ichor's, and ichor proves HW/fallback
parity and constant-timeness in its own suite. To spend the measurement budget
where it earns its keep, the harness **pins ichor to its software fallback by
default** (`ICHOR_FORCE_BACKEND=aes:bitsliced,clmul:scalar`, set in
`dudect_main.c`): the hardware AES-NI/CLMUL path is constant-time by
construction, so the empirical test matters on the hand-written scalar path that
ships to targets without crypto acceleration ("fallback paths get primary-path
validation"). A leak this harness reports is in syndrome's code.
(The library is built here as a dedicated static copy so the harness can link
the internal layers directly, and this build compiles ichor with its force hook
enabled so the pin takes effect.)

## Targets

| Target | Two classes | What it validates |
| --- | --- | --- |
| `sample_fixed_weight` | two RNG streams | masked Fisher-Yates: timing independent of the drawn positions |
| `bitflip_decode` | two private syndromes | fixed iterMax=3; decode success/failure timing-indistinguishable (the load-bearing decoder) |
| `kem_encap` | two RNG streams | F1 oblivious error expansion on the anonymity-critical path |
| `kem_decap` | valid vs. tampered ciphertext | constant-time implicit rejection (§4.6), the highest-value test |
| `argus_open` | two openable tags | F2 oblivious support extraction + the constant-time tail; only the §6.2 openable/not return value may vary |

The two `sentinel_*` targets (shared verbatim with ichor's harness) validate
the *harness itself*: `sentinel_leak` must FAIL and `sentinel_clean` must
PASS. If a sentinel reports the wrong verdict, the host is too noisy to trust
the real results.

## Building and running

**Off by default** and a standalone executable, not a CTest: runs are slow
and host-noise-sensitive and must not gate CI.

There is one harness per built parameter set, `syndrome_dudect_<lambda>_<n0>`
(the algorithm bodies are per-set static code, like the test binaries). The
sentinel targets are set-independent; each syndrome target validates that set's
code. Pick the set you want to check:

```sh
cmake -B build -DSYNDROME_BUILD_DUDECT=ON
cmake --build build --target syndrome_dudect_128_5   # or 128_2 / 256_2 / 256_5
# disable frequency scaling first for stable numbers:
sudo cpupower frequency-set -g performance
./build/tools/dudect/syndrome_dudect_128_5 --all
./build/tools/dudect/syndrome_dudect_128_5 --target kem_decap --verbose
./build/tools/dudect/syndrome_dudect_128_5 --list
```

The harness forces ichor's software fallback by default (see Scope). To measure
the hardware backend instead, set an explicit `ICHOR_FORCE_BACKEND` (even empty);
the harness uses `setenv(..., overwrite=0)` and will not override it:

```sh
ICHOR_FORCE_BACKEND= ./build/tools/dudect/syndrome_dudect_128_5 --all   # hardware
```

Verdict per target: `|t| > 4.5` → **FAIL**; `|t| <= 4.5` with at least
100 000 samples/class → **PASS**; otherwise **INCONCLUSIVE** (collect more
samples with `--samples`). Process exit code is non-zero if any target failed
or was inconclusive.

## Runtime: this is a slow tool, by design

Each target times a *whole crypto operation* (`reps_per_trial = 1`), unlike
ichor's per-instruction targets: one sample, inversion, decode, encap,
decap, or open already dominates the timer granularity, and these run on the
forced software fallback (see Scope). A single trial is **milliseconds**, so a
PASS-grade run (100 000 samples/class = 200 000 trials) is **~15-20 minutes
for `sample_fixed_weight`** and minutes each for the rest; a full `--all` is
an overnight run, not interactive.

Recommended workflow:

```sh
# 1. Sanity-check the host (seconds): sentinels must verdict correctly.
./build/tools/dudect/syndrome_dudect_128_5 --target sentinel_leak    # must FAIL
./build/tools/dudect/syndrome_dudect_128_5 --target sentinel_clean   # must PASS

# 2. Quick directional smoke per target (a few minutes; expect INCONCLUSIVE,
#    but a gross leak shows up early and |t| should stay small).
./build/tools/dudect/syndrome_dudect_128_5 --target kem_decap --samples 5000 --verbose

# 3. Sign-off: full PASS-grade run, one heavy target at a time, overnight.
./build/tools/dudect/syndrome_dudect_128_5 --target sample_fixed_weight
```

`--verbose` prints the running `|t|` every 10 %, so you can watch it converge
and `Ctrl-C` early; the SIGINT handler stops cleanly and still prints the
partial summary for whatever samples were collected.
