# libtalos_syndrome

A clean-room **C17** implementation of the QC-MDPC Niederreiter post-quantum
Key Encapsulation Mechanism from *"Efficient QC-MDPC Cryptosystems with Bounded
Decoding Failure Rate"* (IACR ePrint [2025/1043](https://eprint.iacr.org/2025/1043)),
plus a **designated-opener** facility (*Argus*) and a **Proteus** seed-based key
API (compact root-seed key persistence and public-key recovery).

The library is named for the Niederreiter ciphertext, which is the **syndrome**
`s = M · eᵀ` of a fixed-weight error vector `e` through a public QC-MDPC
parity-check matrix `M`. The name is scheme-neutral and survives a future
code-family swap (QC-MDPC → Goppa).

> **Status: 1.0.0.** All twelve parameter sets
> (`{λ128, λ192, λ256} × {n₀ 2, 3, 4, 5}`) are implemented and KAT-covered, each
> with a per-set dudect constant-time target. `docs/DESIGN.md` is the
> authoritative design record. (Version-file bump to 1.1.0 for the eight added
> sets is pending.)

## Why this library

- **Post-quantum** security from the hardness of the Syndrome Decoding Problem
  and QC-MDPC code indistinguishability. No discrete-log / elliptic-curve, no
  lattices, symmetric primitives only.
- A **general-purpose standalone KEM** with a clean keypair / encap / decap API
  shaped after NIST SP 800-227.
- A **designated-opener** facility (named *Argus*) layered on `decap`, so
  libtalos_voleith can "open" (de-anonymize) traceable ring-signature proofs.
- A **Proteus seed API**: a private key is a deterministic function of a small
  2λ-bit root seed, so an application can persist the seed instead of the full
  key, and recover `pk` from `sk` alone. A future unified KEM + signature
  credential (the seed as a signing witness) is in design and not part of this
  release.
- **Long-Term** parameter sets only, with a closed-form decoding-failure-rate
  (DFR) bound `≤ 2⁻λ`. A decoding failure leaks information about the private
  key, so a sound DFR bound is a security *requirement*, not a tuning knob.

### Scope and caveats

This scheme is **not NIST-standardized** (HQC won the code-based slot; the
QC-MDPC family / BIKE did not advance). For generic off-circuit use, **ML-KEM or
HQC are the right defaults.** This library's niche is binary-field-native,
compact-key, circuit-free designated opening for the voleith use case. It is not
a drop-in ML-KEM / HQC replacement.

## Architecture

Layered bottom-up; each layer depends only on those below it. The PKE/KEM
boundary is the primary abstraction: consumers use `encap`/`decap` and never
touch the decoder or code internals. Only the public header in `include/` is
consumer-facing. Layer-0 symmetric primitives (AES, AES-DM, Grøstl, SHAKE,
CLMUL) live in the vendored `libtalos_ichor` submodule.

| Layer | Directory   | Contents                                                                 |
|-------|-------------|--------------------------------------------------------------------------|
| 1     | `core/`     | circulant `F₂[x]/(xᵖ−1)` arithmetic, bit vectors, DRBG, constant-time fixed-weight sampling |
| 2     | `code/`     | private sparse `H`, public systematic `M = H₍ₙ₀₋₁₎⁻¹ H`, syndrome maps   |
| 3     | `decoder/`  | 3-iteration parallel bit-flipping decoder (Alg. 1), per-set thresholds; SSE2/AVX2/NEON bit-sliced counter kernels + optional threaded decode |
| 4     | `pke/`      | Niederreiter PKE: keygen, encrypt, decrypt (Fig. 1)                      |
| 5     | `kem/`      | KEM-DEM with an IND-CCA FO-style transform, constant-time implicit rejection |
| 6     | `opener/`   | Argus designated-opener facility, built on `decap`                       |

## Public API

Every entry point takes a `syndrome_set_id` first argument selecting the
parameter set (the id is public, never secret). Buffers are sized per set via the
runtime `syndrome_*_bytes` accessors, or the `SYNDROME_MAX_*` compile-time
ceilings. All functions return `0` on success and a negative value on failure.
See [`include/talos_syndrome.h`](include/talos_syndrome.h).

```c
#include <talos_syndrome.h>

/* General KEM (NIST SP 800-227 shape). */
int syndrome_kem_keypair(syndrome_set_id set, uint8_t *pk, uint8_t *sk);
int syndrome_kem_encap(syndrome_set_id set, uint8_t *ct, uint8_t *k, const uint8_t *pk);
int syndrome_kem_decap(syndrome_set_id set, uint8_t *k, const uint8_t *ct, const uint8_t *sk);

/* Proteus seed API: persist a small seed instead of the full key. */
int syndrome_kem_keypair_keep_seed(syndrome_set_id set, syndrome_xof_id xof,
    uint8_t *pk, uint8_t *sk, uint8_t *blob);
int syndrome_kem_keypair_from_seed(syndrome_set_id set, uint8_t *pk, uint8_t *sk,
    const uint8_t *blob);
int syndrome_kem_pubkey_from_sk(syndrome_set_id set, uint8_t *pk, const uint8_t *sk);

/* Designated-opener (Argus): recover an identity from a signature-verified tag.
 * gate must be SYNDROME_ARGUS_TAG_SIGNATURE_VERIFIED; opening an unverified tag
 * returns an unauthenticated identity (the OTP DEM is malleable), so any other
 * value is rejected. */
int syndrome_argus_open(syndrome_set_id set, uint8_t *identity_out, size_t identity_len,
    const uint8_t *tag, size_t tag_len, const uint8_t *sk, syndrome_argus_gate gate);
```

`encap` samples a fresh random weight-`t` error every time; `decap` performs
**constant-time implicit rejection** on decode failure (it returns a
deterministic pseudo-random shared secret, never an error; exposing a
decode-failure oracle would be a key-recovery oracle for QC-MDPC).

> **Using the Argus opener?** The open is unauthenticated by design: it returns a
> `K`-derived identity for any tag, and its `OK` status attests only that the
> syndrome decoded, never that the identity is genuine (the DEM is a malleable
> one-time pad, with no MAC). Your application MUST verify the enclosing
> ring-signature proof, or otherwise authenticate the tag, *before* calling
> `syndrome_argus_open`; the `gate` argument is your fail-closed attestation that
> you did. This is a plaintext-authentication requirement only: the opener private
> key is protected unconditionally regardless. See
> [`docs/DESIGN.md`](docs/DESIGN.md) §6.

### Threading

`syndrome_kem_decap_ex` (and the Argus opener) take an optional
`syndrome_opts_t` that parallelises the internal decode across an ichor thread
pool. There are two supported ways to provide one, and the shared secret is
byte-identical for both:

- **Library-owned (default):** leave `opts->pool` `NULL` (or pass `opts == NULL`).
  The library creates an internal pool sized by `thread_count` for the call and
  destroys it before returning.
- **Caller-provided:** set `opts->pool` to an `ichor_pool` you own. The library
  borrows it and never destroys it, so repeated calls reuse one pool instead of
  creating one per call; `thread_count` is then ignored.

Both modes are fully supported; **neither pool mode is promised to be faster
than the other.** Which one wins is platform- and workload-dependent (per-call
thread-creation cost versus pool-reuse wake behaviour differ across CPUs and
schedulers), so the library makes no claim between the two modes; if it matters,
measure on your own target. How threaded decode compares to the serial baseline
is shown under [Performance](#performance).

The result is byte-identical at any thread count, and threading preserves the
decoder's constant-time property. The internal parallelisation design (the
support-loop partition, the byte-identical merge, and why it stays constant-time)
is in [`docs/DESIGN.md` §4.10](docs/DESIGN.md#parallel-decode).

## Parameter sets

Long-Term sets only (`DFR ≤ 2⁻λ`), selected at build time. All twelve sets ship,
`{λ128, λ192, λ256} × {n₀ 2, 3, 4, 5}`: `n₀ = 2` gives the smallest public key,
`n₀ = 5` the cheapest voleith circuit, with `n₀ ∈ {3, 4}` between. The Ephemeral
`2⁻⁶⁴` sets from the paper are deliberately not exposed. Sizes below are exact
bytes.

| set id           | λ   | n₀ | `p`   | `v` | `t` | pk    | ct   | sk   |
|------------------|-----|----|-------|-----|-----|-------|------|------|
| `SYNDROME_SET_128_2` | 128 | 2  | 13613 | 69  | 130 | 1702  | 1702 | 340  |
| `SYNDROME_SET_128_3` | 128 | 3  | 10037 | 77  | 83  | 2510  | 1255 | 526  |
| `SYNDROME_SET_128_4` | 128 | 4  | 8627  | 81  | 66  | 3237  | 1079 | 712  |
| `SYNDROME_SET_128_5` | 128 | 5  | 7829  | 83  | 57  | 3916  | 979  | 894  |
| `SYNDROME_SET_192_2` | 192 | 2  | 26813 | 103 | 195 | 3352  | 3352 | 508  |
| `SYNDROME_SET_192_3` | 192 | 3  | 19709 | 115 | 124 | 4928  | 2464 | 786  |
| `SYNDROME_SET_192_4` | 192 | 4  | 16829 | 121 | 98  | 6312  | 2104 | 1064 |
| `SYNDROME_SET_192_5` | 192 | 5  | 15373 | 125 | 85  | 7688  | 1922 | 1346 |
| `SYNDROME_SET_256_2` | 256 | 2  | 43451 | 135 | 261 | 5432  | 5432 | 668  |
| `SYNDROME_SET_256_3` | 256 | 3  | 32069 | 153 | 165 | 8018  | 4009 | 1046 |
| `SYNDROME_SET_256_4` | 256 | 4  | 27437 | 161 | 131 | 10290 | 3430 | 1416 |
| `SYNDROME_SET_256_5` | 256 | 5  | 24733 | 165 | 113 | 12368 | 3092 | 1778 |

The Proteus root seed is 2λ bits (32 B @ λ128 / 48 B @ λ192 / 64 B @ λ256); the
persisted self-describing blob adds an 8-byte header. Decoder thresholds are
pinned per set; changing a parameter without re-deriving thresholds and
re-validating the DFR bound is a security bug. See
[`docs/DESIGN.md`](docs/DESIGN.md) §3.

## Performance

Measured on a Core i9 via `tools/profile_driver`, median of 5000 iterations per
op. These are illustrative throughput figures on one machine, not guarantees;
measure on your own target. Set ids are abbreviated `λ_n₀` (see the table above).

Serial (single thread):

| set   | keypair | encap | decap | argus_open |
|-------|---------|-------|-------|------------|
| 128_2 | 802     | 7800  | 825   | 510        |
| 128_3 | 1070    | 8349  | 656   | 483        |
| 128_4 | 1284    | 7970  | 609   | 464        |
| 128_5 | 1251    | 7254  | 522   | 416        |
| 192_2 | 311     | 3804  | 294   | 196        |
| 192_3 | 420     | 3962  | 243   | 177        |
| 192_4 | 513     | 3683  | 218   | 168        |
| 192_5 | 572     | 3312  | 182   | 144        |
| 256_2 | 156     | 2158  | 129   | 85         |
| 256_3 | 225     | 2143  | 117   | 84         |
| 256_4 | 270     | 2023  | 96    | 76         |
| 256_5 | 311     | 1857  | 90    | 72         |

Figures are op/s (higher is better). `keypair` and `encap` are single-threaded
and unaffected by the threading options below.

Threaded decode speedup over the serial figures above (8 threads, library-owned
per-call pool). Only `decap` and `argus_open` parallelise; threaded timings vary
more run-to-run, so these are representative, not peak:

| set   | decap | argus_open |
|-------|-------|------------|
| 128_2 | 1.3×  | 1.1×       |
| 128_3 | 1.7×  | 1.4×       |
| 128_4 | 1.6×  | 1.4×       |
| 128_5 | 1.7×  | 1.4×       |
| 192_2 | 1.8×  | 1.4×       |
| 192_3 | 2.1×  | 1.7×       |
| 192_4 | 2.0×  | 1.7×       |
| 192_5 | 2.1×  | 1.7×       |
| 256_2 | 1.9×  | 1.4×       |
| 256_3 | 2.3×  | 1.6×       |
| 256_4 | 2.5×  | 1.8×       |
| 256_5 | 2.4×  | 1.9×       |

## Building

> The library depends only on a C17 toolchain, CMake ≥ 3.16, and the vendored
> `libtalos_ichor` submodule (layer-0 primitives).

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build/tests      # runs the test harness
```

By default all twelve sets are built. Trim the build with a semicolon-separated
token list:

| Option                  | Default | Meaning                                                         |
|-------------------------|---------|-----------------------------------------------------------------|
| `SYNDROME_MINIMAL_BUILD`| `""`    | Subset of sets to build, e.g. `"SYN_128_2;SYN_256_2"` (empty = all) |
| `SYNDROME_BUILD_TESTING`| `ON`    | Build the test harness into `build/tests/`                      |
| `SYNDROME_BUILD_DUDECT` | `OFF`   | Build the per-set dudect constant-time timing harness (`tools/dudect/`) |

SIMD acceleration for the circulant ring and symmetric primitives
(PCLMULQDQ/PMULL, AES-NI/ARMv8 AES, and the gf2x AVX2/SSE2/NEON kernels) lives in
`libtalos_ichor`, which selects the backend at runtime and validates HW/fallback
parity in its own suite. The decoder adds its own runtime-dispatched
SSE2/AVX2/NEON kernels for the hot bit-sliced counter accumulate
(`decoder/ctr_add.c`), each bit-identical to the constant-time scalar floor and
gated behind the same CPU-feature detection; the scalar path is always compiled
in as the portable, constant-time baseline.

## Security model

- **Constant-time is load-bearing**: this scheme leaks the key on an observed
  decode failure. No secret-dependent branches, no secret-indexed memory access.
  Success vs. failure must be unobservable through timing or control flow at the
  KEM boundary; failure is handled by constant-time implicit rejection. The
  Argus opener is likewise constant-time and posture-agnostic.
- **The constant-time guarantee is tied to the default build.** The dudect
  evidence holds for the tested compiler and flags only. Do not add `-flto` or
  otherwise change the compiler/flags without re-running the dudect suite: LTO
  can inline ichor's out-of-line CT barriers and silently reintroduce a
  secret-dependent branch (observed with clang >= 17 in the opener support
  scatter). Re-verifying after any toolchain change is the builder's
  responsibility. Per-host timing evidence trails (Apple M1 / clang 17 and
  Intel Sandy Bridge / clang 19) live in [`docs/dudect-runs/`](docs/dudect-runs/).
- The decoder runs a fixed `iterMax = 3` with data-independent control flow, the
  exact parallel bit-flipping decoder of Algorithm 1.
- The Proteus seed is as sensitive as `sk`: the seed-expansion and keygen paths
  are constant-time in the seed and zeroize on every path.
- Sensitive material (private `H`, sampled `e`, shared secrets, seeds) is
  secure-zeroed on free.

## Clean-room policy

This implementation is derived **only** from the specifications in `docs/`:

1. [`docs/specs/2025-1043.pdf`](docs/specs/2025-1043.pdf): the QC-MDPC
   cryptosystem (authoritative for scheme, decoder, parameter sets).
2. [`docs/NIST.SP.800-227.pdf`](docs/NIST.SP.800-227.pdf): NIST SP 800-227,
   Recommendations for KEMs (authoritative for the KEM API shape and discipline).

No code is ported from any reference implementation. Reference decoders/KEMs are
used as **test oracles only**, never copied from.

## Documentation

`docs/DESIGN.md` is the authoritative design record (source of truth). The other
public documents are:

- [`docs/DESIGN.md`](docs/DESIGN.md): scheme, KEM/FO transform, Argus recipe
  (§6.2 is the byte-exact cross-firewall contract libtalos_voleith reproduces
  in-circuit), Proteus seed derivation, parameter sets, DFR analysis, spec
  deviations.
- [`docs/SEED_KEY_API.md`](docs/SEED_KEY_API.md): the Proteus seed-based key API
  reference.
- [`CHANGELOG.md`](CHANGELOG.md): release history.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
