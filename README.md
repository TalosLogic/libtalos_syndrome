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

> **Status: 1.0.0.** All four parameter sets are implemented, validated against
> pinned KATs, and constant-time-audited (dudect). `docs/DESIGN.md` is the
> authoritative design record.

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
| 3     | `decoder/`  | 3-iteration parallel bit-flipping decoder (Alg. 1), per-set thresholds   |
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

## Parameter sets

Long-Term sets only (`DFR ≤ 2⁻λ`), selected at build time. Two block counts ship:
`n₀ = 2` (smallest public key) and `n₀ = 5` (cheapest voleith circuit). The
Ephemeral `2⁻⁶⁴` sets from the paper are deliberately not exposed. Sizes below
are exact bytes.

| set id           | λ   | n₀ | `p`   | `v` | `t` | pk    | ct   | sk   |
|------------------|-----|----|-------|-----|-----|-------|------|------|
| `SYNDROME_SET_128_2` | 128 | 2  | 13613 | 69  | 130 | 1702  | 1702 | 340  |
| `SYNDROME_SET_128_5` | 128 | 5  | 7829  | 83  | 57  | 3916  | 979  | 894  |
| `SYNDROME_SET_256_2` | 256 | 2  | 43451 | 135 | 261 | 5432  | 5432 | 668  |
| `SYNDROME_SET_256_5` | 256 | 5  | 24733 | 165 | 113 | 12368 | 3092 | 1778 |

The Proteus root seed is 2λ bits (32 B @ λ128 / 64 B @ λ256); the persisted
self-describing blob adds an 8-byte header. λ = 192 and `n₀ ∈ {3, 4}` are
reference-only additive future sets. Decoder thresholds are pinned per set;
changing a parameter without re-deriving thresholds and re-validating the DFR
bound is a security bug. See [`docs/DESIGN.md`](docs/DESIGN.md) §3.

## Building

> The library depends only on a C17 toolchain, CMake ≥ 3.16, and the vendored
> `libtalos_ichor` submodule (layer-0 primitives).

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build/tests      # runs the test harness
```

By default all four sets are built. Trim the build with a semicolon-separated
token list:

| Option                  | Default | Meaning                                                         |
|-------------------------|---------|-----------------------------------------------------------------|
| `SYNDROME_MINIMAL_BUILD`| `""`    | Subset of sets to build, e.g. `"SYN_128_2;SYN_256_2"` (empty = all) |
| `SYNDROME_BUILD_TESTING`| `ON`    | Build the test harness into `build/tests/`                      |
| `SYNDROME_BUILD_DUDECT` | `OFF`   | Build the per-set dudect constant-time timing harness (`tools/dudect/`) |

SIMD acceleration (PCLMULQDQ/PMULL, AES-NI/ARMv8 AES) and its portable software
fallback live entirely in `libtalos_ichor`, which selects the backend at runtime
and validates HW/fallback parity in its own suite; syndrome carries no hardware
intrinsics of its own.

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
