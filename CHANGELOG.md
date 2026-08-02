# Changelog

All notable changes to libtalos_syndrome are recorded here. See
[`docs/DESIGN.md`](docs/DESIGN.md) for the authoritative design rationale behind
each item.

## 1.0.0

Initial release: a clean-room QC-MDPC Niederreiter post-quantum KEM with a
designated-opener facility and a seed-based key API.

- **QC-MDPC Niederreiter KEM** (ePrint 2025/1043): keypair / encap / decap with an
  IND-CCA FO-style transform and constant-time implicit rejection (no
  decode-failure oracle).
- **Four Long-Term parameter sets** (`DFR ≤ 2⁻λ`): `{λ128, λ256} × {n₀ 2, n₀ 5}`,
  selected at build time via `SYNDROME_MINIMAL_BUILD`. `n₀ = 2` minimizes public
  key size; `n₀ = 5` minimizes the in-circuit cost for libtalos_voleith.
- **Argus designated opener**: recover a traced identity from a tag `prim_id ‖ s ‖ ct`,
  layered on decap with an AES-DM (λ128) / Grøstl-256 (λ256) DEM-key KDF and a
  one-time-pad DEM. The byte-exact recipe is pinned in
  [`docs/DESIGN.md` §6.2](docs/DESIGN.md#argus-recipe) for in-circuit
  reproduction by voleith.
- **Proteus seed API**: persist a compact 2λ-bit root seed instead of the full
  key; deterministically reconstruct `(pk, sk)` from a self-describing seed blob;
  recover `pk` from `sk` alone. A unified KEM + signature credential built on this
  seed is a future direction, still in design and not part of this release.
- **3-iteration parallel bit-flipping decoder** (Algorithm 1) with fixed,
  data-independent control flow and per-set pinned thresholds; independently
  validated closed-form DFR bound.
- **Constant-time throughout**: no secret-dependent branches or memory indexing,
  constant-time comparisons, and secure-zeroization of all sensitive material.
  Validated empirically with a per-set dudect timing harness.
- **Layer-0 primitives** (AES, AES-DM, Grøstl, SHAKE, CLMUL with runtime backend
  dispatch and software fallback, plus the constant-time fixed-weight index
  sampler) provided by the vendored `libtalos_ichor` submodule; syndrome carries
  no hardware intrinsics of its own.
- **Frozen wire format**: the `(M, s)` circulant-block byte layout is the sole
  data contract shared with libtalos_voleith (little-endian, canonical zero
  padding), guarded by regression tests.
- **KAT coverage**: pinned KEM, decode, Argus, sample, and seed-path known-answer
  vectors gated in CI for every shipped set.

Scope note: this scheme is not NIST-standardized; for generic off-circuit use,
ML-KEM or HQC are the right defaults. This library's niche is binary-field-native,
compact-key, circuit-free designated opening for the voleith use case.
