# Changelog

All notable changes to libtalos_syndrome are recorded here. See
[`docs/DESIGN.md`](docs/DESIGN.md) for the authoritative design rationale behind
each item.

## 1.1.0

### Added

- **Eight more parameter sets** completing all twelve rows of ePrint 2025/1043
  Table 2 (the `λ192` level plus the `n₀ ∈ {3, 4}` fills). Enabled by default;
  `syndrome_set_id` values appended, existing ids unchanged.
  [`docs/DESIGN.md` §3](docs/DESIGN.md#parameter-sets).
- **Argus opener KDF at λ192** (Grøstl-256 truncated to 24 bytes).
  [`docs/DESIGN.md` §6.2](docs/DESIGN.md#argus-recipe).
- **Optional multi-threaded decode**: `syndrome_kem_decap_ex` /
  `syndrome_argus_open_ex` + `syndrome_opts_t`, byte-identical at any thread
  count. See the README "Threading" section.

### Performance

- SIMD decoder counter kernels (SSE2 / AVX2 / NEON, scalar floor), all
  bit-identical.
- Threaded decode over the support loop (n₀ blocks batched per dispatch).
- Faster Argus support extraction and circulant ring arithmetic (the latter from
  the ichor 1.4.0 bump).

Serial single-core speedup over 1.0.0 on a Core i9 (median of 5000 iterations
per op), for the four sets that shipped in 1.0.0:

| set   | keypair | encap | decap | argus_open |
|-------|---------|-------|-------|------------|
| 128_2 | 2.0×    | 1.7×  | 4.0×  | 3.4×       |
| 128_5 | 1.7×    | 1.7×  | 4.0×  | 3.7×       |
| 256_2 | 2.0×    | 1.9×  | 4.1×  | 3.7×       |
| 256_5 | 1.9×    | 2.0×  | 4.6×  | 4.1×       |

### Fixed

- Intermittent decapsulation mismatch at real parameters, from an
  `ichor_gf2x_scatter` span-check bug that inflated the failure rate above the
  design DFR; fixed via the ichor 1.4.0 bump.

### Changed

- Vendored `libtalos_ichor` bumped to 1.4.0 (gf2x SIMD backends + constant-time
  hardening). Wire-compatible; the additive `_ex` entry points are the only API
  change, hence the minor bump.

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
