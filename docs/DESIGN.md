# libtalos_syndrome Design Specification

This document specifies the cryptographic design of the KEM that
libtalos_syndrome builds on top of the QC-MDPC Niederreiter PKE of ePrint
2025/1043: what the KEM is, what it guarantees, and what it deliberately does
*not* do. It is the design of record and is public-facing: a consumer of the
library should be able to read it and understand the construction in full.

## 1. Introduction {#introduction}

Authority for the design is split across three sources:

- **`docs/specs/2025-1043.pdf`** governs the PKE (Fig. 1), the decoder
  (Algorithm 1), the parameter sets, and the decoding-failure-rate (DFR) bound.
- **`docs/NIST.SP.800-227.pdf`** governs the KEM interface shape and the
  encap/decap discipline.
- The CCA transform that bridges the two is this library's instantiation. The
  paper defines no bespoke transform; in its Concluding Remarks and in the
  Table 4 caption it obtains IND-CCA2 security through the modular
  Fujisaki-Okamoto (FO) analysis of Hofheinz-Hövelmanns-Kiltz (its reference
  [36]), "employing the same construction to turn a PKE into a KEM" as BIKE and
  LEDAcrypt-KEM. This library follows that framework, instantiated for the QROM.

Sections 2 and 3 fix what the spec dictates: the underlying PKE, and the
parameter sets and thresholds. Sections 4 through 7 specify this library's own
construction: the FO KEM transform, deterministic key generation, the
designated-opener (Argus) gadget, and the frozen wire format. Section 8 records
SP 800-227 conformance, section 9 catalogues every departure from the literal
text of 2025/1043, and section 10 states the scope and the claims not made.

Every place the implementation departs from the literal text of 2025/1043 is
catalogued in section 9, each with the reason and the effort to remove it. None
of the departures affects correctness, and the security-relevant ones are
required by the paper's own threat model.

## 2. The underlying PKE {#underlying-pke}

The PKE is fixed by Fig. 1 of 2025/1043. With block count `n0` (the shipped
sets use `n0 ∈ {2, 5}`, rate 1/2 or 4/5):

- **KeyGen.** Sample sparse `h_0, …, h_{n0-1} ∈ F_2[x]/(x^p − 1)`, each of odd
  weight `v`. Private key is `H = [H_0 | … | H_{n0-1}]` (circulant blocks).
  Public key is the systematic matrix `M = [M_0 | … | M_{n0-2} | I] =
  H_{n0-1}^{-1} H`.
- **Encrypt.** The "plaintext" is a fixed-weight error `e ∈ F_2^{n0·p}`,
  `wt(e) = t`. The ciphertext is the syndrome `s = M·eᵀ`, *and nothing else*.
- **Decrypt.** Compute `s' = H_{n0-1}·s`, run the parallel bit-flipping decoder
  (Algorithm 1, `iterMax = 3`) to recover `e`, or return ⊥ on decode failure.

Two properties of this PKE drive the rest of the design:

1. **The message space is the set of weight-`t` errors**, and encryption is a
   *deterministic* function of that message (`s = M·eᵀ`). There is no separate
   randomness and no separate payload field.
2. **A single observed decoding failure leaks the private key** (the standard
   QC-MDPC reaction attack). Decode success/failure must therefore be
   unobservable at the KEM boundary, and the DFR must be provably tiny.

## 3. Parameter sets and thresholds {#parameter-sets}

The table below lists **every** parameter set from Table 2 of 2025/1043, all
`n0 ∈ {2, 3, 4, 5}` at each λ, plus the Ephemeral (`128e`) rows, as an
at-a-glance reference for parameter selection and circuit sizing. `p`, `v`, `t`,
and the decoder thresholds are transcribed verbatim; the −log₂(DFR) column is the
independent recomputation of §3.2, which may differ from the paper's printed
figure by up to 0.1 (rounding). **The library builds all twelve Long-Term sets
`{λ128, λ192, λ256} × {n0 ∈ {2, 3, 4, 5}}`**, each with its own per-set dudect
target, selected at build time (`SYNDROME_MINIMAL_BUILD`; all enabled by
default). The thresholds are a security input tied to the DFR analysis: changing
a parameter without re-deriving thresholds and re-validating the DFR bound is a
security bug.

| λ    | n | `p`   | `v` | `t` | thresholds (it. 1/2/3) | −log₂(DFR) |
|------|---|-------|-----|-----|------------------------|------------|
| 128e | 2 | 12413 | 69  | 131 | 42 / 36 / 35           |  64.5      |
| 128e | 3 | 9203  | 79  | 83  | 47 / 42 / 41           |  65.0      |
| 128e | 4 | 7757  | 81  | 66  | 49 / 42 / 41           |  65.4      |
| 128e | 5 | 6947  | 83  | 57  | 50 / 43 / 43           |  64.2      |
| 128  | 2 | 13613 | 69  | 130 | 41 / 35 / 35           | 131.6      |
| 128  | 3 | 10037 | 77  | 83  | 45 / 41 / 40           | 128.2      |
| 128  | 4 | 8627  | 81  | 66  | 48 / 41 / 41           | 128.7      |
| 128  | 5 | 7829  | 83  | 57  | 49 / 42 / 42           | 130.4      |
| 192  | 2 | 26813 | 103 | 195 | 60 / 53 / 52           | 194.7      |
| 192  | 3 | 19709 | 115 | 124 | 66 / 60 / 59           | 193.8      |
| 192  | 4 | 16829 | 121 | 98  | 70 / 62 / 61           | 192.0      |
| 192  | 5 | 15373 | 125 | 85  | 71 / 66 / 64           | 193.1      |
| 256  | 2 | 43451 | 135 | 261 | 77 / 69 / 69           | 256.6      |
| 256  | 3 | 32069 | 153 | 165 | 87 / 78 / 78           | 256.3      |
| 256  | 4 | 27437 | 161 | 131 | 91 / 82 / 82           | 256.2      |
| 256  | 5 | 24733 | 165 | 113 | 93 / 85 / 84           | 256.5      |

The Ephemeral (`2⁻⁶⁴`, `128e`) rows are tabulated for completeness but **not
exposed** by the build: opener keys and general long-term KEM keys must be
long-term. They also buy little in practice: in a VOLE-in-the-Head circuit their
smaller parameters do not lower the dominant cost enough to matter, and even in a
plain forward-secrecy protocol the gain is marginal, since an ephemeral key must
ship a fresh public key for **every** shared-secret rotation, whereas one
Long-Term key is reused across many rotations. The `n0 ∈ {3, 4}` fill sets and the
λ = 192 level now ship alongside the original `n0 ∈ {2, 5}` sets at λ128 / λ256
(λ192 approaches λ256's cost for less security; `n0` 3/4 trade public-key size
against in-circuit cost between the n0=2 and n0=5 extremes), all over the
n0-generic path of §3.1. The Argus opener KDF at λ192 is Grøstl-256 truncated to
the leading 24 bytes (the 192-bit DEM key), domain-separated from λ256 by the IV
byte `0x18`; see §6.

The persisted root-seed size scales with the level:
`SYNDROME_KEYSEED_BYTES` = 2λ bits = 32 (λ128) / 64 (λ256). This is the size of
the deterministic key-generation seed exposed by the seed-based key API, not the
KEM's internal DRBG seed material (which is a fixed 48 bytes for both sets); §5
gives the distinction and the rationale.

### 3.1 Per-set constants are compile-time; dispatch is runtime at the boundary {#param-compile-time}

Each parameter set's constants are fixed at compile time, but a single binary
carries a caller-selected subset of sets and the public API dispatches on a
runtime `syndrome_set_id`. This is the liboqs pattern: the primitives are
compiled per variant and multiplexed by a dispatcher above the API, and runtime
`p` never leaks *inside* a primitive. Concretely, each set is its own translation
unit (`sets/syn_<lambda>_<n0>.c`) that `#define`s `SYNDROME_LAMBDA` /
`SYNDROME_N0`, includes the generic `*_impl.inc` bodies to materialize that set's
constants, and exports one `const syndrome_set_vtable`; `core/syndrome.c` selects the
vtable by `set_id`. The `set_id` is public, never secret, so dispatching on it is
not a side channel. Why the per-set constants stay compile-time rather than a
runtime `p`:

1. **No dynamic allocation; fixed-size buffers.** The parameter set expands into
   a web of compile-time sizing macros (`SYNDROME_PK_BYTES`, `SYNDROME_SK_BYTES`,
   `SYNDROME_CT_BYTES`, `SYNDROME_GF2X_LIMBS`, `BLOCK_BYTES`, …) used directly as
   stack-array and struct dimensions. The library's house rules require avoiding
   dynamic allocation in hot paths and secure-zeroing every sensitive buffer.
   A runtime `p` turns those buffers into VLAs or heap allocations, breaking the
   no-alloc rule, complicating secure-zeroing, and adding allocation-failure
   paths to code that today cannot fail that way. Callers that need fixed stack
   buffers across sets use the `SYNDROME_MAX_*` ceilings.

2. **One constant-time path per set to audit.** The decoder thresholds tabulated
   above, the masked fixed-weight sampler, and the gf2x reduce/inverse loops are
   specialized per `p`. Per-set compilation leaves each set as one straight-line
   code path to audit by hand and exercise under its own dudect binary
   (`syndrome_dudect_<set>`). A runtime `p` would push parameter-dependent
   branching into the hottest loops.

3. **A deployment picks one level.** This is not a TLS-style provider negotiating
   levels per connection. A deployment, in particular a libtalos_voleith
   designated-opener instance, fixes one security level and an opener key at that
   level, and the `(M, s)` byte-layout contract (§7) is itself per-parameter-set.
   Carrying multiple sets in one binary supports packaging and testing, not
   per-call level negotiation.

The build carries all enabled sets by default; `SYNDROME_MINIMAL_BUILD` trims the
set list (liboqs `OQS_MINIMAL_BUILD`, scaled to syndrome's flat set list), and
only the enabled sets contribute a vtable, so a disabled set reads back as "not
enabled" through `syndrome_set_enabled`.

### 3.2 Independent validation of the DFR bound {#dfr-validation}

The −log₂(DFR) column above was independently recomputed (2026-07-10), not just
transcribed from the paper. The authors of 2025/1043 publish a companion
implementation of their closed-form DFR model (`model_DFR_3it.zip`,
<https://crypto.deib.polimi.it/model_DFR_3it.zip>; not included in this
repository, as the archive carries no license file). It was compiled per its
README (`gcc model_DFR.c -o model_DFR -O3 -fopenmp -lm`) and run at exactly
this library's parameters and pinned thresholds:

```
./model_DFR 2 12413 69 131 1 42 36 35 1  -> 2,12413,69,131,1,42,36,35,3.94570101e-20,64.458280
./model_DFR 3 9203 79 83 1 47 42 41 1    -> 3,9203,79,83,1,47,42,41,2.78803381e-20,64.959314
./model_DFR 4 7757 81 66 1 49 42 41 1    -> 4,7757,81,66,1,49,42,41,2.08379289e-20,65.379350
./model_DFR 5 6947 83 57 1 50 43 43 1    -> 5,6947,83,57,1,50,43,43,4.79435325e-20,64.177226
./model_DFR 2 13613 69 130 1 41 35 35 1  -> 2,13613,69,130,1,41,35,35,2.34885051e-40,131.645169
./model_DFR 3 10037 77 83 1 45 41 40 1   -> 3,10037,77,83,1,45,41,40,2.55092376e-39,128.204176
./model_DFR 4 8627 81 66 1 48 41 41 1    -> 4,8627,81,66,1,48,41,41,1.79572075e-39,128.710633
./model_DFR 5 7829 83 57 1 49 42 42 1    -> 5,7829,83,57,1,49,42,42,5.57997072e-40,130.396866
./model_DFR 2 26813 103 195 1 60 53 52 1 -> 2,26813,103,195,1,60,53,52,2.52492032e-59,194.657520
./model_DFR 3 19709 115 124 1 66 60 59 1 -> 3,19709,115,124,1,66,60,59,4.45826668e-59,193.837275
./model_DFR 4 16829 121 98 1 70 62 61 1  -> 4,16829,121,98,1,70,62,61,1.54011516e-58,192.048791
./model_DFR 5 15373 125 85 1 71 66 64 1  -> 5,15373,125,85,1,71,66,64,7.43563851e-59,193.099301
./model_DFR 2 43451 135 261 1 77 69 69 1 -> 2,43451,135,261,1,77,69,69,5.79268315e-78,256.576160
./model_DFR 3 32069 153 165 1 87 78 78 1 -> 3,32069,153,165,1,87,78,78,7.00732650e-78,256.301527
./model_DFR 4 27437 161 131 1 91 82 82 1 -> 4,27437,161,131,1,91,82,82,7.77973418e-78,256.150671
./model_DFR 5 24733 165 113 1 93 85 84 1 -> 5,24733,165,113,1,93,85,84,6.14109796e-78,256.491895
```

All sixteen runs reproduce Table 2's parameters and land within 0.1 (rounding)
of its printed −log₂(DFR) figures, each satisfying DFR ≤ 2⁻λ with margin; the
thresholds for the shipped sets are pinned in `decoder/threshold.c`. This
validates the closed-form model and the thresholds at these exact parameters. It
is a validation of the model, not of this implementation's decoder behavior; that
the bound transfers to this decoder is checked separately, by comparing empirical
decode-failure rates of the sampler + decoder pipeline against the same model's
predictions in the measurable waterfall regime (reduced block sizes, same `v`,
`t`, and thresholds), as a required step of release validation.

### 3.3 Size calculations {#size-calcs}

Every public-surface size follows in closed form from the parameter set
`(λ, n0, p, v, t)`. The formulas below give each quantity in **bits**; the byte
columns in the table that follows round up to whole bytes, padding each circulant
block to a byte boundary exactly as the `(M, s)` wire does (§7).

| field | size (bits)          | unpacked (bits) |
|-------|----------------------|-----------------|
| pk    | `(n0 - 1) * p`       | N/A             |
| ct    | `p`                  | N/A             |
| sk    | `n0 * v * ⌈log₂(p)⌉` | `n0 * v * 16`   |
| e     | `t * ⌈log₂(n0 * p)⌉` | N/A             |

`pk` is the systematic matrix `M`; only `n0 - 1` blocks are stored, as the
trailing identity block is implicit. `ct` is the syndrome `s`, a single circulant
block (§4.2, error-as-message). `sk` here is the sparse private matrix `H` (its
`n0` weight-`v` support-index lists) and `e` is the fixed-weight error, its `t`
set positions held as ascending indices over `[0, n0 * p)`. For `sk` and `e`, the
**packed** form encodes each index in the minimal `⌈log₂(p)⌉` bits
(`⌈log₂(n0 * p)⌉` for `e`), while the **unpacked** form spends a full `uint16_t`
(16 bits) per index. Packing only pays off inside a VOLE-in-the-Head circuit,
where each bit is a wire; out of circuit the library stores the unpacked `sk`.

In the table below the bare `pk`, `e`, and `sk` columns are bit counts and the
`(B)` columns are bytes.

| λ    | n0 | pk    | pk (B) | ct (B) | e    | e (B) | sk    | sk (B) | sk unpacked |
|------|----|-------|--------|--------|------|-------|-------|--------|-------------|
| 128e | 2  | 12413 | 1552   | 1552   | 1965 | 246   | 1932  | 242    | 276         |
| 128e | 3  | 18406 | 2302   | 1151   | 1245 | 156   | 3318  | 415    | 474         |
| 128e | 4  | 23271 | 2910   | 970    | 990  | 124   | 4212  | 527    | 648         |
| 128e | 5  | 27788 | 3476   | 869    | 912  | 114   | 5395  | 675    | 830         |
| 128  | 2  | 13613 | 1702   | 1702   | 1950 | 244   | 1932  | 242    | 276         |
| 128  | 3  | 20074 | 2510   | 1255   | 1245 | 156   | 3234  | 405    | 462         |
| 128  | 4  | 25881 | 3237   | 1079   | 1056 | 132   | 4536  | 567    | 648         |
| 128  | 5  | 31316 | 3916   | 979    | 912  | 114   | 5395  | 675    | 830         |
| 192  | 2  | 26813 | 3352   | 3352   | 3120 | 390   | 3090  | 387    | 412         |
| 192  | 3  | 39418 | 4928   | 2464   | 1984 | 248   | 5175  | 647    | 690         |
| 192  | 4  | 50487 | 6312   | 2104   | 1666 | 209   | 7260  | 908    | 968         |
| 192  | 5  | 61492 | 7688   | 1922   | 1445 | 181   | 8750  | 1094   | 1250        |
| 256  | 2  | 43451 | 5432   | 5432   | 4437 | 555   | 4320  | 540    | 540         |
| 256  | 3  | 64138 | 8018   | 4009   | 2805 | 351   | 6885  | 861    | 918         |
| 256  | 4  | 82311 | 10290  | 3430   | 2227 | 279   | 9660  | 1208   | 1288        |
| 256  | 5  | 98932 | 12368  | 3092   | 1921 | 241   | 12375 | 1547   | 1650        |

Two notes for integrators. First, the `sk` columns account for `H` alone: the
full serialized secret key (`SYNDROME_SK_BYTES`) also carries the
implicit-rejection secret `σ` and the cached public-key hash `hpk`, each `2λ`
bits, adding `2 * SS_BYTES` = 64 / 96 / 128 B at λ128 / 192 / 256. So the stored
key is, for example, 340 B at `(λ128, n0=2)` and 668 B at `(λ256, n0=2)`. Second,
`pk (B)` and `ct (B)` match `SYNDROME_PK_BYTES = (n0 - 1) * ⌈p/8⌉` and
`SYNDROME_CT_BYTES = ⌈p/8⌉`: each circulant block byte-padded independently. The
shipped sets are `n0 ∈ {2, 5}`: `ct` is always one block (the single syndrome
`s`), while `pk` is `n0 - 1` blocks (one block at `n0 = 2`, four at `n0 = 5`).

## 4. KEM construction: the FO transform {#kem-transform}

Sections 4.1 through 4.7 fix the *shape* of the FO KEM that wraps the PKE of §2;
§4.8 pins the concrete byte encodings so the general KEM is reproducible and
KAT-able; §4.9 gives the reference pseudocode.

### 4.1 Fujisaki-Okamoto transform with implicit rejection {#fo-implicit-rejection}

The KEM turns the OW-CPA PKE into an IND-CCA2 KEM with the FO transform of HHK
(`T` then `U^{⊥̸}` in their taxonomy): derandomized re-encryption check at
decapsulation, shared secret derived through a hash, and **implicit rejection**
on failure (a deterministic pseudo-random shared secret, never an error).

*Why.* Implicit rejection is mandated by the project's non-negotiable design
decisions and is the correct choice here regardless: an explicit decode-failure
signal is a key-recovery oracle for QC-MDPC. `U^{⊥̸}` (implicit) over `U^{⊥}`
(explicit) removes that oracle by construction.

*Authority.* Transform: HHK [36], cited by 2025/1043 for IND-CCA2. Implicit
rejection: NIST SP 800-227 FO-style guidance; project decision #3.

### 4.2 Error-as-message: the ciphertext is the syndrome, and only the syndrome {#error-as-message}

The FO "message" is the weight-`t` error `e` itself. Encapsulation samples a
fresh `e`, and the ciphertext is exactly `ct = s = M·eᵀ`. The construction does
**not** adopt the BIKE-style variant that encapsulates a short seed and transmits
an additional masked-seed component alongside the syndrome.

*Why.*
- It matches Fig. 1 of the spec verbatim: the PKE ciphertext *is* the syndrome.
- It keeps `ct` to a single circulant block, which is the compact, fixed
  `(M, s)` byte layout shared with libtalos_voleith, the only cross-library
  contract. A masked-seed field would either break that layout or have to live
  outside it.
- The designated opener (Argus, §6) needs `e` itself; with error-as-message,
  decapsulation recovers `e` directly, so the opener layers cleanly on decap.

This is the same shape Classic McEliece uses (a Niederreiter KEM with implicit
rejection); the "same construction as BIKE/LEDAcrypt" the paper refers to is the
generic FO wrapper, and the absence of a masked-seed field here is simply because
the underlying PKE is pure Niederreiter rather than BIKE's hybrid PKE.

### 4.3 The shared secret binds the ciphertext (and the public key) {#shared-secret-binding}

The KDF takes the message *and* the ciphertext (and a cached public-key hash):
`K = KDF(dsK ‖ e ‖ s ‖ H(pk))`. This is the non-`m` FO variant, not `FO_m`.

*Why.* Binding `s` into the KDF gives multi-ciphertext / multi-target robustness
and closes known gaps in the FO security argument. Binding the public key
domain-separates shared secrets across keypairs.

*Authority.* SP 800-227: "Shared-secret derivation binds the ciphertext (and
public key) into the KDF."

### 4.4 No plaintext-confirmation field {#no-plaintext-confirmation}

The ciphertext carries no separate hash-of-`e` confirmation component. Integrity
is enforced entirely by the re-encryption check at decapsulation (recompute
`M·e'ᵀ` and compare to `s`, in constant time).

*Why.* A confirmation field would enlarge the ciphertext and, worse, perturb the
`(M, s)` layout that voleith depends on. The re-encryption check already gives
the rigidity the QROM proof needs (§4.5).

### 4.5 QROM target, via the tight implicit-rejection proof line {#qrom-target}

The KEM targets IND-CCA2 security in the **quantum** random oracle model, not
merely the classical ROM that HHK [36] is usually read in.

*Why and how.* The deterministic PKE with implicit rejection is exactly the
setting of the tight QROM reductions of Saito-Xagawa-Yamakawa and the
correctness-error-aware refinement of Bindel-Hamburg-Hövelmanns-Hülsing-
Persichetti. Those proofs avoid the loose `q·√δ` blow-up of generic QROM-FO
bounds, so the spec's DFR margins are adequate:

| set       | DFR bound (from Table 2) | target |
|-----------|--------------------------|--------|
| λ = 128   | ≤ 2⁻¹³¹·⁶                | 2⁻¹²⁸  |
| λ = 256   | ≤ 2⁻²⁵⁶·⁵                | 2⁻²⁵⁶  |

The re-encryption check (§4.4) supplies the rigidity these reductions require;
the fresh-`e`-per-encap rule (§4.2) supplies the message distribution they
assume.

*Caveat, stated plainly.* The QROM correctness term is the one subtlety that
couples the security target to the decoder: if the decoder/threshold analysis is
ever re-derived, the DFR margin must be re-checked against the QROM bound, not
just against `2⁻λ`.

### 4.6 Per-key rejection secret, constant-time selection {#rejection-secret}

The secret key stores a uniform rejection secret `σ`. On any decapsulation
failure (decode failed, weight wrong, or re-encryption mismatch) the shared
secret is `K = KDF(dsR ‖ σ ‖ s)`. The choice between the real and the rejection
secret is a single constant-time select; there is no branch, no early return, and
no timing difference between success and failure.

*Authority.* SP 800-227 implicit rejection; project decision #3.

### 4.7 Domain separation and symmetric primitives {#domain-separation}

All hashing uses the self-contained SHAKE/SHA-3 in `core/`. The KDF is a SHAKE
XOF producing `SYNDROME_SS_BYTES` of shared secret. The accept path (`dsK`), the
reject path (`dsR`), and the public-key hash use distinct domain-separation
prefixes. No external dependency; symmetric-only.

### 4.8 Concrete FO instantiation: the encap/decap byte recipe {#fo-byte-recipe}

Sections 4.1-4.7 fix the FO *shape*; this section pins the concrete encodings
that `kem/kem.c` implements, so the general KEM is reproducible and KAT-able.
(This is the general-purpose `syndrome_kem_*` KDF, software-only, SHAKE-based; it
is a *different* hash from the in-circuit Argus DEM-key KDF of §6.1.)

- **Hash/KDF: SHAKE-256 for every parameter set** (≥ λ security with one code
  path), squeezing `SYNDROME_SS_BYTES`.
- **Domain separation: one-byte prefixes** absorbed first: `DS_PKHASH = 0x01`,
  `DS_K = 0x02`, `DS_REJECT = 0x03`.
- **Cached public-key hash** `hpk = SHAKE256(DS_PKHASH ‖ M)`, `SS_BYTES` wide,
  stored in `sk` and recomputed by `encap` from `pk`.
- **Accept secret** `K = SHAKE256(DS_K ‖ e0 ‖ e1 ‖ ct ‖ hpk)`, with the error
  bound as the two dense `p`-bit blocks `e0 ‖ e1` (the wire packing) and
  `ct = s`. Binds the ciphertext and public key (§4.3).
- **Reject secret** `K = SHAKE256(DS_REJECT ‖ σ ‖ ct)`, with `σ` the per-key
  uniform secret (§4.6). **No `hpk`**: `σ` is drawn per keypair and already
  separates reject outputs across keys, matching FIPS 203 / ML-KEM
  (`J(z ‖ c)`). Symmetry with the accept path is available but adds nothing `σ`
  does not, so it is not adopted.
- **Re-encryption check realized by the decoder's `ok`.** `ok` is "residual
  private syndrome zero", i.e. `h0·e0' + h1·e1' == s'`; since `h1` is a unit
  this is exactly `M·e'^T == s`. So `sk` stores no `M` and `decap` does no
  inversion. A constant-time `wt(e') == t` check is added so the accepted
  preimage is the genuine weight-`t` error (decoding can in principle clear the
  syndrome with a different-weight vector). Together these realize the §4.4/§4.5
  rigidity.
- **Non-canonical ciphertext → implicit rejection.** The top
  `(8·BLOCK_BYTES − p)` padding bits of `ct` must be zero; a constant-time check
  folds any violation into the reject mask (the ring assumes canonical input;
  ML-KEM-style reject-non-canonical).
- **Constant-time selection.** `valid` is a byte mask (`0x00`/`0xFF`)
  AND-combined from canonical, `ok`, weight, and secret-key well-formedness
  (every deserialized `H` index `< p`, accumulated branch-free during
  deserialization); `K = select(valid, K_accept, K_reject)` byte-wise. `decap`
  runs one data-independent path and always returns 0, never a decode-failure
  oracle. The well-formedness term is defense-in-depth on the caller-supplied
  `sk`: a malformed key folds to implicit rejection instead of decoding as a
  plausible wrong key, and because it is a mask term (not a branch or an early
  return) the always-return-0 property is unchanged; for a valid `sk` it is
  all-ones, so nothing on the accept path moves.
- **Secret-key layout** `sk = H ‖ σ ‖ hpk`: `H` as the `n0` weight-`v` index
  lists, little-endian 16-bit per index (`p < 2^16`); then `σ` (`SS_BYTES`);
  then `hpk` (`PKHASH_BYTES = SS_BYTES`). `M` is not stored.
- **Randomness.** The public `keygen`/`encap` seed the AES-CTR DRBG from system
  entropy (`getentropy`) and delegate to derandomized internal entrypoints
  `syndrome_kem_{keypair,encap}_derand(…, syndrome_drbg *)`, the FIPS 203
  `KeyGen_internal`/`Encaps_internal` split (`kem/kem.h`), adapted to take an
  explicit DRBG since H sampling is a rejection loop rather than fixed coins.
  The fresh-`e`-per-encap rule (§4.2) follows from per-call sampling. KATs drive
  the derand entrypoints from a fixed 48-byte seed for reproducibility;
  `tests/test_kem_kat.c` does this and pins a SHA3-256 regression digest over
  (seed, pk, sk, ct, ss); there is no external vector for the Long-Term sets,
  so the digest is self-generated and pinned after a trusted run.

*Authority.* FO shape: §4.1-4.7. Implicit-rejection KDF shape (per-key secret +
ciphertext, no pk hash): FIPS 203 / SXY (§4.5). Re-encryption-as-decoder-residual:
the bit-flipping decoder sets `ok = (residual syndrome == 0)` (`decoder/
bitflip.c`). Constant-time discipline and no decode-failure oracle: a
non-negotiable security invariant of this library.

### 4.9 Reference construction (pseudocode) {#kem-pseudocode}

```
# Core: all key material is a deterministic function of a 2λ-bit root seed
# (§5).  seed is SYNDROME_KEYSEED_BYTES = 2λ bits.
KeyGenFromSeed(set, xof, seed):
    # header(8) = lambda/8 || n0 || xof_id || fmt || reserved(4)=0  (self-describing)
    dm     <- SHAKE256("TALOSProteus" || header || seed)  # 48-byte CTR_DRBG material
    drbg   <- CTR_DRBG_Init(dm)                          # AES-256 CTR_DRBG
    (H, M) <- PKE.KeyGen(drbg)         # H sparse weight-v; M = H_{n0-1}^{-1} H
    sigma  <- drbg[SYNDROME_SS_BYTES]
    hpk    <- SHAKE(ds_pk || M)
    sk = (H, sigma, hpk);  pk = M
    return (pk, sk)

# Wrapper: fresh key, seed discarded (the SP 800-227 keypair).
KeyGen():
    seed <- $ {0,1}^(8 * SYNDROME_KEYSEED_BYTES)
    return KeyGenFromSeed(seed)

# Wrapper: fresh key, seed returned so the caller can persist it.
KeyGenKeepSeed():
    seed         <- $ {0,1}^(8 * SYNDROME_KEYSEED_BYTES)
    (pk, sk)     <- KeyGenFromSeed(seed)
    return (pk, sk, seed)

# The public key is a deterministic function of the secret key alone.
PubKeyFromSk(sk = (H, sigma, hpk)):
    return M = H_{n0-1}^{-1} . H_0

Encap(pk = M):
    e  <- $ { weight-t vectors in F_2^(n0*p) }   # fresh each call, constant-time
    s  <- M . e^T                                 # ciphertext ct = s
    K  <- SHAKE(dsK || e || s || hpk)
    return (ct = s, K)

Decap(sk = (H, sigma, hpk), ct = s):
    s'        <- H_{n0-1} . s
    (e', ok)  <- BitFlippingDecoder(H, s')        # Alg. 1, iterMax = 3
    valid     <- ok AND (wt(e') == t) AND (M . e'^T == s)   # all constant-time
    K_real    <- SHAKE(dsK || e' || s || hpk)
    K_reject  <- SHAKE(dsR || sigma || s)
    return ct_select(valid, K_real, K_reject)     # constant-time, no branch
```

`encap` and `decap` execute the same control-flow path regardless of secret
data; `valid` is a bitmask, never a branch. The concrete byte encodings
(SHAKE-256, the one-byte domain prefixes, the `H ‖ σ ‖ hpk` secret-key layout,
and canonical-ciphertext rejection) are pinned in §4.8, and `M·e'^T == s` is
realized by the decoder's residual-syndrome `ok` flag rather than a separate
re-encryption.

### 4.10 Optional parallel decode {#parallel-decode}

The decoder is the dominant cost of both `decap` and Argus `open`, and it can
optionally run multi-threaded. The threaded entry points (`syndrome_kem_decap_ex`
/ `syndrome_argus_open_ex`, taking a `syndrome_opts_t`) are additive twins; the
non-`_ex` functions are the serial reference. Caller-facing setup (the two pool
ownership modes) is in the README; the internal design is here.

- **What is parallelised.** Within one decode, the per-iteration counter
  accumulation (the hot path) is partitioned over the support column-weight (`v`)
  loop, not over the `n0` blocks (too few to fill a pool). Each worker accumulates
  a private bit-sliced counter over its slice of the support; the partials are
  combined with a constant-time full-adder (a ripple-carry bit-sliced add, not an
  XOR). All `n0` blocks of a single decoder iteration are independent (they read
  the same not-yet-updated syndrome) and so batch into one pool dispatch, giving
  `SYNDROME_ITERMAX` dispatches per decode rather than `SYNDROME_ITERMAX · n0`.

- **Determinism (byte-identical for any thread count).** Integer addition is
  associative and commutative, so the merged counters, the resulting flips, and
  hence the recovered error and the derived shared secret are identical to the
  serial accumulation for every thread count and for the serial path. A
  determinism test (`tests/test_decode_threads`) pins this invariance, so
  threading never changes a decode result or a shared secret and leaves all KATs
  and goldens frozen.

- **Constant-time is preserved.** The partition bounds (`v`, `n0`, the per-worker
  chunk ranges) are public; every worker runs the same secret-driven constant-time
  barrel rotation per support offset; the running slot counters and the pool
  scheduling never depend on secret data; and each worker's scratch is private.
  So threading adds no secret-dependent branch, memory-access pattern, or timing
  path over the serial decoder: the only secret, the support, still enters solely
  as the rotation amount of §3's constant-time rotate.

- **Pool model (borrow-or-create).** A caller-supplied pool is borrowed and never
  destroyed (so a repeat caller reuses one pool); otherwise an internal pool sized
  by `thread_count` is created and destroyed within the call, and `thread_count ≤
  1` (or a `NULL` opts) runs the original serial loop. Nothing the library
  allocates outlives the call, there is no global mutable state, and the
  circulant-ring wrappers are reentrant (per-call stack scratch, §3.1), so
  concurrent workers never share mutable ring state. A pool-creation failure
  degrades to the serial path, never an error.

- **Non-claim.** Threading is a pure performance option. The speedup is
  Amdahl-bound by the unthreaded remainder and is platform- and
  workload-dependent, so the library makes no performance claim either way (§10);
  the serial path is the behavioral reference.

## 5. Deterministic key generation from a 2λ-bit root seed {#seed-keygen}

Key generation is factored so that a **seed-input function is the core
primitive** and every other creation path is a thin wrapper over it (the
pseudocode is in §4.9):

- `KeyGenFromSeed(seed)` does all the work: expand the seed, run the PKE keygen,
  derive σ, cache `hpk`.
- `KeyGen()` (the SP 800-227 keypair) draws a random seed, calls the core, and
  discards the seed.
- `KeyGenKeepSeed()` draws a random seed, calls the core, and additionally
  returns the seed for the caller to persist.
- `PubKeyFromSk(sk)` recomputes the public key from the secret key alone, since
  `M₀ = H₁⁻¹·H₀` is a deterministic function of `H` (the stored `H₁` is
  invertible by construction, so this is loop-free).

This gives two capabilities without changing the KEM proper: a private key can be
persisted as a small **root seed** and reconstructed byte-identically, and a
public key can be recovered from a secret key. It motivates two use cases: a
compressed key-at-rest (store the seed, rebuild `sk`+`pk` on startup), which
ships here, and a forward-looking direction still in design: the seed as a
VOLE-in-the-Head signing witness in voleith for a unified KEM+signature
credential, which is not part of this release.
The usage reference is `docs/SEED_KEY_API.md`; the public surface is in
`include/talos_syndrome.h`.

**Seed size is 2λ, and scales with the level:** `SYNDROME_KEYSEED_BYTES` = 32
(λ128) / 64 (λ256). The distinction that matters: this root seed is *not* the
KEM's internal DRBG seed material. That material is a fixed 48 bytes for both
parameter sets (an artifact of the internal AES-256 CTR_DRBG seedlen (32-byte
key + 16-byte V), the NIST PQC "randombytes" convention) and carries no
per-level meaning. The persisted root seed is decoupled from it by a SHAKE256
expansion, `dm[48] = SHAKE256("TALOSProteus" ‖ header ‖ seed)` with the
self-describing 8-byte `header = level ‖ n0 ‖ xof_id ‖ fmt ‖ reserved(4)`, which
lets the seed size track the security level and binds domain, level, n0, XOF, and
format version. A *secret* needs only λ bits against brute force (the birthday
inflation to 2λ applies to public collision-exposed values, not to secrets), so
λ bits would suffice; 2λ is chosen deliberately to neutralize multi-target key
search at negligible cost (a secret at exactly λ bits degrades under batch attack
over many published keys) and to match the scheme's existing 2λ sizing convention
(`SYNDROME_SS_BYTES` is already 32/64). The header binds (level, n0, xof_id) into
the expansion, so a λ128 seed cannot be reconstructed as λ256, an n0=2 seed cannot
be reconstructed as n0=5, and a key derived under one XOF cannot be reconstructed
under another.

**Frozen-ABI consequence.** Once shipped, the whole derivation pipeline (the
SHAKE256 expansion, the CTR_DRBG construction, the fixed-weight sampler, the `H₁`
resample-loop consumption pattern, and the σ draw) is a compatibility contract:
any change to any of it silently invalidates every stored seed. `fmt`
(`SYNDROME_SEED_FORMAT_VERSION`) exists to make such a change detectable at load
rather than producing a silently-wrong key. The signing-witness use in voleith is
unaffected by this freeze (its statement is over the seed and a hash, not the
DRBG internals) so only the KEM reconstruction depends on the pipeline staying
fixed.

*Authority.* Like the FO transform (§4.1) and the concrete byte recipe (§4.8),
this is *this library's* instantiation, not something 2025/1043 or SP 800-227
dictates; it sits above the PKE keygen and changes none of its security
properties. The seed is as sensitive as `sk` and is held to the same
constant-time and zeroization rules.

## 6. Designated opener (Argus) {#designated-opener}

Argus is a thin facility layered on `decap`, not a separate cryptosystem. A
voleith signer, inside its NIZK proof, encrypts its identity to the opener key
as a KEM-DEM tag: fresh weight-`t` error `e`, syndrome `s = M·eᵀ`, DEM key
`K = H(support(e))`, ciphertext `ct = identity ⊕ K` (a one-time pad). The opener
runs `decap` on `s`, recovers `e`, recomputes `K`, and decrypts `ct`.

Error-as-message (§4.2) is what makes this clean: decap already recovers `e`
exactly, so the opener needs no special decap variant. The KEM primitive itself
stays scheme-neutral and opener-agnostic; only the `opener/` layer is aware of
the voleith use case. A fresh random `e` per encapsulation (§4.2) is mandatory
for signer anonymity: a deterministic `e` would make `s` a static per-member
value.

The DEM-key KDF `K = H(support(e))` here is computed inside the voleith circuit
by the signer and recomputed by Argus, so it is **AES-round-based** (AES-DM at
λ=128, Grøstl-256 at λ=256), pinned per parameter-set version, deliberately *not*
the SHAKE KDF of the general KEM, which is software-only. The full reasoning
(in-circuit-expressibility, why collision resistance is not load-bearing here,
why these AES modes are sound long-term, and agility via versioning) is §6.1.

The concrete opener byte recipe, comprising tag layout `prim_id ‖ s ‖ ct`, the one-time-pad
DEM, the bit-packed ascending-index KDF encoding with fixed-length zero-padding,
the re-encryption-only validation, and the typed-failure return, is pinned in
§6.2 (`opener/argus.c`). The public surface is `syndrome_argus_open`, which takes
a mandatory, fail-closed gate argument attesting the tag passed signature
verification (the OTP DEM is unauthenticated, so an unverified tag opens to an
unauthenticated identity, §6.2), with typed
statuses; `SYNDROME_ARGUS_KEY_BYTES` is the extractor (`K`) width, and identities
up to `SYNDROME_ARGUS_ID_MAX_BYTES` (48 B at λ=128 / 96 B at λ=256) are supported
via an AES-CTR keystream extension of `K` (§6.2).

**Argus is not a standalone PKE.** The OTP DEM gives confidentiality but no
integrity (§8); the ciphertext integrity that makes the open trustworthy comes
from the *enclosing* voleith proof, which attests `(s, ct, identity)` are well
formed and mutually bound. So Argus is IND-CPA on the DEM in isolation but
IND-CCA2 only in-protocol, and **must only be run on tags that have passed
signature verification**. For standalone encrypt-to-recipient / hybrid use,
callers use the general KEM (`syndrome_kem_*`), which carries its own SHAKE KDF
and implicit-rejection CCA (§4.1, §4.8).

> **REQUIREMENT (application obligation).** Any application that uses the Argus
> opener MUST verify the enclosing ring-signature proof (or otherwise establish
> the tag's authenticity) *before* calling `syndrome_argus_open`. The open is
> unauthenticated by construction: it returns a `K`-derived identity for any tag,
> and its `SYNDROME_ARGUS_OK` status attests only that the syndrome decoded, never
> that `ct` or the recovered identity is genuine. syndrome cannot check the proof
> itself (it has no knowledge of the circuit or instance), so this obligation is
> the caller's and the `gate` argument is the caller's fail-closed attestation of
> it. The obligation is load-bearing for two reasons. First, plaintext
> authentication: the open is unauthenticated, so without a verified signature the
> recovered identity is not trustworthy. Second, key secrecy: the typed
> `SYNDROME_ARGUS_OK` / `EUNOPENABLE` status is a decode oracle on `H` for
> attacker-chosen tags (a QC-MDPC reaction attack, §8), and the gate is what denies
> an attacker chosen-tag access to it. The constant-time open closes the timing and
> cache channels but not the typed return value, and the DFR bound covers honest
> errors, not adversarial tags, so the key is not protected independently of this
> obligation.

### 6.1 In-circuit DEM-key KDF: AES-round-based (AES-DM / Grøstl-256), pinned per parameter-set version {#argus-kdf}

The designated opener derives its DEM key from the recovered error as
`K = H(support(e))`. This KDF is **distinct from the general-KEM shared-secret
KDF of §4.3/§4.7** and lives in a different place, which is the root of every
constraint below:

- The general-KEM `K = SHAKE(dsK ‖ e ‖ s ‖ hpk)` runs **only in software**,
  inside `encap`/`decap`. Nothing about it touches a circuit, so SHAKE is the
  right, unconstrained choice there.
- The Argus DEM-key `K = H(support(e))` is computed **in-circuit** by the signer
  (the voleith ring-signature proves the tag's DEM wrap of `identity` under `K`
  is well formed) and
  **recomputed in software** by Argus to open the tag. It crosses the
  circuit/software firewall, and the in-circuit side is a GF(2)/GF(2⁸)
  QuickSilver gadget. SHAKE/Keccak is a poor fit there: it is GF(2)-bitwise and
  expensive in a GF(2⁸) circuit, so the Argus KDF is deliberately a *different*
  primitive from the general-KEM KDF.

Three facts pin the primitive:

1. **In-circuit-expressible only.** The candidate set is exactly the hashes that
   exist as a GF(2⁸) circuit at the required output width, not an arbitrary
   hash. AES-based modes are both expressible and cheapest, because AES is
   already present in every proof (it is the DEM cipher and the leaf OWF/PRF).

2. **Collision resistance is not the load-bearing property.** `support(e)` is a
   random, high-entropy, unique-per-ciphertext value: `e` is sampled fresh per
   signature, the support↔error map is a bijection, and `s = M·eᵀ` decodes to a
   unique `e` under the bounded DFR. Tracing soundness comes from the in-circuit
   weight-`t` constraint and the wire bindings (the same `identity` wire in the
   membership branch and in `ct`), not from `H` resisting collisions; anonymity
   needs `K` merely **unpredictable**, and the cheapest way to predict `K` is to
   decode `s` (syndrome decoding at λ), never to invert `H`. The requirement is
   thus **PRF/one-wayness at λ with output width = the DEM-key width** (128-bit
   at λ=128, 256-bit at λ=256). Collision resistance is a property we neither
   need nor pay for; selection among the primitives that *meet* the requirement
   is therefore purely by in-circuit cost over the packed support message (§6.2).
   At λ=256, among the 256-bit-output AES-round hashes, **Grøstl-256** is cheaper
   per absorbed byte than the double-block-length Hirose (its 512-bit permutation
   amortises to fewer GF(2⁸) S-box evaluations per byte), so Grøstl-256 is
   chosen; that it is also collision-resistant is incidental over-provisioning we
   do not rely on.

3. **AES-DM (λ=128) and Grøstl-256 (λ=256) are sound here for the long
   term.** AES-DM feeds the message into the AES key schedule, so AES's
   related-key structure is nominally in play, and it is proven in the
   ideal-cipher model that AES does not perfectly instantiate; Grøstl-256 is a
   SHA-3 finalist whose security rests on its two AES-round-based permutations
   behaving ideally. Neither idealization yields an attack in
   this role: the hash input is random (no related-key oracle is exposed), `K` is
   secret (no public preimage target), there is no free-start / chosen-IV freedom
   (fixed IV, fixed-format, fixed-length input), and the construction does not
   rely on the collision bounds those idealizations concern. Decisively, **AES is
   already an unavoidable root of trust in the tag**: it is the DEM and the
   OWF/PRF irrespective of `H`, and both KDFs are built from the AES round
   function, so an AES-round KDF adds no new single point of
   failure, and the dominant long-term risk for a reused opener key is the
   QC-MDPC assumption and the DFR bound (a decode failure leaks the key), not the
   symmetric KDF. AES-DM has a 128-bit output and is intrinsically λ=128-only;
   λ=256 uses Grøstl-256 for a 256-bit `K`.

**Why not reuse the membership tree's node hash.** The ring's node hash is a
per-proof, self-describing knob chosen *for its collision resistance* (a
node-hash collision forges a membership path). The opener KDF is the opposite: a
fixed, opener-side interop contract that does not need collision resistance.
Binding `H` to the node hash would force Argus to implement and constant-time-
audit every hash a prover might select (and learn which one each tag used), and
would let a prover's cheap, narrow tree hash pull `K` below the DEM-key width. So
`H` is **decoupled** from the node hash and anchored to AES, the one primitive
guaranteed in every configuration, selected by the opener's parameter set, not
the prover's.

**Agility via versioning, not runtime configurability.** Should `H` ever need to
change, it is rotated by minting a new parameter-set *version* (e.g. a `128b`
set) carrying the new `H`. The opener key names its parameter set, and the opener
public key `M` is Fiat-Shamir-bound into the instance, so a tag for set X
verifies and opens only as set X: rotation is explicit, auditable, and
downgrade-resistant, with exactly one active `H` per opener generation. A runtime
opener-chosen `H` is *possible* but is not adopted: it re-inflates the
dual-firewall audit surface this decoupling removes, adds a downgrade/confusion
vector to the binding obligations, and buys little, since the event that would
motivate swapping `H` (a break of AES) also breaks the AES DEM: the KDF cannot
be rotated to safety on its own. A deployment that nonetheless wants choice must
restrict it to a small allowlist of circuitized, same-width, PRF-secure hashes
carried in the opener public-key parameters and FS-bound with `M`; within a
single opener/ring `H` is constant, so anonymity is not fragmented.

*Authority and homes.* The in-circuit role, the circuit/software firewall, and
the gate budget are libtalos_voleith's domain (its in-circuit PKE/KDF gadget
design); this document fixes only the byte-exact KDF contract those gadgets must
reproduce. Primitive soundness: the standard ideal-cipher analysis of
Davies-Meyer and the SHA-3-finalist analysis of Grøstl-256, read against this
KDF-on-a-random-secret usage. The in-circuit gadgets are libtalos_voleith's; the
canonical *software* definitions of AES-DM / Grøstl-256 live in
libtalos_ichor (the shared symmetric core both libraries sit on), so the signer's
circuit and Argus's `decap` validate against one byte-exact reference and the
syndrome↔voleith decoupling (shared only by the `(M, s, ct)` wire format) is
preserved.

### 6.2 Concrete opener recipe: tag, DEM wrap, KDF framing, validation {#argus-recipe}

Section 6.1 fixes the opener KDF *primitive*; this section pins the concrete byte
recipe that `opener/argus.c` implements, so it is reproducible and KAT-able and so
the voleith in-circuit gadget has a byte-exact target. (This is the in-circuit
designated-opener path; it is a *different* construction from the general
`syndrome_kem_*` KEM of §4.8, which it does not call.)

- **Tag layout.** `tag = prim_id ‖ s ‖ ct`: a one-byte KDF-hash selector
  `prim_id` (`ARGUS_DS_PRIM_ID`, the per-λ compiled default), then the syndrome
  `s` (`SYNDROME_CT_BYTES`, the shared `(M, s)` wire), then the DEM ciphertext
  `ct` (`identity_len` bytes). `tag_len = 1 + SYNDROME_CT_BYTES + identity_len`.
  `prim_id` is public and parsed before decode; an id naming a hash this build
  did not compile is rejected fail-closed with `SYNDROME_ARGUS_EUNSUPPORTED`
  (not a reaction oracle on H). The byte makes the tag self-describing so future
  KDF hashes are additive with no wire change.
- **DEM wrap: one-time pad, with a keystream extension for long identities.**
  `ct = identity ⊕ pad[0:identity_len]`, opened as
  `identity = ct ⊕ pad[0:identity_len]`. When
  `identity_len ≤ SYNDROME_ARGUS_KEY_BYTES` (the extractor width: 16 B at λ=128,
  24 B at λ=192, 32 B at λ=256) the pad *is* the extractor output
  `root = H(support(e))`. When `identity_len` exceeds it, `root` keys AES-CTR
  (AES-128 at λ=128, AES-192 at λ=192, AES-256 at λ=256) and the pad is the
  keystream `AES_root(L ‖ 0) ‖ AES_root(L ‖ 1) ‖ …`
  truncated to `identity_len`, with `L` a fixed 12-byte context label
  (`ARGUS_CTR_LABEL`) and a 4-byte big-endian block counter.
  `identity_len ≤ SYNDROME_ARGUS_ID_MAX_BYTES` (below); it is a public protocol
  parameter, so the ≤/> branch is not a constant-time concern. Both cases rest on
  fresh-`e`-per-encap (§4.2): `root` never repeats, so neither the pad nor any
  `(root, counter)` keystream block is ever reused. XOR is free in-circuit; the
  extension costs `⌈identity_len / 16⌉` AES calls, borne by both the signer and
  the verifier (the voleith relation is re-evaluated in verification). The
  extension is orthogonal to domain separation, which lives in the extractor IV
  and which `root` (and hence the keystream) inherits.
- **KDF input encoding.** `support(e)` is the `t` set positions of `e` over
  `[0, n)`: block 0 in `[0, p)`, block 1 in `p + [0, p)`, **sorted ascending**.
  Each global position is **bit-packed, LSB-first, into exactly `⌈log₂(n)⌉` bits**
  (`n = n₀·p`; e.g. 15-16 at λ=128, 16-17 at λ=192, 17 at λ=256), not a
  byte-aligned `uint32`. The packed message is `pack(idx₀) ‖ … ‖ pack(idx_{t-1})`,
  `t·⌈log₂(2p)⌉` bits wide. Bit-packing minimises the number of compression
  blocks the in-circuit signer must evaluate (the dominant KDF cost) and is
  itself free in-circuit (linear wire re-routing, no S-boxes); it roughly halves
  the block count versus the `uint32` form. Because the packed length is a
  **compile-time constant** (`t` and the pack width are fixed per parameter set),
  the message needs **no Merkle-Damgård length strengthening**: length extension
  has no bite on a fixed-length, fixed-IV, single-purpose hash, and is simply
  **zero-padded to the compression block boundary** (16 B for AES-DM, 64 B for
  Grøstl-256).
- **KDF absorb.** The zero-padded packed message is absorbed through an AES-round
  hash whose initial chaining value is a domain-separation constant (next
  bullet):
  - λ=128 (**AES-DM**, `ichor_aesdm_iteration`, 16-B block): `H₀ = ARGUS_DM_IV`;
    `H ← DM(H, Mᵢ)` per block; `root = H_final` (16 B).
  - λ=192 (**Grøstl-256**, `ichor_grostl256`, 64-B block): same as λ=256, but the
    32-B digest is truncated to its leading `SYNDROME_ARGUS_KEY_BYTES` = 24 B
    (the 192-bit `root`). There is no 24-B AES-round hash, so Grøstl-256 is reused
    and domain-separated from λ=256 by the IV `λ`-byte (next bullet).
  - λ=256 (**Grøstl-256**, `ichor_grostl256`, 64-B block): initial chaining value
    `ARGUS_G256_IV` in place of Grøstl's standard length-encoding IV; `root` is
    the 32-B digest.
  Hirose-AES-256 is **not** used: Grøstl-256 is cheaper per absorbed byte
  in-circuit at this output width (§6.1, fact 2).
- **Domain separation via the IV (free).** The initial chaining value is a fixed,
  readable, Argus-specific constant, matching Grøstl's own structured-IV
  convention and costing zero extra blocks, since a distinct fixed public IV
  yields an independent function. Its 16-byte core is `"TALOS"(5) ‖ "Argus"(5) ‖
  λ-in-bytes(1: 0x10 / 0x18 / 0x20) ‖ primitive-id(1: 0x01=AES-DM, 0x02=Grøstl-256
  for both λ=192 and λ=256, distinguished by the λ-byte;
  0x03=Hirose, 0x04=Grøstl-512 reserved, not compiled in 1.11.0) ‖
  n0(1, the literal block count) ‖ version(3, big-endian u24)`, which fills the
  AES-DM IV exactly and is
  zero-padded to 64 B for Grøstl-256. The `λ`-byte also re-encodes Grøstl's
  output length; the `"TALOS"` tag separates this hash from any other project's
  AES-DM/Grøstl use. The IV constants, the pack width, the counter label, and the
  zero-padding are the cross-firewall contract; rotating any of them is a
  parameter-set-version change (§6.1).
- **Signaled `prim_id`, single compiled prim.** The `primitive-id`
  byte is also carried at the front of the Argus tag (`tag = prim_id ‖ s ‖ ct`),
  so the tag is self-describing and future hashes are
  additive with no wire change. Each build compiles and opens only the per-λ
  default (0x01 at λ128, 0x02 at λ192 and λ256); `syndrome_argus_open` parses
  `prim_id` and, if it
  is not the compiled default, returns a fail-closed `SYNDROME_ARGUS_EUNSUPPORTED`
  early (before decode; `prim_id` is public, so this branch is not a reaction
  oracle on H). Reserved ids 0x03/0x04 (Hirose / Grøstl-512) become a runtime
  dispatch case plus that hash's constant-time and KAT validation in a future
  version; they touch neither the wire nor a shipped set.
- **Maximum identity length.** `SYNDROME_ARGUS_ID_MAX_BYTES` = 48 (λ=128) /
  96 (λ=256). This is a **buffer-sizing bound**: the opener uses fixed stack
  buffers, no allocation, **not** a security limit: the AES-CTR extension has no
  cryptographic length ceiling, and the per-tag cost scales with the actual
  identity length, not this maximum. The values are the rsv5 fixed-leaf input
  capacity (leaf-hash block minus the committed `sk`: 64−16 at λ=128, 128−32 at
  λ=256) and comfortably cover the ≤2λ identities of a plain key-exchange use.
  Because `tag_len = SYNDROME_CT_BYTES + identity_len` is carried per tag rather
  than fixed, raising this bound later is backward-compatible (old tags still
  parse); it is not part of the frozen wire contract.
- **Validation: re-encryption only (§4.4), no confirmation field.** Accept iff
  `s` is canonical (top `(8·BLOCK_BYTES − p)` padding bits zero) **and** the
  decoder's `ok` flag (residual private syndrome zero, i.e. `M·e'^T == s`)
  **and** `wt(e') == t` **and** the deserialized `H` is well-formed (every index
  `< p`). The well-formedness term folds constant-time into the accept mask, so a
  malformed opener key yields `EUNOPENABLE` (defense-in-depth on the
  caller-supplied `sk`; all-ones for a valid key). This is the same FO
  re-encryption discipline as `decap` (§4.8); a confirmation tag was not added because the enclosing voleith proof
  already attests `s`, `ct`, and the `identity` wire are well formed and bound,
  so an in-tag binding would be redundant for the only supported use.
- **Typed failure, not implicit rejection.** A bad tag returns a negative typed
  status (`EARGS` / `EMALFORMED` / `EUNOPENABLE`), unlike `decap`'s implicit
  rejection, because the opener's purpose is to tell its (trusted) caller
  whether a tag was openable, and there is no downstream check to absorb a silent
  rejection. This is sound against adversarial input, but **not** for the reason
  an earlier draft of this document gave (a bare "DFR ≤ 2⁻λ ⇒ negligible
  leakage"). The complete argument is in §6.4-§6.6: the two attack surfaces
  (co-resident microarchitectural, and chosen-input); why an `H`-blind adversary
  cannot construct a failing weight-`t` input (the failure-dominating errors are
  columns of `H`, so building one is Key Recovery), which makes the average DFR
  bound apply to adversarial input too; the constant-time opener that keeps the
  open outcome out of any side channel; and the obligations voleith, the
  parameters, and the operator must uphold. The in-module decode and open path
  are constant-time, and the general `decap` keeps implicit rejection.

*Authority.* Tag/DEM/validation choices: this section, with the SP 800-227
deviation analysis in §8. Adversarial-input safety (DFR + key-recovery argument,
constant-time opener, and the firewall obligations on voleith/parameters/
operator): §6.4-§6.6. KDF primitive and firewall: §6.1.
Re-encryption-as-decoder-residual: §4.8.

### 6.3 What `e` is, who generates it, and why its randomness matters {#argus-randomness}

`e` is the KEM **encapsulation randomness**: a fresh weight-`t` error vector
over `F_2^(n0·p)`. It is **not** the signer's identity. The identity is a
separate value (`identity`, at most `SYNDROME_ARGUS_KEY_BYTES` bytes) wrapped
under the key `K = H(support(e))`. In the signer's proof, `e` appears only to
produce the syndrome `s = M·eᵀ` and the key `K`; it is used nowhere else: not in
ring membership, not in any tag or commitment. Recovering `e` is what lets the
opener compute `K` and unwrap the identity, but `e` and the identity are distinct
values.

Three properties depend on `e` being a fresh, high-entropy weight-`t` error.
None of them is KEM *correctness* (the math works for any weight-`t` `e`):

1. **Anonymity of the public tag.** The tag `(s, ct)` is public and `s = M·eᵀ`.
   If `e` were derived from the low-entropy, enumerable identity, `s` would be a
   static function of the identity and anyone could re-encrypt a guess and
   compare, de-anonymizing the signer. A random `e` makes `s` indistinguishable
   from random (the KEM half is IND-CPA), hiding the identity behind the
   symmetric layer. This is mostly the *signer's own* interest: a signer who
   picks a bad `e` chiefly weakens their own anonymity.
2. **Openability / traceability.** The opener must always be able to
   de-anonymize. The bounded three-iteration decoder has a non-zero
   decoding-failure rate; for honest random `e` it is ≤ 2⁻λ (§3). An `e` that
   fails to decode yields an *un-openable* signature: a signer able to craft one
   would escape tracing entirely, breaking the designated-opener guarantee.
3. **Key secrecy under reaction attacks.** An observed decoding failure leaks
   information about the private `H` (§6.4). Honest random `e` fails only with
   probability ≤ 2⁻λ, so failures are never observed in practice.

**Who generates `e`, and why this library cannot guarantee it.** In the voleith
use case the signer generates `e` **inside its zero-knowledge proof** and proves,
without revealing `e` or the identity, that:

- `e` has weight exactly `t` (structural: `e` is `t` one-hot blocks, one set bit
  per block);
- `s = M·eᵀ`, where `M` is the *real* opener's public key, bound into the
  Fiat-Shamir transcript: a signer must not be able to encrypt to a substituted
  opener key (which would redirect or defeat tracing);
- `K = H(support(e))`;
- `ct = identity ⊕ K`, with `identity` the same value committed under the
  ring-membership root (this binding is what makes the open *traceable* to the
  true signer).

This encryption is therefore re-implemented as proof constraints in voleith; it
cannot call libtalos_syndrome, because a proof is a system of constraints over
field elements, not native-code execution. The two implementations (this
library's native reference plus opener, and voleith's in-circuit signer) agree
only through a shared byte-layout contract, with no source-level dependency in
either direction.

A direct consequence: **no library can guarantee `e`'s randomness for the
proof.** A zero-knowledge proof attests *relations* about a prover-chosen
witness; "this value was sampled uniformly at random" is not such a relation.
Any weight-`t` vector is a possible honest-sampler output, so there is no
certificate of randomness to verify. A malicious signer can run a modified
prover and choose any weight-`t` `e`; the proof still verifies, because only the
weight is constrained. Honest randomness of `e` is thus an **assumption on
signer behaviour**, not something the opener (or this library) can enforce.
(This library *does* sample `e` honestly when its own encapsulation is used: the
general KEM `encap` and the reference seal. That path is not the production
signer, which is voleith's circuit.)

### 6.4 Adversarial-input safety: assets, attack surfaces, and the DFR argument {#argus-adversarial}

Because `e` can be adversarial, the opener must be safe when fed hostile input.
Two assets must be protected, to the **same** standard. The plaintext a
public-key scheme protects is held as secret as the key itself:

- **A1: the opener's private key `H`.** Compromise is catastrophic: `H` decodes
  every tag, de-anonymizing the whole system.
- **A2: the signer identity**, the plaintext the KEM-DEM protects.

Two attack surfaces are in scope. Both were under-weighted in early analysis and
are called out explicitly here:

- **V1: co-resident attacker.** On a multi-tenant host the attacker is a
  *separate, unprivileged user* sharing hardware with the opener. OS memory
  protection prevents reading the opener's memory, but microarchitectural side
  channels (Flush+Reload on shared pages, Prime+Probe on shared cache, SMT port
  contention) cross the process boundary and recover secret-dependent timing and
  memory-access patterns *without* reading memory. "Trusted operator" is
  therefore **not** a sufficient exemption.
- **V2: chosen-input attacker.** The attacker submits crafted tags and observes
  the open outcome (the returned status, or any behaviour keyed on it). A
  malicious ring member is exactly this attacker, and is **`H`-blind**: it holds
  only the public `M`, never the opener's private `H`.

The one signal that could compromise `H` (A1) is **whether a tag decodes**: for
an adversarially chosen `s`, the decoder's success/failure correlates with `H`,
and a single observed failure can leak the key (the reaction attack). Safety
rests on the fact that an `H`-blind adversary **cannot produce a failing input**,
so the signal can never be triggered:

- The decoding-failure-rate bound (§3, DFR ≤ 2⁻λ) is an **average over uniformly
  random weight-`t` errors.**
- The errors that dominate the failure rate are **functions of the secret key**:
  - a *near codeword* is an error whose single non-zero block equals a column of
    `H`, `e^(i0) = (H_{:,p·i0+l})ᵀ`, for some shift `l`;
  - a *half codeword* is the analogous structure using a column of `H` from a
    *different* block (`i1 ≠ i0`);
  - and errors with substantial *overlap* with these are the next-hardest.
  These are the patterns the bounded decoder fails on.
- Constructing such an error requires knowing a low-weight column of `H`.
  Recovering one from the public `M` **is the Key-Recovery problem**: NP-hard
  for random codes, conjectured-hard for QC codes. This is the *same* assumption
  the cryptosystem's IND-CCA2 security already rests on; it is not a new trust.
- Therefore an `H`-blind adversary's chosen weight-`t` errors are, with respect
  to the secret code structure, indistinguishable from random ones: they fail at
  the **average rate ≤ 2⁻λ**. The average DFR bound thus also bounds adversarial
  input, *provided the input is weight-`t`* (why the circuit must pin the
  weight, §6.6).

Consequences for both assets:

- **Traceability (A2 / un-openable tag).** A malicious signer cannot craft a
  failing `e` without solving Key Recovery, so every tag a feasible adversary can
  produce decodes with probability ≥ 1 − 2⁻λ. The opener can always trace; a
  signer cannot manufacture an un-revocable signature.
- **Reaction key recovery (A1).** Failures occur at ≤ 2⁻λ even on adversarial
  input, so over any feasible number of queries no failure is observed; the
  reaction oracle is never triggered.

This is the correct reading of the DFR argument: average DFR **is** the right
bound against adversarial input, *because* the worse-than-average errors are
key-dependent and unconstructable without the key. It is not sufficient on its
own: it requires the weight constraint (§6.6), key-recovery hardness, and the
constant-time opener (§6.5).

### 6.5 Constant-time opener: what the implementation guarantees {#argus-constant-time}

The opener (`opener/argus.c`, built on `decap`) is constant-time over both
secrets, closing V1 and ensuring that even a failure that did occur could not be
observed through timing or memory-access pattern:

- The decoder runs a fixed `iterMax = 3` with data-independent control flow; the
  only data-dependent value it produces is the residual-syndrome `ok` flag, a
  value, never a branch. It indexes memory by neither `H` nor the error support.
- Expanding a weight-`t` index list into dense error blocks is **oblivious**:
  every output position is compared against every index (block 1 addressed by
  subtracting `p`), so the secret support is never used as a memory offset.
- Extracting the support from the recovered error for the KDF is **oblivious
  compaction**: a fixed-bound scan with a masked sweep over all `t` output slots;
  the running count is compared, never used as an index.
- The open path is **unconditional and branch-free in the result**: support
  extraction, KDF, and the one-time-pad unwrap all run regardless of the
  `ok`/weight outcome; the recovered identity is written under a validity mask
  (zeroed on failure); and the openable-or-not bit appears only in the returned
  status, computed branchlessly. So "openable" and "not openable" are
  indistinguishable in timing and access pattern; the bit reaches the trusted
  caller, never the cache.
- All secret stack material is zeroed before return.

The general `decap` additionally uses constant-time *implicit rejection* (returns
a pseudorandom key on failure, with no status). Argus instead returns a **typed**
status to its trusted caller, because the opener's whole purpose is to report
whether a tag was openable and there is no downstream check to absorb a silent
rejection. But the *work* is constant-time either way, so the typed status is
not a side channel (V1); it is only an explicit signal to the caller, governed by
§6.6.

### 6.6 Security obligations outside this library: the firewall contract {#argus-firewall}

The opener's adversarial-input safety holds only if the rest of the system
upholds its half. These obligations are **not** enforceable by this library and
must be guaranteed by voleith, the parameter choice, and the operator:

1. **The signer's circuit MUST enforce `wt(e) = t`.** The DFR argument (§6.4)
   applies only to weight-`t` errors; an out-of-weight error is outside the
   regime the bound covers. voleith's one-hot-block encoding enforces this
   structurally and it must not be relaxed.
2. **The opener public key `M` MUST be the real opener key, Fiat-Shamir-bound**
   (§6.3). If a signer could encrypt to a substituted `M`, it could redirect or
   defeat tracing while still producing a verifying signature.
3. **Parameters MUST keep Key Recovery hard** (the long-term sets of §3 are
   chosen for this). If a low-weight column of `H` were recoverable from `M`,
   near/half codewords become constructible and §6.4 collapses.
4. **The opener MUST run only on signature-verified tags** (verify-then-open) and
   **MUST NOT expose the per-tag open outcome** to anyone who could use it as an
   accept/reject oracle. Verify-then-open's *primary* job is plaintext
   authentication: the OTP DEM is unauthenticated, so `open` returns a `K`-derived
   identity for any tag and its `OK` status attests only that the syndrome decoded,
   never that the identity is genuine; the verified proof is what authenticates the
   tag. Its contribution to `H`-secrecy is defense-in-depth on the DFR precondition
   (keeping inputs in the weight-`t` regime the §6.4 bound covers), not the load-
   bearing protection: `H`-secrecy rests on the low DFR and the constant-time
   opener (#5), which hold whether or not this obligation is met. Not publishing
   openability removes the explicit accept/reject channel; the constant-time opener
   removes the side-channel one.
5. **`H` MUST stay secret.** Every point above ultimately serves this single
   invariant: the average-DFR argument is valid precisely while `H` is unknown
   to the adversary. The two halves that maintain it are the **low DFR** (so a
   failure essentially never occurs) and the **constant-time opener** (so a
   failure could not be observed); obligations 1-4 are what stop an adversary
   from circumventing them.

In short: this library guarantees a **constant-time opener** and a **sound DFR**
for weight-`t` input; voleith guarantees the **weight constraint**, the
**Fiat-Shamir-bound opener key**, and the **verify-then-open gate**; the
parameters guarantee **key-recovery hardness**. Together these let the opener
safely process input from a malicious signer.

## 7. Frozen wire format: the (M, s) byte layout {#wire-format}

This is the **only** contract shared with libtalos_voleith (design decision #6):
no source-level dependency in either direction, only these bytes. It is frozen:
once shipped it must not change without a parameter-set-version bump, and is
regression-guarded directly by `tests/test_wire.c` and transitively by the KEM
KAT digest (§4.8, which pins `pk`/`ct` byte-for-byte). `core/gf2x.c`
`syndrome_gf2x_load`/`syndrome_gf2x_store` are the only sanctioned
bytes↔block conversions; any consumer (including the voleith circuit) must
reproduce exactly the mapping below.

### 7.1 The circulant-block primitive (the whole contract, in one rule) {#wire-block-primitive}

Every `(M, s)`-side value is a length-`p` element of `F₂[x]/(xᵖ−1)`, a
*circulant block*, serialized identically:

- A block occupies `SYNDROME_BLOCK_BYTES = ⌈p/8⌉` bytes.
- The coefficient of `xʲ` (`0 ≤ j < p`) is stored in **byte `⌊j/8⌋`, bit
  `j mod 8`**, i.e. **little-endian byte order, least-significant-bit-first
  within each byte**. Equivalently: byte `i`, bit `b` is the coefficient of
  `x^(8·i + b)`.
- **Canonical form.** The top `8·SYNDROME_BLOCK_BYTES − p` bits of the last byte
  are not part of the block and **MUST be zero on the wire**. `syndrome_gf2x_load`
  masks them on input (`GF2X_TOP_MASK`); `syndrome_gf2x_store` emits zero there
  for any reduced block. A non-canonical `s` (any padding bit set) is rejected:
  `decap` folds it into the implicit-rejection mask (§4.8) and `argus_open`
  returns `SYNDROME_ARGUS_EMALFORMED` (§6.2).

That single rule defines `M`, `s`, and the error blocks; everything below is just
which blocks go where.

### 7.2 The public-surface objects {#wire-objects}

| object | wire bytes | size macro | layout |
|--------|-----------|------------|--------|
| public key `pk = M` | `(n₀−1)·⌈p/8⌉` | `SYNDROME_PK_BYTES` | systematic `M = [M₀ \| I]`; for `n₀ = 2`, one block `M₀` (the identity block is implicit, never transmitted) |
| ciphertext `ct = s` | `⌈p/8⌉` | `SYNDROME_CT_BYTES` | one block, the syndrome `s = M·eᵀ`; canonical |
| Argus tag | `1 + ⌈p/8⌉ + id_len` | `SYNDROME_ARGUS_TAG_BYTES(id_len)` | `prim_id ‖ s ‖ ct_dem`: the KDF-hash selector byte, the syndrome block, then `id_len` one-time-pad DEM bytes (§6.2) |

The KEM accept-path KDF binds the two **error blocks** `e₀ ‖ e₁` (§4.8); each is
a dense circulant block under §7.1. These are an internal KDF input, not part of
`pk`/`ct`/`tag`, but use the identical block packing.

### 7.3 Index encodings are a *different*, non-block packing {#wire-index-encodings}

Two places serialize *positions* rather than block coefficients, and deliberately
do **not** use §7.1:

- the secret key's private `H` (n₀ weight-`v` index lists, **little-endian
  16-bit** per index, `p < 2¹⁶`; §4.8), which is private, not part of the shared
  contract;
- the Argus KDF message `support(e)` (the `t` set positions, ascending,
  **bit-packed LSB-first into `⌈log₂(n₀·p)⌉` bits** per index, then zero-padded
  to the compression-block boundary; §6.2), shared with voleith, but as an index
  list, not a block.

They are called out here only so an implementer never confuses an index list with
a packed block. The `(M, s)` wire itself is exclusively §7.1.

### 7.4 In-memory note (not part of the contract) {#wire-in-memory}

Internally a block is `SYNDROME_GF2X_LIMBS = ⌈p/64⌉` little-endian `uint64`
limbs; `load`/`store` convert to/from the byte form above. The limb form is an
implementation detail and is **not** the wire format; only the bytes are. The
contract is endianness-fixed (little-endian) end to end, so it is identical on
any host.

## 8. SP 800-227 conformance {#conformance}

SP 800-227 is followed as design discipline, not as a conformance claim: the
underlying QC-MDPC scheme is **not an *approved* KEM** (SP 800-227 §3.1: no FIPS
specifies it; HQC took the code-based slot), so strict compliance (approved
scheme in a validated module) is out of scope for the whole library by scheme
choice (§10). Within that posture, the **general KEM** (`syndrome_kem_*`) is the
SP 800-227-shaped surface:

- Interface names and shapes follow the SP 800-227 KEM interface
  (`syndrome_kem_keypair` / `syndrome_kem_encap` / `syndrome_kem_decap`).
- Implicit rejection (§4.1, §4.6) follows the SP 800-227 / FO-style guidance.
- Shared-secret derivation binds the ciphertext and public key into the KDF
  (§4.3).
- Security is framed in SP 800-227 terms: IND-CCA2 of the KEM resting on the
  hardness of the Key-Recovery and Message-Recovery attacks (Defs. 3-4 of the
  spec) plus a sound DFR bound.

### 8.1 Argus deviations from SP 800-227 (deliberate, justified) {#conformance-argus-deviations}

Argus (§6.2) is a KEM-DEM opener gadget, not the KEM, and departs from
SP 800-227's symmetric-usage guidance on purpose. None of this touches the
general-KEM surface above. The choices and their justification:

- **Re-encryption only: aligned, not a deviation.** SP 800-227 §4.2(1) wants
  IND-CCA "whenever possible"; FO re-encryption is exactly the mechanism that
  provides it, so this *follows* the guidance. The one "should" to honour is
  SP 800-227 §3.3 (do not leak decode failure outside the module). This is met
  not by trusting the operator but by the argument in §6.4-§6.6: the opener is
  constant-time, so a failure is unobservable via side channel; an `H`-blind
  adversary cannot construct a failing weight-`t` input (that is Key Recovery),
  so the average DFR ≤ 2⁻λ also bounds adversarial input; the opener runs only on
  verified tags and does not publish per-tag openability; and `decap` keeps
  implicit rejection.
- **Bit-packed index encoding: no issue.** SP 800-227 §3.2 makes byte format the
  implementation's choice (fixed only for validation vectors). The encoding is
  injective over `support(e)`, so `K` deterministically binds the encapsulation.
- **Non-approved KDF (SP 800-227 §4.3).** `K = H(support(e))` uses AES-DM /
  Grøstl-256, not an SP 800-108/56C/133 KDM. Forced by in-circuit expressibility
  (§6.1); the role needs only PRF/one-wayness at λ on a random secret input, and
  the output width matches λ, so the SP 800-227 §4.2(4) strength-matching clause
  is satisfied even though the *approved* clause is not.
- **Non-AEAD DEM (SP 800-227 §4.1(5), §4.2(4)).** The OTP wrap provides
  confidentiality only; SP 800-227's model DEM is an AEAD (AES-GCM) giving
  confidentiality *and* integrity. Here the ciphertext integrity /
  `(s, ct, identity)` binding is supplied by the **enclosing voleith proof**, not
  the tag. Consequence (restated from §6): Argus is IND-CPA on the DEM standalone
  but **IND-CCA2 in-protocol**; it must only open tags gated by a verified
  signature, and standalone use goes through `syndrome_kem_*`.

Authority for the deviation analysis: §6.4-§6.6 above, read against SP 800-227
§3.1-3.3 and §4.1-4.3.

## 9. Deviations from the literal specification text (2025/1043) {#deviations}

This section is deliberately upfront. The implementation was reviewed line by
line against `docs/specs/2025-1043.pdf`. The scheme (Fig. 1), the decoder
(Algorithm 1), and the parameter sets and thresholds (Table 2, Long-Term,
`n0 ∈ {2, 5}`) conform exactly. There is no correctness-affecting departure.
Every place the code does not match the paper's *literal* text is listed below,
each with the reason and the effort to remove it. A cryptographer auditing this
library should read this list as the complete set of differences between "what
the paper writes" and "what we ship", and should note that the first three are
departures the paper's own threat model, or the project's non-negotiable security
decisions, *require*: making them literally match the pseudocode would weaken
security.

### 9.1 The decoder runs a fixed three iterations with no early exit {#dev-fixed-iterations}

The paper's Algorithm 1 loops `while (s != 0 and iter <= iterMax)`, stopping as
soon as the syndrome clears. We run exactly `iterMax = 3` iterations with no
data-dependent loop condition (`decoder/bitflip.c`).

*Why.* An early exit on `s == 0` is a secret-dependent branch, and decode timing
is the exact side channel the scheme exists to deny (a single observed failure
leaks `H`; project decisions #3 and #4). The fixed-iteration form is required by
the constant-time discipline of §6.5.

*Output equivalence.* Once `s == 0`, every `upc` is `popcount(0 AND column) = 0`,
which is below every threshold (all thresholds are at least 35), so no further
flip occurs and `s` stays zero. The fixed-iteration decoder therefore returns an
identical `(e, ok)` to the early-exit version on every input. The deviation is
observable only in running time, which is the point.

*Effort to make literally compliant.* Trivial in code, but it must not be done:
reinstating the guard reintroduces a timing oracle. Recommended action: none.

### 9.2 Thresholds depend on the iteration index only, not on the syndrome {#dev-fixed-thresholds}

Algorithm 1 line 5 writes `th <- ThresholdChoice(iter, s)`, taking the current
syndrome as an argument. We use a fixed constant per iteration and ignore the
syndrome weight (`decoder/threshold.c`, values pinned from Table 2; see §3).

*Why.* This is the decoder the paper actually models and bounds. Section 3.2
states plainly that the model employs "thresholds depending only on the iteration
index, and not on the Hamming weight of the syndrome", and Table 2 reports fixed
per-iteration thresholds. The closed-form DFR `<= 2^-lambda` guarantee
(Theorem 4) is proved for the fixed-threshold decoder. A syndrome-weight-adaptive
rule (as in BIKE) falls outside that proof.

*Effort to make literally compliant.* The literal `ThresholdChoice(iter, s)`
signature suggests a syndrome-dependent rule, but adopting one would move the
decoder outside the paper's DFR theorem and invalidate the security argument.
The fixed-threshold choice is the compliant reading of the analyzed scheme; the
unused syndrome argument is intentionally dropped. Recommended action: none.

### 9.3 Decode failure becomes constant-time implicit rejection, not a returned bottom {#dev-implicit-rejection}

Fig. 1 Decryption sets `e <- bottom` on decode failure and returns it, a visible
failure signal at the PKE boundary. The KEM never signals failure: it derives a
pseudorandom shared secret from the per-key secret `sigma` and returns success
unconditionally (§4.1, §4.6, §4.8). The PKE layer still computes the success flag
internally (`pke/niederreiter.c` sets `*ok`); the KEM consumes it without
branching.

This is the same departure already justified in §4.1 and §4.6; it is listed here
so the mapping to Fig. 1 is explicit. The FO re-encryption check is realized as
the decoder's residual-syndrome `ok` (`ok` means `h0 e0' + h1 e1' = s'`, and
multiplying through by the existing inverse `H_{n0-1}^-1` gives `s = M e'^T`
exactly), plus a constant-time `wt(e') == t` check; see §4.8 for the byte recipe.
Recommended action: none (the PKE-level bottom exists internally and is
deliberately not surfaced).

### 9.4 The KEM transform is not specified by 2025/1043 (out of scope, not a deviation) {#dev-kem-out-of-scope}

The KDF, the domain-separation tags, the public-key hash, the
implicit-rejection secret, and the ciphertext binding (`kem/kem.c`) have no
counterpart in the paper, which specifies only the PKE and defers the KEM to its
reference [36] and to the "same construction" as BIKE and LEDAcrypt. This is the
authority split stated at the top of this document and analyzed in §8: the KEM
layer is governed by SP 800-227 and the FO references, not by 2025/1043. It is
recorded here only to mark the scope boundary; against its governing documents it
is a faithful implicit-rejection FO transform.

### 9.5 Fixed-weight sampling uses a multiply-shift reduction with negligible bias {#dev-sampler-bias}

`syndrome_sample_fixed_weight` (`core/sample.c`) draws each index with a Lemire
multiply-shift reduction rather than rejection sampling, so the per-draw
distribution over a range is not perfectly uniform.

*Why.* The partial Fisher-Yates with a multiply-shift map is constant-time and
allocation-light; rejection sampling has a data-dependent iteration count and a
data-dependent number of DRBG bytes, both of which would be side channels on the
secret draw and would break the fixed-consumption KAT and derandomized
composition. The paper presupposes uniform weight-`t` and weight-`v` sampling but
does not pin a sampler algorithm, so this is an implementation choice rather than
a departure from a specified procedure.

*Magnitude.* The bias for a range `R` is at most about `R / 2^L`, where `L` is
the width of the draw. The draw is widened to `lambda + 64` bits (24 bytes at
`lambda 128`, 40 bytes at `lambda 256`), so with `R <= N < 2^18` the per-draw
bias is below `2^-lambda` for every set (about `2^-164` and `2^-292`
respectively), and subadditively over the `O(w)` draws in a key it stays far
below the security level. The draws are guaranteed distinct and in range.

*Why not exactly zero.* Exact uniformity would require rejection sampling, which
is variable-time and consumes a variable number of DRBG bytes; that is
disqualified here because the sampler is on the constant-time critical path (its
output is the secret support). Constant time, bounded work, and exactly-zero bias
cannot hold at once, so the bias is driven negligibly small by widening rather
than to zero. The width is a compile-time per-set constant, so control flow and
consumption stay fixed.

### 9.6 Ring convention for parity-check columns (note, not a deviation) {#dev-ring-convention}

The decoder treats the parity-check column at position `m` as `h_b(x) * x^m`
(a rotate of the block), the polynomial / `x`-power convention, rather than the
literal matrix column of `circ(h)` as written in Section 2.1. The paper itself
reinterprets `H e^T` as polynomial multiplication in `R` (Section 2.4), and the
convention is used consistently across keygen, encryption, decryption, and the
frozen `(M, s)` wire format (§7), so the scheme round-trips and solves the same
syndrome-decoding instance. The position relabeling it implies is invariant under
the weight-based near-codeword and half-codeword analysis, so it has no effect on
the DFR argument or on security. This is recorded only because any independent
oracle (the from-spec decoder in `tools/decode_oracle/`) must use the same
convention when constructing near and half codewords, or its expected outcomes
will not match. No action required.

## 10. Scope and non-claims {#scope}

This scheme is **not NIST-standardized** (HQC won the code-based KEM slot; the
QC-MDPC family / BIKE did not advance). For generic off-circuit use, ML-KEM or
HQC are the right defaults. The edge of this library (binary-field-native,
compact keys, a circuit-free syndrome map) is the in-circuit designated-opening
niche for libtalos_voleith. It is not a drop-in ML-KEM / HQC replacement.

The IND-CCA2 claim rests on (a) the conjectured hardness of QC-MDPC key/message
recovery (ISD-dominated), (b) the FO/QROM reduction of §4.5, and (c) the spec's
DFR bound. A break of any one of these is a break of the KEM.

### 10.1 Secret material in memory: zeroized, not locked (deployment note) {#mem-hygiene}

Every internal secret (the deserialized private key `syndrome_qcmdpc_sk`, the
sampled error and its index list, the DRBG `Key`/`V`, the root seed, and the
shared secret) is stack-resident and is promptly cleared with `ichor_secure_zero`
on every return path, including the error paths. There are no static or
heap-resident secret buffers. `ichor_secure_zero` is written so the compiler may
not optimize the wipe away, so a secret does not outlive the call that used it.

What the library deliberately does **not** do is lock memory or alter the
process's crash behavior. Between the moment a secret is written and the moment it
is zeroized it could, in principle, be paged to swap or captured in a core dump.
Preventing that is **process-global deployment policy**: `mlock`/`mlockall`,
core-dump suppression, and swap configuration affect the whole address space and
the host's crash handling, so a library must not impose them on the application
that embeds it (this library is also consumed in-circuit by libtalos_voleith and
may be called from managed runtimes, where silently locking all memory or
disabling core dumps would be hostile). The correct division of responsibility is
that the library keeps secrets short-lived and wiped; the deployment decides its
memory and crash policy.

For a long-lived deployment that holds a private key resident (an opener service,
in particular), the recommended host-side mitigations are: `mlockall(MCL_CURRENT
| MCL_FUTURE)` or a per-mapping `mlock` over the secret region, `madvise(...,
MADV_DONTDUMP)` on it, disabling core dumps (`RLIMIT_CORE = 0` or
`prctl(PR_SET_DUMPABLE, 0)`), and encrypted swap. The caller-owned secret buffers
(the serialized `sk`, the shared secret) sit at addresses the consumer controls,
and their sizes are exposed (`SYNDROME_MAX_SK_BYTES`, `SYNDROME_MAX_SS_BYTES`), so
the consumer can lock those directly without any library hook.

## 11. References {#references}

The design leans on the spec plus three transform/proof papers and the NIST
recommendation. Citations, for anyone auditing the reasoning:

1. A. Annechini, A. Barenghi, G. Pelosi, S. Perriello. *Efficient QC-MDPC
   Cryptosystems with Bounded Decoding Failure Rate.* IACR ePrint 2025/1043.
   (`docs/specs/2025-1043.pdf`: authoritative for PKE, decoder, parameters,
   DFR.)
2. NIST SP 800-227, *Recommendations for Key-Encapsulation Mechanisms.*
   (`docs/NIST.SP.800-227.pdf`: authoritative for KEM interface/discipline.)
3. D. Hofheinz, K. Hövelmanns, E. Kiltz. *A Modular Analysis of the
   Fujisaki-Okamoto Transformation.* TCC 2017 (ePrint 2017/604). The `T`/`U`
   transform framework the spec cites (its [36]) for IND-CCA2.
4. T. Saito, K. Xagawa, T. Yamakawa. *Tightly-Secure Key-Encapsulation
   Mechanism in the Quantum Random Oracle Model.* EUROCRYPT 2018
   (ePrint 2017/1005). Tight QROM proof for the deterministic-PKE +
   implicit-rejection KEM, the basis for §4.5.
5. N. Bindel, M. Hamburg, K. Hövelmanns, A. Hülsing, E. Persichetti. *Tighter
   Proofs of CCA Security in the Quantum Random Oracle Model.* TCC 2019
   (ePrint 2019/590). QROM FO accounting for *correctness errors*, directly
   applicable to a failure-prone code-based KEM, and what makes the DFR margins
   in §3 sufficient under §4.5.
