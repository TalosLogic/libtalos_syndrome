# Proteus seed-based key API

Reference for the seed-based key-management surface (the *Proteus* seed API). The
authoritative design record is [`docs/DESIGN.md`](DESIGN.md) §5; the frozen ABI
lives in [`include/talos_syndrome.h`](../include/talos_syndrome.h). This file is a
usage-oriented summary and defers to both on any conflict.

## What it provides

A private key is a deterministic function of a small **2λ-bit root seed**, and the
public key is a deterministic function of the private key (`M₀ = H₍ₙ₀₋₁₎⁻¹ H₀`).
The API exposes both facts:

- **Compressed key-at-rest.** Persist a `syndrome_keyseed_bytes(set)` root seed
  (32 B @ λ128 / 64 B @ λ256) instead of the full `sk` / `pk`, and rebuild both on
  startup.
- **Public-key recovery.** Recompute `pk` from `sk` alone (backup / recovery, or
  to avoid shipping `pk` when the holder has `sk`).
- **Credential foundation (in design).** The 2λ-byte seed fits a single Grøstl
  block, which is what would let libtalos_voleith use it as a VOLE-in-the-Head
  signing witness to give the keypair signature capability. That unified-credential
  construction is still in the design phase and is not part of this release; this
  file covers only the shipped syndrome-side seed plumbing.

## Entry points

```c
/* Fresh keypair; also returns the persistable, self-describing seed blob. */
int syndrome_kem_keypair_keep_seed(syndrome_set_id set, syndrome_xof_id xof,
                                   uint8_t *pk, uint8_t *sk, uint8_t *blob);

/* Deterministically reconstruct (pk, sk) from a stored seed blob. */
int syndrome_kem_keypair_from_seed(syndrome_set_id set, uint8_t *pk, uint8_t *sk,
                                   const uint8_t *blob);

/* Recompute the public key from the secret key alone. */
int syndrome_kem_pubkey_from_sk(syndrome_set_id set, uint8_t *pk, const uint8_t *sk);
```

`syndrome_kem_keypair_from_seed` is the core; `keep_seed` draws a random seed,
calls the core, and returns the blob; the plain `syndrome_kem_keypair` draws a
random seed, calls the core, and discards it. All three return `0` / negative per
house style, are constant-time in the seed / `sk`, and zeroize every output on
failure.

## The persisted blob

`syndrome_seedblob_bytes(set)` = an 8-byte header followed by the 2λ-bit raw seed:

```
header(8) = lambda/8(1) || n0(1) || xof_id(1) || format(1) || reserved(4, zero)
blob      = header(8) || seed(2*lambda/8)
```

The library builds and validates the header from the `(set, xof)` you pass, so a
λ128 blob cannot reconstruct as λ256, an `n0=2` blob cannot reconstruct as
`n0=5`, and a key derived under one XOF cannot reconstruct under another.

## Seed-expansion XOF

The XOF is an axis **orthogonal** to the `(lambda, n0)` set. 1.0.0 ships
`SYNDROME_XOF_SHAKE256` only; the `xof_id` byte is present-and-fixed in the
derivation domain, so a future GF(2⁸)-native XOF (for in-circuit key-derivation
proofs) is an additive new `xof_id` value that never reinterprets an existing key.
The derivation pipeline is:

```
dm[48] = SHAKE256("TALOSProteus" || header(8) || seed)   # 48-byte CTR_DRBG material
       -> AES-256 CTR_DRBG -> syndrome_kem_keypair_derand
```

## Frozen ABI

Once 1.0.0 ships, the derivation pipeline (domain string, header, SHAKE256
expansion, CTR_DRBG, keygen consumption) is a compatibility contract: any change
silently invalidates every stored seed. `SYNDROME_SEED_FORMAT_VERSION` makes such
a change detectable at load. Full rationale and the CT / zeroization obligations
are in [`docs/DESIGN.md`](DESIGN.md) §5.
