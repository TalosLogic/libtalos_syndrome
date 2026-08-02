# decode_oracle: from-spec decoder oracle for KAT vectors

An independent, clean-room reimplementation of the QC-MDPC bit-flipping decoder
of ePrint 2025/1043 (Algorithm 1), in Python, used **only** to decide the
*expected outcomes* of decoder KAT vectors for `tests/test_decode_kat.c`.

It exists because those expected outcomes, especially for the near-codeword /
half-codeword stress cases of `docs/DESIGN.md` §6.4, must come from something
other than the implementation under test, and the paper authors' DFR tool
(`model_DFR_3it.zip`) is no longer reachable (see `TODO.md`).

- Written from `docs/specs/2025-1043.pdf` (Algorithm 1) and `docs/SCHEME.md`
  **only**, not ported from the C decoder. Deliberately simple and
  non-constant-time. Never shipped or linked; this is an oracle.
- Emits self-contained JSON vectors `(h0, h1, e0, e1, ok, recovered e0'/e1')`,
  every block hex in the frozen `(M, s)` wire format (`docs/DESIGN.md` §7), so
  `decode_kat` can load them with `syndrome_gf2x_load` and compare directly.

## Usage

```sh
# sanity: random weight-t errors must round-trip (no vectors emitted)
python3 decode_oracle.py --param 128 --selftest

# human-readable JSON battery (random weight-t, near/half codewords, overlap)
python3 decode_oracle.py --param 128 --seed 0 --out dec128.json
```

Requires only Python 3 (3.10+ for the fast `int.bit_count()`; older works via a
fallback). λ=256 is several× slower (larger `p`).

## Hooking the vectors into the C tests

`tests/test_decode_kat.c` consumes a generated C header: no JSON parser in the
C code. From the repo root:

```sh
python3 tools/decode_oracle/decode_oracle.py --emit-c tests/decode_kat_vectors.h
```

This writes **both** parameter sets into one header, guarded by
`SYNDROME_LAMBDA`. Each set carries its key support (`DKAT_H0/H1`), each case's
error support, and the oracle's `expect_ok`. `test_decode_kat.c` picks it up
automatically via `__has_include`: if the header is present it rebuilds
`s = h0*e0 + h1*e1` per vector, runs the C decoder, and asserts `ok` matches
`expect_ok` (and, on success, that the recovered error matches the input). If
the header is absent the cross-check is skipped and only the self-validating
hand-built cases run, so the build never breaks.

**Commit the generated header** to arm the cross-check in CI (the vectors are
the frozen expected outcomes and should be reviewed like any KAT). Regenerate
with the same command if the decoder, thresholds, or parameters change, and
re-confirm the new outcomes against the spec / authors' reference before
committing a changed `expect_ok`.

## Trust boundary

`ok` / `recovered_*` are *this oracle's* decision. Two spec details are flagged
in the source and should be confirmed against Algorithm 1 in the PDF before
treating a borderline case as ground truth: the flip comparison is `>=`, and the
per-iteration thresholds are fixed constants (not syndrome-weight-dependent). For
high-assurance sign-off, cross-check a handful of vectors against the authors'
reference once obtained (the email TODO).

## Observed behaviour (λ=128, seed 0): a quick consistency check

Matches the §6.4 theory: random weight-`t` errors decode; pure near/half
codewords (weight `v`) all fail; weight-`t` errors fail once their overlap with
an `H` column gets large. If a future run disagrees with this shape, suspect the
thresholds or the flip rule.
