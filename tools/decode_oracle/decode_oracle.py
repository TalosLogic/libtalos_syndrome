#!/usr/bin/env python3
# Copyright (c) 2026 Jason Crawford
# SPDX-License-Identifier: AGPL-3.0-only
"""
decode_oracle.py - independent, from-spec oracle for the QC-MDPC bit-flipping
decoder of ePrint 2025/1043 (Algorithm 1), for generating decoder KAT vectors.

WHY THIS EXISTS
---------------
libtalos_syndrome's C decoder needs curated decode vectors whose *expected
outcomes* come from something other than the implementation under test --
especially the near-codeword / half-codeword stress cases of docs/DESIGN.md
§6.4, whose pass/fail is the whole point of the test.  The paper authors' DFR
tool (model_DFR_3it.zip) is no longer reachable, so this is a second,
clean-room implementation of the *exact* decoder, written only from
docs/specs/2025-1043.pdf (Algorithm 1) and docs/SCHEME.md -- NOT ported from the
C code.  It is deliberately simple and non-constant-time; it is an oracle, never
shipped or linked.

n0-GENERIC
----------
The decoder, sampler and vector battery are generic over the number of circulant
blocks n0 (2 for the KEM/opener Long-Term sets, 5 for the compact n0=5 sets).
For n0=2 the RNG draw order is identical to the original two-block generator, so
the emitted n0=2 vectors are byte-for-byte unchanged.

WHAT IT EMITS
-------------
Self-contained JSON vectors: for each case, the private key blocks h[i], the
error blocks e[i], and the decoder's outcome (ok, recovered e[i]').  Every block
is hex in the FROZEN (M, s) wire format (docs/DESIGN.md §7: circulant block,
little-endian bytes, LSB-first, canonical zero padding), so the C test can load
them with syndrome_gf2x_load and compare directly.

The decoder here consumes the PRIVATE syndrome s' = H*e^T = sum_i h[i]*e[i] (mod
x^p - 1), the same value the C decoder (syndrome_bitflip_decode) consumes -- see
docs/SCHEME.md "Decryption".

THRESHOLD / FLIP RULE (verify against Algorithm 1 in the PDF)
-------------------------------------------------------------
Per iteration: compute the unsatisfied-parity-check count upc for every variable
position, then flip ALL positions with upc >= threshold[iter] simultaneously and
update the syndrome (parallel bit-flipping), for exactly iterMax = 3 iterations.
The per-iteration thresholds are the pinned per-parameter-set constants.  Two
choices here are spec details worth confirming against the paper before trusting
a borderline outcome: (1) the comparison is ">=" (flip when count reaches the
threshold), and (2) thresholds are fixed per iteration (the greedy-optimized
design), not a function of the running syndrome weight.
"""
import argparse
import json
import sys

# Per-(lambda, n0) constants (docs/SCHEME.md, docs/DESIGN.md §3; thresholds are
# the pinned iteration-1/2/3 flip thresholds, decoder/threshold_impl.inc).
PARAMS = {
    (128, 2): {"p": 13613, "v": 69,  "t": 130, "thresholds": (41, 35, 35)},
    (256, 2): {"p": 43451, "v": 135, "t": 261, "thresholds": (77, 69, 69)},
    (128, 5): {"p": 7829,  "v": 83,  "t": 57,  "thresholds": (49, 42, 42)},
    (256, 5): {"p": 24733, "v": 165, "t": 113, "thresholds": (93, 85, 84)},
    (128, 3): {"p": 10037, "v": 77,  "t": 83,  "thresholds": (45, 41, 40)},
    (128, 4): {"p": 8627,  "v": 81,  "t": 66,  "thresholds": (48, 41, 41)},
    (192, 2): {"p": 26813, "v": 103, "t": 195, "thresholds": (60, 53, 52)},
    (192, 3): {"p": 19709, "v": 115, "t": 124, "thresholds": (66, 60, 59)},
    (192, 4): {"p": 16829, "v": 121, "t": 98,  "thresholds": (70, 62, 61)},
    (192, 5): {"p": 15373, "v": 125, "t": 85,  "thresholds": (71, 66, 64)},
    (256, 3): {"p": 32069, "v": 153, "t": 165, "thresholds": (87, 78, 78)},
    (256, 4): {"p": 27437, "v": 161, "t": 131, "thresholds": (91, 82, 82)},
}
# The original four sets lead and keep their order so their emitted vectors
# re-emit byte-for-byte; the eight fill sets are appended.
SETS = ((128, 2), (128, 5), (256, 2), (256, 5),
        (128, 3), (128, 4), (192, 2), (192, 3),
        (192, 4), (192, 5), (256, 3), (256, 4))
ITERMAX = 3


def popcount(x):
    # int.bit_count() is Python 3.10+; fall back for older interpreters.
    try:
        return x.bit_count()
    except AttributeError:
        return bin(x).count("1")


# --- circulant ring F_2[x]/(x^p - 1), elements as p-bit Python ints ----------

def rotl(a, m, p, mask):
    """x^m * a(x) mod (x^p - 1): cyclic left shift of the p-bit value a by m."""
    m %= p
    if m == 0:
        return a
    return ((a << m) | (a >> (p - m))) & mask


def ring_mul(a, b, p, mask):
    """a(x) * b(x) mod (x^p - 1), schoolbook over the set bits of b."""
    r = 0
    bb = b
    j = 0
    while bb:
        if bb & 1:
            r ^= rotl(a, j, p, mask)
        bb >>= 1
        j += 1
    return r


# --- wire format (docs/DESIGN.md §7) -----------------------------------------

def block_to_hex(a, p):
    """Pack a p-bit ring element to the frozen wire format, as lowercase hex.

    Coefficient x^j -> byte j>>3, bit j&7 (little-endian, LSB-first); the top
    8*ceil(p/8) - p padding bits are zero (canonical).
    """
    nbytes = (p + 7) // 8
    return a.to_bytes(nbytes, "little").hex()


def hex_to_block(h, p):
    mask = (1 << p) - 1
    return int.from_bytes(bytes.fromhex(h), "little") & mask


def indices_to_block(idx, p):
    a = 0
    for i in idx:
        a |= 1 << (i % p)
    return a


def block_support(a):
    s, j = [], 0
    while a:
        if a & 1:
            s.append(j)
        a >>= 1
        j += 1
    return s


# --- the decoder (Algorithm 1), generic over n0 blocks -----------------------

def bitflip_decode(h, s_in, p, mask, thresholds):
    """3-iteration parallel bit-flipping over n0 = len(h) blocks.

    Inputs: private key blocks h[i] and the private syndrome s_in = sum_i
    h[i]*e[i].  Returns (e_hat, ok) where e_hat is the list of recovered error
    blocks and ok is True iff the residual syndrome is zero after iterMax
    iterations.
    """
    n0 = len(h)
    e = [0] * n0
    s = s_in
    for it in range(ITERMAX):
        th = thresholds[it]
        # upc for variable (block b, m) = popcount(s & (x^m * h[b])).
        flips = [[m for m in range(p) if popcount(s & rotl(h[b], m, p, mask)) >= th]
                 for b in range(n0)]
        # Apply all flips simultaneously, then update the syndrome.
        for b in range(n0):
            for m in flips[b]:
                e[b] ^= 1 << m
                s ^= rotl(h[b], m, p, mask)
        if s == 0:
            break
    return e, (s == 0)


def private_syndrome(h, e, p, mask):
    s = 0
    for hb, eb in zip(h, e):
        s ^= ring_mul(hb, eb, p, mask)
    return s


# --- sampling / structured-error construction --------------------------------

def sample_distinct(rng, weight, n):
    s = set()
    while len(s) < weight:
        s.add(rng.randrange(n))
    return sorted(s)


def random_block(rng, p, v):
    """A weight-v ring element (v is odd per spec)."""
    return indices_to_block(sample_distinct(rng, v, p), p)


def split_error(idx, n0, p):
    """Split a weight-t index list over n = n0*p into n0 p-bit blocks."""
    return [indices_to_block([i - b * p for i in idx if b * p <= i < (b + 1) * p], p)
            for b in range(n0)]


def random_error(rng, p, t, n0):
    """A weight-t error over n = n0*p, split into n0 p-bit blocks."""
    return split_error(sample_distinct(rng, t, n0 * p), n0, p)


def near_codeword(h, target, source, shift, p, mask, n0):
    """Structured error: put a column of H_source (a rotation of h[source]) into
    block `target`; every other block is empty (docs/DESIGN.md §6.4).

    near codeword: source == target; half codeword: source != target.  Weight v,
    NOT t -- these probe the decoder outside its weight-t regime; the *outcome*
    is exactly what we want the oracle (not the C code) to decide.
    """
    col = rotl(h[source], shift, p, mask)
    e = [0] * n0
    e[target] = col
    return e


def overlap_error(rng, h, block, shift, overlap, p, mask, t, n0):
    """A weight-t error that shares `overlap` set bits with a column of H_block
    (a rotation of h[block] placed in `block`), the rest random -- the
    "substantial overlap" stress of §6.4.
    """
    col_support = block_support(rotl(h[block], shift, p, mask))
    overlap = min(overlap, len(col_support))
    chosen = set(rng.sample(col_support, overlap))
    # Fill the rest of the weight-t budget with random distinct positions over N.
    out = {(block * p + c) for c in chosen}
    while len(out) < t:
        out.add(rng.randrange(n0 * p))
    return split_error(sorted(out), n0, p)


# --- vector emission ---------------------------------------------------------

def make_vector(name, h, e, p, mask, thresholds):
    s = private_syndrome(h, e, p, mask)
    r, ok = bitflip_decode(h, s, p, mask, thresholds)
    return {
        "name": name,
        "h": [block_to_hex(hb, p) for hb in h],
        "e": [block_to_hex(eb, p) for eb in e],
        "ok": ok,
        "recovered_e": [block_to_hex(rb, p) for rb in r],
        "round_trip": ok and r == e,
    }


def build_cases(lam, n0, seed):
    """Compose the vector battery as raw ring elements (shared by every emitter).

    Returns a dict with p, v, t, thresholds, mask, the single key h[0..n0-1], and
    a list of (name, [e blocks]) cases.  The n0=2 draw order matches the original
    two-block generator, so its emitted vectors are byte-for-byte unchanged.
    """
    import random

    pp = PARAMS[(lam, n0)]
    p, v, t, th = pp["p"], pp["v"], pp["t"], pp["thresholds"]
    mask = (1 << p) - 1
    rng = random.Random(seed)

    h = [random_block(rng, p, v) for _ in range(n0)]
    cases = []

    # 1. Baseline: random weight-t errors must round-trip (sanity on the oracle).
    for i in range(3):
        cases.append((f"random_weight_t_{i}", random_error(rng, p, t, n0)))

    # 2. Pure near-codeword (source==target) and half-codeword (source!=target),
    #    a few shifts.  Weight v; outcome decided by the oracle.  Kept identical
    #    across n0 (block 0 target, source 0 or 1) so n0=2 vectors do not move.
    for shift in (0, 1, 7):
        cases.append((f"near_cw_b0_shift{shift}",
                      near_codeword(h, 0, 0, shift, p, mask, n0)))
        cases.append((f"half_cw_b0_src1_shift{shift}",
                      near_codeword(h, 0, 1, shift, p, mask, n0)))

    # 3. Weight-t errors overlapping a column of H by varying amounts.
    for ov in (v // 4, v // 2, (3 * v) // 4, v):
        cases.append((f"overlap_b0_ov{ov}",
                      overlap_error(rng, h, 0, 0, ov, p, mask, t, n0)))

    return {"p": p, "v": v, "t": t, "th": th, "mask": mask, "h": h,
            "cases": cases}


def build_battery(lam, n0, seed):
    c = build_cases(lam, n0, seed)
    p, mask, th, h = c["p"], c["mask"], c["th"], c["h"]
    vecs = [make_vector(n, h, e, p, mask, th) for (n, e) in c["cases"]]
    return p, vecs


# --- C-header emission (for tests/test_decode_kat.c) -------------------------

def _fmt_u16_array(name, vals):
    """A `static const uint16_t name[] = { ... };` C definition.  Empty support
    is emitted as `{0}` (a length-0 vector is tracked by a separate length)."""
    if not vals:
        return "static const uint16_t " + name + "[] = {0};"
    lines = []
    for i in range(0, len(vals), 16):
        lines.append("    " + ", ".join(str(x) for x in vals[i:i + 16]) + ",")
    return ("static const uint16_t " + name + "[] = {\n" +
            "\n".join(lines) + "\n};")


def _emit_set(out, lam, n0, seed, first):
    c = build_cases(lam, n0, seed)
    p, mask, th, h = c["p"], c["mask"], c["th"], c["h"]
    out.append(("#if" if first else "#elif") +
               " SYNDROME_LAMBDA == %d && SYNDROME_N0 == %d" % (lam, n0))
    # Key blocks h[0..n0-1].
    for b in range(n0):
        out.append(_fmt_u16_array("DKAT_H%d" % b, block_support(h[b])))
    out.append("static const uint16_t *const DKAT_H[SYNDROME_N0] = { %s };" %
               ", ".join("DKAT_H%d" % b for b in range(n0)))
    # Per-case error support, one array per block.
    rows = []
    for ci, (name, e) in enumerate(c["cases"]):
        supports = [block_support(eb) for eb in e]
        for b in range(n0):
            out.append(_fmt_u16_array("kv%d_b%d" % (ci, b), supports[b]))
        eptrs = ", ".join("kv%d_b%d" % (ci, b) for b in range(n0))
        elens = ", ".join(str(len(supports[b])) for b in range(n0))
        s = private_syndrome(h, e, p, mask)
        _, ok = bitflip_decode(h, s, p, mask, th)
        rows.append('    { "%s", %d, { %s }, { %s } },'
                    % (name, 1 if ok else 0, eptrs, elens))
    out.append("static const syndrome_decode_kat_vec SYNDROME_DECODE_KAT[] = {")
    out.extend(rows)
    out.append("};")
    out.append("#define SYNDROME_DECODE_KAT_COUNT "
               "(sizeof SYNDROME_DECODE_KAT / sizeof SYNDROME_DECODE_KAT[0])")


def emit_c(path, seed):
    """Write a self-contained C header of decode vectors for all twelve
    parameter sets, keyed on (SYNDROME_LAMBDA, SYNDROME_N0).

    Each set carries its own key support (DKAT_H[b]) and per-case error support
    (uint16 positions, < p) plus the oracle's expected `ok`; the C test loads
    them, rebuilds s = sum_b h[b]*e[b], and asserts the C decoder agrees.
    """
    out = [
        "/*",
        " * Copyright (c) 2026 Jason Crawford",
        " * SPDX-License-Identifier: AGPL-3.0-only",
        " */",
        "",
        "/* AUTO-GENERATED by tools/decode_oracle/decode_oracle.py --emit-c.",
        " * Decoder KAT vectors with independent from-spec oracle outcomes",
        " * (docs/DESIGN.md §6.4; see tools/decode_oracle/README.md).  Do not edit",
        " * by hand -- regenerate.  Error/key blocks are uint16 support positions",
        " * (< p); expect_ok is the oracle's decision.  Keyed on (lambda, n0). */",
        "#ifndef SYNDROME_DECODE_KAT_VECTORS_H",
        "#define SYNDROME_DECODE_KAT_VECTORS_H",
        "",
        "#include <stdint.h>",
        "",
        '#include "talos_syndrome.h"',
        "",
        "typedef struct {",
        "    const char *name;",
        "    int expect_ok;",
        "    const uint16_t *e[SYNDROME_N0];",
        "    uint16_t e_len[SYNDROME_N0];",
        "} syndrome_decode_kat_vec;",
        "",
    ]
    first = True
    for (lam, n0) in SETS:
        _emit_set(out, lam, n0, seed, first)
        first = False
    out.append("#else")
    out.append('#error "no decode KAT vectors for this (SYNDROME_LAMBDA, SYNDROME_N0)"')
    out.append("#endif")
    out.append("#endif /* SYNDROME_DECODE_KAT_VECTORS_H */")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote C header %s (all twelve parameter sets, seed=%d)" % (path, seed))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--param", type=int, choices=(128, 192, 256), default=128,
                    help="security level lambda (default 128)")
    ap.add_argument("--n0", type=int, choices=(2, 3, 4, 5), default=2,
                    help="number of circulant blocks (default 2)")
    ap.add_argument("--seed", type=int, default=0,
                    help="PRNG seed for reproducible vectors (default 0)")
    ap.add_argument("--out", default=None,
                    help="write JSON vectors to this file (default: stdout)")
    ap.add_argument("--selftest", action="store_true",
                    help="only check that random weight-t errors round-trip")
    ap.add_argument("--emit-c", dest="emit_c", default=None,
                    help="write a C header of vectors (ALL parameter sets) for "
                         "tests/test_decode_kat.c, then exit")
    args = ap.parse_args()

    if args.emit_c:
        emit_c(args.emit_c, args.seed)
        return 0

    p, vecs = build_battery(args.param, args.n0, args.seed)

    if args.selftest:
        rt = [v for v in vecs if v["name"].startswith("random_weight_t_")]
        bad = [v["name"] for v in rt if not v["round_trip"]]
        if bad:
            print(f"SELFTEST FAIL (lambda={args.param}, n0={args.n0}): "
                  f"no round-trip: {bad}", file=sys.stderr)
            return 1
        print(f"selftest OK (lambda={args.param}, n0={args.n0}): "
              f"{len(rt)} random weight-t errors round-tripped")
        return 0

    doc = {
        "lambda": args.param,
        "p": p,
        "n0": args.n0,
        "seed": args.seed,
        "wire_format": "circulant block, little-endian bytes, LSB-first, "
                       "canonical zero padding (docs/DESIGN.md §7)",
        "note": "ok / recovered_* are this oracle's decision; cross-check vs the "
                "authors' reference before treating borderline cases as ground "
                "truth (see TODO.md).",
        "vectors": vecs,
    }
    out = json.dumps(doc, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
        n_ok = sum(1 for v in vecs if v["ok"])
        print(f"wrote {len(vecs)} vectors to {args.out} "
              f"(lambda={args.param}, n0={args.n0}; {n_ok} decode ok)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
