"""Uniqueness proof: for each vector, decode the expected bit pattern with an
independent decoder and prove the exact input rational is STRICTLY closer to
the expected value than to its adjacent representable neighbour.

This does not reuse oracle.py's rounding. It only:
  1. decodes a bit pattern -> exact Fraction (independent decoder),
  2. compares exact distances.
"""
import json
import os
from fractions import Fraction
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
VECTOR_FILES = [
    os.path.join(_HERE, "vectors.json"),
    os.path.join(_HERE, "vectors_discriminator.json"),
    os.path.join(_HERE, "vectors_extra.json"),
]


def decode(bits, typ):
    """Independent IEEE-754 bit-pattern -> exact Fraction decoder."""
    if typ == "float":
        mant_width, exp_width, emin, bias = 23, 8, -126, 127
    else:
        mant_width, exp_width, emin, bias = 52, 11, -1022, 1023
    total = mant_width + exp_width + 1
    sign = -1 if (bits >> (total - 1)) & 1 else 1
    expf = (bits >> mant_width) & ((1 << exp_width) - 1)
    mant = bits & ((1 << mant_width) - 1)
    if expf == 0:
        if mant == 0:
            return Fraction(0)
        # Subnormal: mant * 2^(emin - mant_width). For binary32 this is
        # 2^-149, the correct smallest-subnormal scale.
        return sign * Fraction(mant) * Fraction(2) ** (emin - mant_width)
    e_unb = expf + emin - 1
    return sign * Fraction((1 << mant_width) | mant) * Fraction(2) ** (e_unb - mant_width)


def adjacents(bits, typ):
    """Return the two neighbouring representable values (same sign side)."""
    # bit-pattern neighbour (IEEE ordering holds within a sign)
    total = 32 if typ == "float" else 64
    sign_bit = (bits >> (total - 1)) & 1
    mag = bits & ((1 << (total - 1)) - 1)
    if sign_bit == 0:
        lower, upper = mag - 1, mag + 1
    else:
        lower, upper = mag - 1, mag + 1
    def rebuild(m):
        if m < 0:
            return None
        return (sign_bit << (total - 1)) | m
    return rebuild(lower), rebuild(upper)


def parse_decimal(t):
    neg = t.startswith("-")
    if t and t[0] in "+-":
        t = t[1:]
    m = re.fullmatch(r"(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?", t)
    ip, fp, ex = m.group(1) or "", m.group(2) or "", m.group(3)
    num = int((ip + fp) or "0")
    den = 10 ** len(fp)
    e = int(ex) if ex else 0
    if e >= 0:
        num *= 10 ** e
    else:
        den *= 10 ** (-e)
    return (-1 if neg else 1) * Fraction(num, den)


def parse_hex(t):
    neg = t.startswith("-")
    if t and t[0] in "+-":
        t = t[1:]
    m = re.fullmatch(r"([0-9a-fA-F]*)(?:\.([0-9a-fA-F]*))?(?:[pP]([+-]?\d+))?", t)
    ip, fp, ex = m.group(1) or "", m.group(2) or "", m.group(3)
    num = int((ip + fp) or "0", 16)
    den = 16 ** len(fp)
    e = int(ex) if ex else 0
    if e >= 0:
        num <<= e
    else:
        den <<= (-e)
    return (-1 if neg else 1) * Fraction(num, den)


def main():
    vectors = []
    for vf in VECTOR_FILES:
        if os.path.exists(vf):
            vectors.extend(json.load(open(vf)))
    bad = 0
    print(f"{'id':>4} {'type':<6} {'input':<22} {'expected':>18} {'dist_exp':>26} {'dist_adj':>26}  verdict")
    for v in vectors:
        x = parse_hex(v["input"]) if v["grammar"] == "hex" else parse_decimal(v["input"])
        exp_bits = v["expected_bits"]
        ve = decode(exp_bits, v["type"])
        lo, hi = adjacents(exp_bits, v["type"])
        cands = [(decode(b, v["type"]), b) for b in (lo, hi) if b is not None]
        dists = [(abs(x - c), c, b) for (c, b) in cands]
        dists.sort(key=lambda t: t[0])
        d_exp = abs(x - ve)
        # strict uniqueness: expected is strictly closer than BOTH neighbours
        strictly = all(d_exp < d for (d, c, b) in dists) and len(dists) == 2
        nearest_other = dists[0][1]
        if not strictly:
            bad += 1
        # also assert the expected value is the nearest of {ve} u neighbours
        ok = strictly and (d_exp < dists[0][0] or
                           (d_exp == dists[0][0] and False))
        print(f"{v['vector_id']:>4} {v['type']:<6} {v['input']:<22} 0x{exp_bits:016x} "
              f"{str(d_exp):>26} {str(dists[0][0]):>26}  "
              f"{'UNIQUE-NEAREST' if strictly else 'NOT-UNIQUE'}")
    print("non-unique vectors:", bad)
    assert bad == 0, "a primary vector is not strictly nearest"


if __name__ == "__main__":
    main()
