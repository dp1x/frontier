"""Third, fully independent verification of expected bits.

Three things are checked that the earlier cross-check did NOT check independently:
  1. Hex input parsing, re-implemented from scratch (no oracle.parse_hex).
  2. Decimal input parsing, re-implemented from scratch (no oracle.parse_decimal).
  3. Rounding via decimal.Decimal at 80 digits of precision, a third algorithm
     distinct from oracle.py (scaled-integer) and crosscheck.py (binary search).

Fraction is used only for exact comparison of rationals.
"""
import json
import re
from decimal import Decimal, getcontext
from fractions import Fraction

getcontext().prec = 80

# ---------- independent parsers ----------

def indep_parse_decimal(text):
    t = text
    neg = t.startswith("-")
    if t and t[0] in "+-":
        t = t[1:]
    m = re.fullmatch(r"(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?", t)
    if not m:
        raise ValueError(text)
    ip, fp, ex = m.group(1) or "", m.group(2) or "", m.group(3)
    digits = (ip + fp) or "0"
    exp = int(ex) if ex else 0
    num = int(digits)
    den = 10 ** len(fp)
    if exp >= 0:
        num *= 10 ** exp
    else:
        den *= 10 ** (-exp)
    return (-1 if neg else 1) * Fraction(num, den)


def indep_parse_hex(text):
    t = text
    neg = t.startswith("-")
    if t and t[0] in "+-":
        t = t[1:]
    m = re.fullmatch(r"([0-9a-fA-F]*)(?:\.([0-9a-fA-F]*))?(?:[pP]([+-]?\d+))?", t)
    if not m:
        raise ValueError(text)
    ip, fp, ex = m.group(1) or "", m.group(2) or "", m.group(3)
    digits = (ip + fp) or "0"
    exp = int(ex) if ex else 0
    num = int(digits, 16)
    den = 16 ** len(fp)
    if exp >= 0:
        num <<= exp
    else:
        den <<= (-exp)
    return (-1 if neg else 1) * Fraction(num, den)


# ---------- third rounding algorithm: high-precision Decimal ----------

def round_with_decimal(x, typ):
    """Return (bits, tie) computed via 80-digit Decimal arithmetic."""
    if typ == "float":
        p, emin, emax, bias, mant_width, exp_width = 24, -126, 127, 127, 23, 8
    else:
        p, emin, emax, bias, mant_width, exp_width = 53, -1022, 1023, 1023, 52, 11

    if x == 0:
        return (1 << (mant_width + exp_width) if x < 0 else 0), False

    sign = -1 if x < 0 else 1
    a = Decimal(abs(x.numerator)) / Decimal(x.denominator)

    # find e with 2^e <= a < 2^(e+1) using Decimal comparisons only
    e = 0
    while Decimal(2) ** (e + 1) <= a:
        e += 1
    while a < Decimal(2) ** e:
        e -= 1

    if e < emin:
        scale_exp = emin - p + 1
        m = int((a / (Decimal(2) ** scale_exp)).to_integral_value(rounding="ROUND_HALF_EVEN"))
    else:
        scale_exp = e - p + 1
        m = int((a / (Decimal(2) ** scale_exp)).to_integral_value(rounding="ROUND_HALF_EVEN"))

    # exact tie detection: is a exactly halfway between m and its neighbour?
    scaled = a / (Decimal(2) ** scale_exp)
    frac = scaled - int(scaled)
    tie = (frac == Decimal("0.5"))

    if e < emin and m >= (1 << (p - 1)):
        e = emin
    if m == (1 << p):
        m >>= 1
        e += 1

    if e == emin and m < (1 << (p - 1)):
        expf, mantf = 0, m
    else:
        expf, mantf = e + bias, m - (1 << (p - 1))

    sign_bit = 1 if sign < 0 else 0
    bits = (sign_bit << (mant_width + exp_width)) | (expf << mant_width) | mantf
    return bits, tie


def main():
    vectors = json.load(open("R:/scratch/fc/vectors.json"))
    bad = 0
    for v in vectors:
        if v["grammar"] == "hex":
            x = indep_parse_hex(v["input"])
        else:
            x = indep_parse_decimal(v["input"])
        bits, tie = round_with_decimal(x, v["type"])
        ok = (bits == v["expected_bits"])
        if tie:
            ok = False
        if not ok:
            bad += 1
        print(f"{v['vector_id']:>4} {v['type']:<6} {v['input']:<22} "
              f"expect=0x{v['expected_bits']:x} indep=0x{bits:x} tie={tie} "
              f"{'OK' if ok else 'MISMATCH'}")
    print("mismatches:", bad)
    assert bad == 0


if __name__ == "__main__":
    main()
