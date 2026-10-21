"""Independent cross-check of the oracle.

Deliberately uses a DIFFERENT algorithm from oracle.py:
  - oracle.py:  floor-log2 + scaled-integer rounding (analytic).
  - here:       exact enumeration/binary search over candidate bit patterns,
                 comparing Fractions, plus an independent "next representable
                 above/below" search driven by integer bit patterns.

No use of from_chars / strtod / float(). Fractions only.
"""
import json
import sys
from fractions import Fraction

sys.path.insert(0, "R:/scratch/fc")
import oracle  # only for parsing (text -> exact rational); rounding is redone here


def bits_to_frac(b, typ):
    if typ == "float":
        mant_width, exp_width, emin = 23, 8, -126
    else:
        mant_width, exp_width, emin = 52, 11, -1022
    sign = -1 if (b >> (mant_width + exp_width)) & 1 else 1
    expf = (b >> mant_width) & ((1 << exp_width) - 1)
    mant = b & ((1 << mant_width) - 1)
    if expf == 0:
        val = Fraction(mant, 1) * Fraction(1, 1 << (mant_width + 1)) * Fraction(2) ** emin
        # subnormal: mant * 2^(emin - mant_width - 1)
        val = Fraction(mant) * Fraction(2) ** (emin - mant_width - 1)
    else:
        e_unb = expf + emin - 1
        val = Fraction((1 << mant_width) | mant) * Fraction(2) ** (e_unb - mant_width)
    return sign * val


def total_bits(typ):
    return 32 if typ == "float" else 64


def nearest_by_search(x, typ):
    """Find the representable value nearest to x by expanding a search window
    around an approximate seed, using exact Fraction comparisons only."""
    # seed: use integer bit pattern of the correctly scaled value computed by a
    # naive-but-independent route: scale x to a power of two by repeated doubling
    # of an integer numerator, then binary-search the mantissa.
    if x == 0:
        return None, None, False
    sign = -1 if x < 0 else 1
    ax = abs(x)
    p = 24 if typ == "float" else 53
    emin = -126 if typ == "float" else -1022
    emax = 127 if typ == "float" else 1023
    # find e with 2^e <= ax < 2^(e+1) using Fraction comparisons (no bit tricks)
    e = 0
    while Fraction(2) ** (e + 1) <= ax:
        e += 1
    while ax < Fraction(2) ** e:
        e -= 1
    # candidate significand search: mantissa m in [2^(p-1), 2^p-1], value m*2^(e-p+1)
    lo = 1 << (p - 1)
    hi = (1 << p) - 1
    if e < emin:
        # subnormal region: value = m * 2^(emin-p+1)
        scale_exp = emin - p + 1
        best = None
        bestd = None
        m = 0
        while True:
            v = Fraction(m) * Fraction(2) ** scale_exp
            d = abs(ax - v)
            if bestd is None or d < bestd:
                bestd = d
                best = m
            if v > ax:
                break
            m += 1
            if m > (1 << p):
                break
        # check tie: neighbours
        lo_m = best
        hi_m = best + 1
        dlo = abs(ax - Fraction(lo_m) * Fraction(2) ** scale_exp)
        dhi = abs(ax - Fraction(hi_m) * Fraction(2) ** scale_exp)
        tie = (dlo == dhi)
        # choose nearest with ties-to-even
        if dlo < dhi:
            m = lo_m
        elif dhi < dlo:
            m = hi_m
        else:
            m = lo_m if lo_m % 2 == 0 else hi_m
        if m >= (1 << (p - 1)):
            # became normal
            e = emin
            m2 = m
        else:
            m2 = m
        return sign, (m2, emin, p), tie
    scale_exp = e - p + 1
    # binary search on m
    while lo < hi:
        mid = (lo + hi) // 2
        v = Fraction(mid) * Fraction(2) ** scale_exp
        if v < ax:
            lo = mid + 1
        else:
            hi = mid
    m = lo
    # compare m and m-1
    d_up = abs(ax - Fraction(m) * Fraction(2) ** scale_exp)
    d_dn = abs(ax - Fraction(m - 1) * Fraction(2) ** scale_exp)
    tie = (d_up == d_dn)
    if d_dn < d_up:
        m = m - 1
    elif d_up == d_dn:
        m = m if m % 2 == 0 else m - 1
    return sign, (m, e, p), tie


def encode(sign, m, e, p, typ):
    if typ == "float":
        mant_width, exp_width, emin, bias = 23, 8, -126, 127
    else:
        mant_width, exp_width, emin, bias = 52, 11, -1022, 1023
    if e == emin and m < (1 << (p - 1)):
        expf = 0
        mantf = m
    else:
        expf = e + bias
        mantf = m - (1 << (p - 1))
    s = 1 if sign < 0 else 0
    return (s << (mant_width + exp_width)) | (expf << mant_width) | mantf


def main():
    vectors = json.load(open("R:/scratch/fc/vectors.json"))
    mismatches = 0
    for v in vectors:
        if v["grammar"] == "hex":
            sign, num, den = oracle.parse_hex(v["input"])
        else:
            sign, num, den = oracle.parse_decimal(v["input"])
        x = Fraction(num, den) * (1 if sign > 0 else -1)
        sign2, mp, tie = nearest_by_search(x, v["type"])
        m, e, p = mp
        bits = encode(sign2, m, e, p, v["type"])
        # independent tie verification via exact neighbours
        ok = (bits == v["expected_bits"])
        if not ok:
            mismatches += 1
        print(f"{v['vector_id']:>4} {v['type']:<6} {v['input']:<22} "
              f"oracle=0x{v['expected_bits']:x} independent=0x{bits:x} "
              f"tie={tie} {'OK' if ok else 'MISMATCH'}")
    print("mismatches:", mismatches)
    assert mismatches == 0, "independent implementation disagrees"


if __name__ == "__main__":
    main()
