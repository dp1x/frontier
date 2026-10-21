"""Exact rational oracle for from_chars rounding-mode experiment.

No use of std::from_chars, strtod, Python float(), or any target library.
Uses integer arithmetic and fractions.Fraction only as exact rational.
"""
import json
import re
from fractions import Fraction
from math import gcd

TYPES = {
    "float": {"p": 24, "emin": -126, "emax": 127, "bias": 127, "bits": 32, "mant_width": 23},
    "double": {"p": 53, "emin": -1022, "emax": 1023, "bias": 1023, "bits": 64, "mant_width": 52},
}


def parse_decimal(s):
    s = s.strip()
    sign = -1 if s.startswith("-") else 1
    if s and s[0] in "+-":
        s = s[1:]
    if "e" in s or "E" in s:
        idx = max(s.find("e"), s.find("E"))
        mant = s[:idx]
        exp10 = int(s[idx + 1:])
    else:
        mant = s
        exp10 = 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = ip + fp
    if digits == "":
        digits = "0"
    num = int(digits)
    frac_len = len(fp)
    # value = num * 10^(exp10 - frac_len)
    shift = exp10 - frac_len
    if shift >= 0:
        num2 = num * (10 ** shift)
        den2 = 1
    else:
        num2 = num
        den2 = 10 ** (-shift)
    g = gcd(num2, den2) if den2 != 0 else 1
    if g == 0:
        g = 1
    num2 //= g
    den2 //= g
    if num2 == 0:
        den2 = 1
    return sign, num2, den2


def parse_hex(s):
    s = s.strip()
    sign = -1 if s.startswith("-") else 1
    if s and s[0] in "+-":
        s = s[1:]
    if "p" in s or "P" in s:
        low = s.lower()
        idx = low.find("p")
        mant = s[:idx]
        exp2 = int(s[idx + 1:])
    else:
        mant = s
        exp2 = 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = ip + fp
    if digits == "":
        digits = "0"
    num = int(digits, 16)
    frac_len = len(fp)
    shift = exp2 - 4 * frac_len
    if shift >= 0:
        num2 = num * (2 ** shift)
        den2 = 1
    else:
        num2 = num
        den2 = 2 ** (-shift)
    g = gcd(num2, den2) if den2 != 0 else 1
    if g == 0:
        g = 1
    num2 //= g
    den2 //= g
    if num2 == 0:
        den2 = 1
    return sign, num2, den2


def floor_log2_rational(n, d):
    # n,d positive ints; find e with 2^e <= n/d < 2^(e+1)
    e = n.bit_length() - d.bit_length()
    def le_pow(k):
        # 2^k <= n/d  <=>  n >= d*2^k
        if k >= 0:
            return n >= d * (1 << k)
        else:
            return n * (1 << (-k)) >= d
    while le_pow(e + 1):
        e += 1
    while not le_pow(e):
        e -= 1
    return e


def to_rational_bits(typ, sign, num, den):
    cfg = TYPES[typ]
    p = cfg["p"]
    emin = cfg["emin"]
    emax = cfg["emax"]
    bias = cfg["bias"]
    mant_width = cfg["mant_width"]
    total_bits = cfg["bits"]

    neg = sign < 0
    n = abs(num)
    d = den

    # max finite
    max_mant = (1 << p) - 1
    max_fin_n = max_mant * (1 << (emax - p + 1))
    max_fin_d = 1
    in_range = (n * max_fin_d <= max_fin_n * d)

    if n == 0:
        bits = (1 if neg else 0) << (total_bits - 1)
        return {
            "bits": bits,
            "adjacent_bits": bits,
            "tie": False,
            "in_range": True,
            "finite": True,
            "q": 0,
            "e": 0,
            "expected_rational": "0",
            "adjacent_rational": "0",
            "dist_expected_ulp": "0",
            "dist_adjacent_ulp": "0",
        }

    e = floor_log2_rational(n, d)
    orig_e = e
    if e < emin:
        e = emin
    if e > emax:
        e = emax
        in_range = False

    ulp_exp = e - (p - 1)
    if ulp_exp >= 0:
        Nt = n
        Dt = d * (1 << ulp_exp)
    else:
        Nt = n * (1 << (-ulp_exp))
        Dt = d

    q_floor = Nt // Dt
    rem = Nt - q_floor * Dt
    tie = (rem * 2 == Dt)

    # determine rounding
    round_up = False
    if rem * 2 > Dt:
        round_up = True
    elif rem * 2 == Dt:
        # tie to even
        if q_floor % 2 == 1:
            round_up = True

    if round_up:
        q_exp = q_floor + 1
    else:
        q_exp = q_floor

    # carry
    e_final = e
    if q_exp == (1 << p):
        q_exp >>= 1
        e_final += 1
        if e_final > emax:
            in_range = False
            e_final = emax

    # subnormal encoding
    if e_final == emin and q_exp < (1 << (p - 1)):
        exp_field = 0
        mant_field = q_exp
    else:
        exp_field = e_final + bias
        mant_field = q_exp - (1 << (p - 1))

    # clamp exponent field for overflow safety
    if exp_field > (1 << (8 if typ == "float" else 11)) - 1:
        exp_field = (1 << (8 if typ == "float" else 11)) - 1
        in_range = False

    sign_bit = 1 if neg else 0
    bits = (sign_bit << (total_bits - 1)) | (exp_field << mant_width) | mant_field

    # competitor (the other candidate in same ulp bin, pre-carry exponent e)
    comp_mant = q_floor if round_up else (q_floor + 1)
    if comp_mant >= (1 << p):
        comp_mant = (1 << p) - 1
    # encode competitor with exponent e (original clamped)
    e_comp = e
    if e_comp == emin and comp_mant < (1 << (p - 1)):
        exp_field_c = 0
        mant_field_c = comp_mant
    else:
        exp_field_c = e_comp + bias
        mant_field_c = comp_mant - (1 << (p - 1))
        if comp_mant < (1 << (p - 1)):
            # shouldn't happen for comp in same bin except subnormal; handle
            mant_field_c = comp_mant
            exp_field_c = 0
    if exp_field_c > (1 << (8 if typ == "float" else 11)) - 1:
        exp_field_c = (1 << (8 if typ == "float" else 11)) - 1
    adj_bits = (sign_bit << (total_bits - 1)) | (exp_field_c << mant_width) | mant_field_c

    # rationals
    def bits_to_value(b):
        # returns Fraction for a given bit pattern
        sign_b = (b >> (total_bits - 1)) & 1
        exp_f = (b >> mant_width) & ((1 << (8 if typ == "float" else 11)) - 1)
        mant_f = b & ((1 << mant_width) - 1)
        if exp_f == 0:
            # subnormal
            m = mant_f
            e_unb = emin  # value = m * 2^(emin - p + 1)? Actually subnormal: m * 2^(emin - p + 1) with m < 2^(p-1)
            # exponent for subnormal ulp: emin - p + 1
            val = Fraction(m * (1 << (emin - p + 1)) if m else 0)  # but 2^negative -> use Fraction
            # use Fraction with power
            val = Fraction(m, 1 << (p - 1 - (emin)))  # careful
        # easier: use float formula via Fraction powers
        return None

    # Instead compute expected rational from q_exp and e_final
    # value = sign * q_exp * 2^(e_final - p + 1)
    exp_val = e_final - (p - 1)
    if exp_val >= 0:
        exp_rat = Fraction(q_exp * (1 << exp_val)) * (1 if not neg else -1)
    else:
        exp_rat = Fraction(q_exp, 1 << (-exp_val)) * (1 if not neg else -1)

    comp_exp_val = e - (p - 1)
    if comp_exp_val >= 0:
        comp_rat = Fraction(comp_mant * (1 << comp_exp_val)) * (1 if not neg else -1)
    else:
        comp_rat = Fraction(comp_mant, 1 << (-comp_exp_val)) * (1 if not neg else -1)

    input_rat = Fraction(num, den) * (1 if sign > 0 else -1)

    dist_exp = abs(input_rat - exp_rat)
    dist_comp = abs(input_rat - comp_rat)

    # express distances in ULP units (divide by 2^(e_final-p+1)? use expected ulp)
    ulp = Fraction(1, 1 << (-(e_final - (p - 1)))) if (e_final - (p - 1)) < 0 else Fraction(1 << (e_final - (p - 1)))
    # distance in ulp = dist / ulp
    dist_exp_ulp = dist_exp / ulp
    dist_comp_ulp = dist_comp / (Fraction(1, 1 << (-(e - (p - 1)))) if (e - (p - 1)) < 0 else Fraction(1 << (e - (p - 1))))

    return {
        "bits": bits,
        "adjacent_bits": adj_bits,
        "tie": tie,
        "in_range": in_range,
        "finite": True,
        "q_floor": q_floor,
        "q_expected": q_exp,
        "e": e_final,
        "expected_rational": str(exp_rat),
        "adjacent_rational": str(comp_rat),
        "input_rational": str(input_rat),
        "dist_expected": str(dist_exp),
        "dist_adjacent": str(dist_comp),
        "dist_expected_ulp": str(dist_exp_ulp),
        "dist_adjacent_ulp": str(dist_comp_ulp),
    }


def parse(s, grammar):
    if grammar == "hex":
        return parse_hex(s)
    return parse_decimal(s)


if __name__ == "__main__":
    # self-test
    # 1.0 float
    sign, n, d = parse_decimal("1.0")
    r = to_rational_bits("float", sign, n, d)
    print("1.0 float bits:", hex(r["bits"]), r["tie"], r["in_range"])
    assert r["bits"] == 0x3F800000
    # 0.5 double
    sign, n, d = parse_decimal("0.5")
    r = to_rational_bits("double", sign, n, d)
    print("0.5 double bits:", hex(r["bits"]))
    assert r["bits"] == 0x3FE0000000000000
    # 2.0
    sign, n, d = parse_decimal("2.0")
    r = to_rational_bits("float", sign, n, d)
    assert r["bits"] == 0x40000000
    # hex 1.8p0 = 1.5? 0x1.8 = 1.5
    sign, n, d = parse_hex("1.8p0")
    r = to_rational_bits("float", sign, n, d)
    print("1.8p0 float bits:", hex(r["bits"]))
    assert r["bits"] == 0x3FC00000
    # negative
    sign, n, d = parse_decimal("-1.0")
    r = to_rational_bits("float", sign, n, d)
    assert r["bits"] == 0xBF800000
    print("self-tests passed")
