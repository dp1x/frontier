// Mechanistic reproduction of the libc++ Clinger fast path.
//
// Source under test: llvm-project release/20.x
//   libc/src/__support/str_to_float.h
//     clinger_fast_path():
//       result = FPBits(float_mantissa / POWERS_OF_TEN_ARRAY[-exp10]);   (exp10 < 0)
//       result = FPBits(float_mantissa * POWERS_OF_TEN_ARRAY[exp10]);    (exp10 > 0)
//   libcxx/src/include/from_chars_floating_point.h
//     __from_chars_floating_point_decimal():
//       decimal_exp_to_float<_Fp>(..., RoundDirection::Nearest, ...)
//
// This program parses the same decimal input the way libc++ does (integer
// mantissa + decimal exponent), then performs the SAME native floating-point
// operation under the ambient rounding mode and prints the resulting bits.
// If those bits equal the bits std::from_chars returned in the same mode,
// the observed from_chars behaviour is explained by the native FP operation
// following the ambient FPU rounding mode.
//
// This file computes a diagnostic value only. It is not the oracle.

#include <cfenv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// libc++ ClingerConsts<double> / <float> (release/20.x)
static const double POWERS_OF_TEN_D[23] = {1e0,  1e1,  1e2,  1e3,  1e4,  1e5,  1e6,
                                           1e7,  1e8,  1e9,  1e10, 1e11, 1e12, 1e13,
                                           1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20,
                                           1e21, 1e22};
static const float POWERS_OF_TEN_F[11] = {1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6,
                                          1e7, 1e8, 1e9, 1e10};
static const int32_t EXACT_POWERS_OF_TEN_D = 22, DIGITS_IN_MANTISSA_D = 15;
static const int32_t EXACT_POWERS_OF_TEN_F = 10, DIGITS_IN_MANTISSA_F = 7;
static const double MAX_EXACT_INT_D = 9007199254740991.0;
static const float MAX_EXACT_INT_F = 16777215.0f;

// Parse like libc++ __parse_fractional_decimal_constant: integer mantissa +
// integer decimal exponent, plus a 'truncated' flag.
struct Parsed {
    unsigned long long mantissa;
    int exponent;
    bool truncated;
};

static Parsed parse_like_libcxx(const char* s) {
    Parsed p{0, 0, false};
    const unsigned long long max_div_by_10 = ~0ULL / 10;
    bool after_decimal = false;
    const char* q = s;
    // libc++ strips an optional sign before the conversion; the magnitude is
    // what reaches the conversion machinery.
    if (*q == '+' || *q == '-')
        ++q;
    for (;; ++q) {
        if (*q >= '0' && *q <= '9') {
            unsigned d = (unsigned)(*q - '0');
            if (p.mantissa < max_div_by_10) {
                p.mantissa = p.mantissa * 10 + d;
                if (after_decimal)
                    --p.exponent;
            } else {
                if (d > 0)
                    p.truncated = true;
                if (!after_decimal)
                    ++p.exponent;
            }
            continue;
        }
        if (*q == '.') {
            after_decimal = true;
            continue;
        }
        break;
    }
    if (*q == 'e' || *q == 'E') {
        ++q;
        bool neg = false;
        if (*q == '+' || *q == '-') {
            neg = (*q == '-');
            ++q;
        }
        int e = 0;
        while (*q >= '0' && *q <= '9') {
            e = e * 10 + (*q - '0');
            ++q;
        }
        p.exponent += neg ? -e : e;
    }
    return p;
}

// Replicate clinger_fast_path's eligibility test and its native operation.
template <class T>
static bool clinger(const Parsed& p, unsigned long long* out_bits) {
    constexpr int32_t FRACTION_LEN = (sizeof(T) == 4) ? 23 : 52;
    constexpr int32_t EXACT_POWERS_OF_TEN =
        (sizeof(T) == 4) ? EXACT_POWERS_OF_TEN_F : EXACT_POWERS_OF_TEN_D;
    constexpr int32_t DIGITS_IN_MANTISSA =
        (sizeof(T) == 4) ? DIGITS_IN_MANTISSA_F : DIGITS_IN_MANTISSA_D;

    unsigned long long mantissa = p.mantissa;
    int32_t exp10 = p.exponent;

    if ((mantissa >> FRACTION_LEN) > 0)
        return false; // not eligible

    T float_mantissa = static_cast<T>(mantissa);
    T result = T(0);

    if (exp10 > 0) {
        if (exp10 > EXACT_POWERS_OF_TEN + DIGITS_IN_MANTISSA)
            return false;
        if (exp10 > EXACT_POWERS_OF_TEN) {
            float_mantissa = float_mantissa *
                              (sizeof(T) == 4 ? (T)POWERS_OF_TEN_F[exp10 - EXACT_POWERS_OF_TEN]
                                              : (T)POWERS_OF_TEN_D[exp10 - EXACT_POWERS_OF_TEN]);
            exp10 = EXACT_POWERS_OF_TEN;
        }
        if (sizeof(T) == 4) {
            if (float_mantissa > MAX_EXACT_INT_F)
                return false;
            result = float_mantissa * POWERS_OF_TEN_F[exp10];
        } else {
            if (float_mantissa > MAX_EXACT_INT_D)
                return false;
            result = float_mantissa * POWERS_OF_TEN_D[exp10];
        }
    } else if (exp10 < 0) {
        if (-exp10 > EXACT_POWERS_OF_TEN)
            return false;
        if (sizeof(T) == 4)
            result = float_mantissa / POWERS_OF_TEN_F[-exp10];
        else
            result = float_mantissa / POWERS_OF_TEN_D[-exp10];
    } else {
        result = float_mantissa;
    }

    if (sizeof(T) == 4) {
        unsigned int u;
        std::memcpy(&u, &result, sizeof(u));
        *out_bits = u;
    } else {
        unsigned long long u;
        std::memcpy(&u, &result, sizeof(u));
        *out_bits = u;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <f|d> <mode 0..3> <input>\n", argv[0]);
        return 2;
    }
    char typec = argv[1][0];
    int mode = std::atoi(argv[2]);
    const char* s = argv[3];

    static const int modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    std::fesetround(modes[mode]);

    Parsed p = parse_like_libcxx(s);
    unsigned long long bits = 0;
    bool eligible = (typec == 'f') ? clinger<float>(p, &bits) : clinger<double>(p, &bits);

    // libc++ applies the sign to the magnitude result (see
    // __calculate_result in libcxx/src/include/from_chars_floating_point.h).
    // Only meaningful when the Clinger path was actually taken; for an
    // ineligible input this reproducer models nothing.
    if (eligible && s[0] == '-') {
        if (typec == 'f')
            bits |= 0x80000000ull;
        else
            bits |= 0x8000000000000000ull;
    }

    std::printf("{\"clinger_eligible\":%s,\"clinger_bits\":%llu,\"parsed_mantissa\":%llu,"
                "\"parsed_exponent\":%d,\"truncated\":%s}\n",
                eligible ? "true" : "false", bits, p.mantissa, p.exponent,
                p.truncated ? "true" : "false");
    return 0;
}
