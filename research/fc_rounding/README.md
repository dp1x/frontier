# Ambient floating-point rounding-mode leakage in `std::from_chars`

Bounded empirical investigation: does a caller's active floating-point
rounding mode change the output bits of `std::from_chars` for finite, in-range,
non-tie inputs?

## Result in one paragraph

For **libc++ 20.1.8** (clang++ 20, `-stdlib=libc++`) the answer is **yes**, for
the decimal conversion path. For **GCC 13/14 + libstdc++** and **MSVC STL
14.51.36231** the answer is **no**: the output bits are identical under
`FE_TONEAREST`, `FE_DOWNWARD`, `FE_UPWARD` and `FE_TOWARDZERO`, and identical to
the exact-rational oracle. The libc++ behaviour is caused by the **Clinger
fast path** in `libc/src/__support/str_to_float.h`, which performs the
decimal-to-binary step as a *native* floating-point multiply or divide; that
operation follows the ambient FPU rounding mode, so the result is the value
correctly rounded *toward the ambient mode* rather than the round-to-nearest
value that `[charconv.from.chars]` requires. Rebuilding libc++ with
`LIBC_COPT_STRTOFLOAT_DISABLE_CLINGER_FAST_PATH` removes the mode-dependence
entirely, which is a direct causal test.

## Scope

* Destination types: `float` (binary32) and `double` (binary64) only.
* Inputs: finite, in range, and **not** exact ties, so a unique nearest
  representable value exists.
* Modes: `FE_TONEAREST`, `FE_DOWNWARD`, `FE_UPWARD`, `FE_TOWARDZERO`.
* Out of scope: overflow, underflow, NaN/Inf, malformed input, `long double`,
  non-IEC formats, and any security or exploitability claim.

## Files

| File | Purpose |
|---|---|
| `oracle.py` | Exact-rational oracle. Decimal/hex text -> exact `Fraction`; nearest representable value and raw bits; tie detection; uniqueness distances. |
| `crosscheck.py` | Independent re-derivation of expected bits by binary search over significands (different algorithm from `oracle.py`). |
| `crosscheck2.py` | Third independent derivation: from-scratch parsers plus 80-digit `decimal.Decimal` rounding. |
| `uniqueness.py` | Proves each expected value is *strictly* nearer than both representable neighbours, using an independent bit-pattern decoder. |
| `harness.cpp` | Runtime harness. Reads input string and mode from `argv` at runtime; `fesetround`; `fegetround` before and after; `std::from_chars`; raw bit serialisation; two liveness controls. |
| `runner.py` | One fresh subprocess per (vector, mode); writes JSONL. |
| `clinger_repro.cpp` | Mechanism reproducer: replays the upstream Clinger arithmetic (native FP multiply/divide) under the ambient mode. |
| `clinger_runner.py` | Runs the mechanism reproducer over the corpus. |
| `vectors.json` | 23 primary + control vectors with exact rationals and expected bits. |
| `vectors_discriminator.json` | 4 path-discriminator vectors (2 defeat the Clinger path, 2 are Clinger-eligible controls). |
| `results/` | Raw JSONL output for every target actually executed. |

## Expected bits are never taken from a tested implementation

The expected value for every vector is computed from the input's exact
rational value. `oracle.py` uses integer arithmetic and `fractions.Fraction`
only. It does not call `std::from_chars`, `strtod`, `strtof`, Python `float()`,
or any standard library conversion. Two further independent implementations
(`crosscheck.py`, `crosscheck2.py`) reproduce every expected bit, and
`uniqueness.py` independently proves each is strictly nearest.

## Harness guarantees

* The input string and the rounding mode are runtime `argv` values, so no
  conversion can be constant-folded.
* Each (vector, mode) case runs in a **fresh process**, so no state leaks
  between cases.
* The requested mode is set with `fesetround`; its return status and the mode
  read back by `fegetround` **immediately before** the `from_chars` call are
  recorded, as is the mode read back immediately after.
* Two positive controls run in the same process while the ambient mode is
  still active: a raw FPU liveness probe (`1.0 + 1e-20`) and a `strtod`
  probe. Both vary with the mode in the same process, proving the ambient
  rounding mode was genuinely live at the point of the `from_chars` call.
  The `strtod` control is diagnostic only and is never used as an expected
  value.
* Compilation: `-std=c++17 -O0 -fno-fast-math -frounding-math`, with
  `#pragma STDC FENV_ACCESS ON` under Clang. No fast-math, no LTO.

## Targets actually executed

| Target | Identity | Where |
|---|---|---|
| GCC / libstdc++ | `g++` on `ubuntu-latest` | GitHub Actions |
| Clang / libc++ 20.1.8 | `clang++-20 -stdlib=libc++` | GitHub Actions |
| Clang / libc++ 20.1.8, Clinger disabled | rebuilt from `llvmorg-20.1.8` with `-DLIBC_COPT_STRTOFLOAT_DISABLE_CLINGER_FAST_PATH` | GitHub Actions |
| MSVC STL | 14.51.36231, `cl` 19.51.36248, Windows 11 ARM64 | local, `clang++` front end with MSVC STL |

Compiler front end and standard-library identity are recorded separately.
`clang++` with MSVC's STL is **not** a third standard library; it is the MSVC
STL.

## Reproducing

```bash
# GCC / libstdc++
g++ -std=c++17 -O0 -fno-fast-math -frounding-math harness.cpp -o harness_gcc
python3 runner.py ./harness_gcc vectors.json,vectors_discriminator.json results_gcc.jsonl "GCC"

# Clang / libc++ 20
clang++-20 -std=c++17 -stdlib=libc++ -O0 -fno-fast-math -frounding-math harness.cpp -o harness_clang
python3 runner.py ./harness_clang vectors.json,vectors_discriminator.json results_clang.jsonl "libc++"

# Oracle self-checks and independent re-derivations
python3 oracle.py
python3 crosscheck.py
python3 crosscheck2.py
python3 uniqueness.py
```

The full GitHub Actions matrix is in `.github/workflows/fc-rounding.yml`.

## Claim boundaries

* The observed behaviour is a property of **libc++ 20.1.8** on this platform,
  in the decimal conversion path. It is not a claim about all libc++ versions.
* The evidence shows the result is *not* round-to-nearest under a non-default
  ambient mode. Whether that constitutes a conformance defect depends on
  resolving the conflicting wording in `[charconv.from.chars]`, which this
  experiment does not attempt.
* No security or exploitability claim is made.
