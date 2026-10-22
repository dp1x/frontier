# Ambient floating-point rounding-mode leakage in `std::from_chars`

Bounded empirical investigation: does a caller's active floating-point
rounding mode change the output bits of `std::from_chars` for finite, in-range,
non-tie inputs?

## Result in one paragraph

For **libc++ 20.1.8** (clang++ 20, `-stdlib=libc++`) the answer is **yes**, on
the decimal conversion path. For **GCC 13/14 + libstdc++** and **MSVC STL
14.51.36231**, over the tested corpus, the answer is **no**: the output bits are identical under
`FE_TONEAREST`, `FE_DOWNWARD`, `FE_UPWARD` and `FE_TOWARDZERO`, and identical
to the exact-rational oracle.

The libc++ behaviour is caused by the **Clinger fast path** in
`libc/src/__support/str_to_float.h`, which performs the decimal-to-binary step
as a *native* floating-point multiply or divide. That operation follows the
ambient FPU rounding mode, so the result is the **magnitude** rounded in the
ambient direction and then negated, rather than the round-to-nearest value
that one reading of `[charconv.from.chars]` (round_to_nearest) calls for,
under a non-default ambient mode. Rebuilding libc++ with
`LIBC_COPT_STRTOFLOAT_DISABLE_CLINGER_FAST_PATH` removes the mode-dependence
entirely, which is a direct causal test.

### The exact characterisation

Across all 104 (Clinger-eligible vector, mode) cells, the libc++ result is
**exactly** the value obtained by rounding the input's *magnitude* under the
ambient rounding mode and then applying the sign — 104 of 104, with no
exceptions. For positive inputs this coincides with "correctly rounded toward
the ambient mode". For **negative** inputs it does not: libc++ converts the
magnitude and negates at the end, so the result rounds *away from zero*
relative to the signed value. Both behaviours are present in the committed
records (`N01`–`N04` are negative Clinger-eligible inputs).

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
| `vectors.json` | 23 primary and control vectors with exact rationals and expected bits. |
| `vectors_discriminator.json` | 4 path-discriminator vectors (2 defeat the Clinger path, 2 are Clinger-eligible controls). |
| `vectors_extra.json` | 8 vectors added after independent review: 4 negative Clinger-eligible, 3 exercising the two-multiply sub-branch, 1 de-duplicated Clinger-eligible control. |
| `results/` | Raw JSONL output for every target actually executed. |

All three verifier scripts read their vector files relative to their own
location, so they run from a fresh clone. All three cover all 34 vectors.

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
  probe. The `strtod` probe varies across all four modes on all four targets,
  which is what establishes that the ambient rounding mode was genuinely live
  at the point of the `from_chars` call. The FPU probe distinguishes
  `FE_UPWARD` from the other three; it does not distinguish
  `FE_DOWNWARD` from `FE_TOWARDZERO` on its own. The `strtod` control is
  diagnostic only and is never used as an expected value.
* Compilation: `-std=c++17 -O0 -fno-fast-math -frounding-math`, with
  `#pragma STDC FENV_ACCESS ON` under Clang. No fast-math, no LTO.

## Targets actually executed

| Target | Identity | Where |
|---|---|---|
| GCC / libstdc++ | `g++` on `ubuntu-latest` | GitHub Actions |
| Clang / libc++ 20.1.8 | `clang++-20 -stdlib=libc++` (apt.llvm.org `llvmorg-20.1.8` packages) | GitHub Actions |
| Clang / libc++ 20.1.8, Clinger disabled | rebuilt from the `llvmorg-20.1.8` tag with `-DLIBC_COPT_STRTOFLOAT_DISABLE_CLINGER_FAST_PATH` | GitHub Actions |
| MSVC STL | 14.51.36231, `cl` 19.51.36248, Windows 11 ARM64 | local, `clang++` front end with MSVC STL headers |

Compiler front end and standard-library identity are recorded separately.
`clang++` with MSVC's STL is **not** a third standard library; it is the MSVC
STL. The recorded `target_label` in each JSONL file carries the identity that
was actually used for that run.

## Reproducing

```bash
# GCC / libstdc++
g++ -std=c++17 -O0 -fno-fast-math -frounding-math harness.cpp -o harness_gcc
python3 runner.py ./harness_gcc vectors.json,vectors_discriminator.json,vectors_extra.json \
        results_gcc.jsonl "GCC/libstdc++" "-std=c++17 -O0 -fno-fast-math -frounding-math"

# Clang / libc++ 20
clang++-20 -std=c++17 -stdlib=libc++ -O0 -fno-fast-math -frounding-math harness.cpp -o harness_clang
python3 runner.py ./harness_clang vectors.json,vectors_discriminator.json,vectors_extra.json \
        results_clang.jsonl "Clang/libc++" "-std=c++17 -stdlib=libc++ -O0 -fno-fast-math -frounding-math"

# Oracle self-checks and independent re-derivations
python3 oracle.py
python3 crosscheck.py
python3 crosscheck2.py
python3 uniqueness.py
```

The full GitHub Actions matrix is in `.github/workflows/fc-rounding.yml`. The
no-Clinger job also asserts that the ablation define actually took effect: it
reconstructs the build's own compile command for the translation unit that
instantiates the floating-point `from_chars`, preprocesses it with and without
the define, and requires the `clinger_fast_path` **call site** to be present
without the define and absent with it.

## Claim boundaries

* The observed behaviour is a property of **libc++ 20.1.8** on this platform,
  in the decimal conversion path. It is not a claim about all libc++ versions.
* The evidence shows the result is *not* round-to-nearest under a non-default
  ambient mode. Whether that constitutes a conformance defect depends on
  resolving the conflicting wording in `[charconv.from.chars]`, which this
  experiment does not attempt.
* No security or exploitability claim is made.
