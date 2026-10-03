<!-- Preserved from .scratch/ (gitignored, not durable).
     Supports knowledge/reports/rpt-2026-0017.yaml.
     Original filename: formal_rebuild_assessment.md -->

# Formalization Assessment — What a REAL §7.2 Composition Requires

**Role:** formalization-agent (read-only feasibility assessment)
**Date:** 2026-10-03
**Subject:** FORMAL-205 (`fnd-2026-0006`) — is the "combined LENGTH + MODULUS" claim repairable by writing Lean, and what would it cost?
**Method:** READ-ONLY. No `.lean` file edited. No `lake build`. No Mathlib download. No git commit.
**Evidence used:** the three committed sources under `formal/Formal/`, the three build logs,
the retained `.lake/build/lib/lean/Formal/*.olean` + `*.trace` proof-term sidecars, the Lean
4.22.0 toolchain itself (probed via `lean --stdin` against **core only**, zero downloads),
`localdocs/refs/fips203.pdf` PDF pp.45–46, and the existing YAML artifacts.

**Bottom line:** the gap is real and it is *wider* than the audit found — but the connective
tissue is cheap. A genuine composition is roughly **15 declarations in one new file, zero new
Mathlib imports, about a day**, not a week. However I recommend **re-scoping FORMAL-205 rather
than retro-fitting it**, because the mission's acceptance criteria specified a *dependent type*
and were never met, and because rewriting a `status: verified` mission's artifacts in place would
launder the original overclaim.

---

## 1. Current state: what the Lean code actually models

### 1.1 There is no byte-array type. There is no length-indexed type. Everything is `Nat → Nat`.

The FIPS 203 names `ByteEncode₁₂` / `ByteDecode₁₂` **do not exist in the Lean corpus** — they
appear only in prose. The Lean names are `encByte` / `dec`. Every one of them has the identical
shape `(Nat → Nat) → …`:

```lean
39:  def bit (x j : Nat) : Nat := (x / 2 ^ j) % 2

76:  def wsum (G : Nat → Nat) (N : Nat) : Nat := ∑ t ∈ Finset.range N, G t * 2 ^ t

259: def gbit (B : Nat → Nat) (p : Nat) : Nat := bit (B (p / 8)) (p % 8)

275: def seg (B : Nat → Nat) (i : Nat) : Nat :=
276:   wsum (fun j => gbit B (12 * i + j)) 12

285: def dec (B : Nat → Nat) (i : Nat) : Nat := seg B i % 3329

288: def ebit (F : Nat → Nat) (p : Nat) : Nat := bit (F (p / 12)) (p % 12)

295: def encByte (F : Nat → Nat) (y : Nat) : Nat :=
296:   wsum (fun t => ebit F (8 * y + t)) 8
```
(`formal/Formal/ByteEncode.lean`)

**Real types:** `bit : Nat → Nat → Nat`; `wsum : (Nat → Nat) → Nat → Nat`;
`gbit, seg, dec : (Nat → Nat) → Nat → Nat`; `ebit, encByte : (Nat → Nat) → Nat → Nat`.
The "byte array" is an infinite total function of byte value by index. It has no length, no
bound, and no way to be ill-formed.

Corroborating grep over `formal/**/*.lean` for `Fin|Array|Vector|List|Fintype`: 11 hits, **every
one inside a comment or docstring** — `ValidKey.lean:11, 44, 74`, `LengthCheck.lean:21`, plus
`Finset.*` in `ByteEncode.lean`. **Zero occurrences of `Fin` in any type signature.** So there is
no byte-array/vector model at all, and no length-indexed type anywhere in the corpus.

One dependency note worth recording: `wsum` (ByteEncode.lean:76) is defined with **`Finset`**,
which is Mathlib's, reached via `import Mathlib.Tactic` (ByteEncode.lean:32). I confirmed by
probing the core toolchain that `Finset` does *not* exist in Lean core — `import
Init.Data.Nat.Lemmas` alone yields `unknown namespace 'Finset'`. Consequence: **ByteEncode.lean
is not core-only and cannot be made so** without rewriting `wsum`. Any new file that imports
`Formal.ByteEncode` inherits Mathlib whether it wants it or not. That is fine (CI already pays
for it) but it forecloses any "strip Mathlib from the corpus" idea.

### 1.2 The LENGTH "machinery" is two `Nat`s compared by `=`

```lean
56: inductive MLKEMParam where
57:   | k2 : MLKEMParam
58:   | k3 : MLKEMParam
59:   | k4 : MLKEMParam
60: deriving DecidableEq, Repr

64: def canonicalLength : MLKEMParam → Nat
65:   | .k2 => 384 * 2 + 32
66:   | .k3 => 384 * 3 + 32
67:   | .k4 => 384 * 4 + 32

71: theorem canonicalLength_k2 : canonicalLength .k2 = 800 := rfl
73: theorem canonicalLength_k3 : canonicalLength .k3 = 1184 := rfl
75: theorem canonicalLength_k4 : canonicalLength .k4 = 1568 := rfl

152: def isCanonicalLength (p : MLKEMParam) (n : Nat) : Prop := n = canonicalLength p
```
(`formal/Formal/LengthCheck.lean`)

`isCanonicalLength` takes a bare `Nat`. It has no array argument, so it cannot check anything
about an array; it is a re-spelling of `canonicalLength p`. The only `Prop`-level length work in
the file is `cross_param_set_rejection (p q) (hne : p ≠ q) : ¬ canonicalLength p = canonicalLength q`
(L132–133) — genuinely parametric, still pure arithmetic over a 3-constructor inductive.

### 1.3 FORMAL-205, quoted in full for the three claims

```lean
47: def isValidKey (p : MLKEMParam) (B : Nat → Nat) : Prop :=
48:   B = B ∧ ∀ i, seg B i < 3329

51: theorem wsum_zero (N : Nat) : wsum (fun _ : Nat => 0) N = 0 := by …

59: theorem isValidKey_zero_k2 : isValidKey .k2 (fun _ => 0) := by …

78: theorem isValidKey_length_k2 : canonicalLength .k2 = 800 := by
79:   exact canonicalLength_k2

83: theorem isValidKey_roundtrip_k2 (B : Nat → Nat)
84:     (hB : ∀ y, B y < 256) (hSeg : ∀ i, seg B i < 3329) (y : Nat)
85:     (hy : y < canonicalLength .k2) :
86:     encByte (fun i => dec B i) y = B y := by …

92: theorem isValidKey_roundtrip_general (B : Nat → Nat)
93:     (hB : ∀ y, B y < 256) (hSeg : ∀ i, seg B i < 3329) (y : Nat) :
94:     encByte (fun i => dec B i) y = B y :=
95:   enc_dec_eq B hB hSeg y
```
(`formal/Formal/ValidKey.lean`)

Two facts that are load-bearing for the assessment:

* **`isValidKey` occurs in exactly one of the three theorems** — T1 at L59. It appears in the
  statements of neither T2 nor T3, and `p` appears nowhere except T1's `.k2`. So "the combined
  predicate" is not used by the combined theorems.
* **T3 is a verbatim re-projection of FORMAL-203's helper** (`ByteEncode.lean:363–365`):
  `enc_dec_eq (B) (hB : ∀ y, B y < 256) (hSeg : ∀ i, seg B i < 3329) (y)`. Identical binder
  list, identical hypotheses, identical conclusion. Nothing is composed.

### 1.4 The compiler's own records corroborate the audit (stronger than the logs)

`formal/.lake/build/lib/lean/Formal/ValidKey.trace` is the compiler's structured warning record
and contains, verbatim:

```
Formal/ValidKey.lean:47:16: unused variable `p`
Formal/ValidKey.lean:85:5:  unused variable `hy`
Formal/ValidKey.lean:56:14: This simp argument is unused: Nat.zero_mul
Formal/ValidKey.lean:56:28: This simp argument is unused: Nat.add_zero
```

So the *Lean front end itself*, at the pinned toolchain, certifies: `p` unused in the combined
predicate, `hy` unused in the "combined" roundtrip, and the "roundtrip" restated under a second
name. `formal/build_output_r3.log` carries the same four warnings in human-readable form, ending
`✔ [3053/3054] Built Formal / Build completed successfully.`

I also found a warning the audit did not list: `ByteEncode.lean:381:44: unused variable 'hB'`
inside `reject_on_overflow`. It is not a soundness problem — the theorem's conclusion
`∃ y, encByte (dec B) y ≠ B y` genuinely does not need the byte bound — but it means
`reject_on_overflow` is stated with a hypothesis it does not use, and any composition routed
through it must supply an `hB` it does not consume.

Residual build-tree state (measured, not built): `formal/.lake` contains **34 files / 1.15 MB**,
all of them our own `.olean`/`.ilean`/`.trace`/`ir` products. `formal/.lake/packages` does not
exist — Mathlib was deleted, exactly as `CHECKPOINT.md:262` records. All three `.olean` files
begin with the header bytes `olean4.22.0`, and each is newer than its source. `git log --follow
-- formal/Formal/ValidKey.lean` returns exactly one commit (`f083ff4`), so there is no earlier
iteration from which to recover intent.

---

## 2. The gap, stated precisely

The claim requires `ek : 𝔹^(384k+32)` and two checks. Measured against the code, **all three
prerequisites are absent, and one of them is absent from FORMAL-203 too — which the audit did
not catch.**

### (a) A length-indexed array type — ABSENT
`Fin` occurs in `formal/` only at `ValidKey.lean:11, 44, 74` and `LengthCheck.lean:21`, all
comment text. The `Fin (canonicalLength p) → Nat` type is *described* at `ValidKey.lean:44`
("a `Fin (canonicalLength p) → Nat` type would enforce the length") but never written. There is
no type in the corpus under which an 801-byte array is inadmissible.

### (b) A statement whose truth depends on the length — ABSENT
`isValidKey_length_k2 : canonicalLength .k2 = 800` (`ValidKey.lean:78`) mentions neither
`isValidKey`, nor `B`, nor `p`; its body is `exact canonicalLength_k2`. `isValidKey_roundtrip_k2`'s
`hy : y < canonicalLength .k2` (L85) is dead — compiler-proven. Delete `hy` and nothing weakens;
delete `p` from `isValidKey` and nothing changes. The LENGTH half therefore contributes **zero
bits** to the formalized content.

### (c) A modulus check over the `384k` prefix — ABSENT, and this is deeper than reported

FIPS 203 §7.2 step 2 (PDF p.45) is Eq. (7.1) `test ← ByteEncode₁₂(ByteDecode₁₂(ek[0:384k]))`,
compared against `ek[0:384k]` — **the first 384k bytes only**. FORMAL-203 proves instead:

```lean
420: theorem roundtrip_iff_canonical :
421:   ∀ (B : Nat → Nat), (∀ y, B y < 256) →
422:     ((∀ i, seg B i < 3329) ↔ (∀ y, encByte (fun i => dec B i) y = B y))
```
and its one-directional helper `enc_dec_eq` (L363–365) carries `hSeg : ∀ i, seg B i < 3329`
**with no bound on `i`**, plus a conclusion quantified over all `y : Nat`.

Both sides range over the *whole* 800-byte array, including the 32-byte seed `ρ` at bytes
`384k … 384k+31`. Those bytes are read by segments `i ≥ 256k` (segment `256k` begins at global
bit `3072k`, i.e. exactly byte `384k`). A random seed byte pair makes `seg` land in `[0,4096]`,
so `seg B i ≥ 3329` for `i = 256k` with probability ≈ `1 − 3329/4096 ≈ 19%`.

Consequence, and it matters: **Eq. (7.1) holds for a genuine encapsulation key whose seed
segments are non-canonical, and `roundtrip_iff_canonical` gives you no way to conclude that.**
For such a key the prefix condition holds but the RHS of `roundtrip_iff_canonical` fails — the
biconditional is satisfied with both sides false, so the theorem stays *true* (good: FORMAL-203
is sound), but it is **not Eq. (7.1)** and cannot be specialized to it. The audit's statement that
FORMAL-203 is "strictly stronger than the spec on the content side" is, as a claim about
*derivability of Eq. (7.1)*, backwards.

The audit's attack on FORMAL-203's *soundness* ("does it compose? NO") is right; it just did not
carry the attack into FORMAL-203 itself. So the real connective work is not "glue two theorems" —
it is **proving the prefix-restricted roundtrip that FORMAL-203 does not state.**

### (d) The index arithmetic that makes (c) possible — ABSENT

To restrict to the prefix you need, and nowhere have:

```lean
(k y s : Nat) (hy : y < 384 * k) (hs : s < 8) : (8 * y + s) / 12 < 256 * k
(k i j : Nat) (hi : i < 256 * k) (hj : j < 12) : (12 * i + j) / 8 < 384 * k
```

I machine-checked both in core Lean 4.22.0 (see §3). They are the connective tissue, and their
absence is *why* FORMAL-203 had to state the whole-array version: without the first, you cannot
show that `y < 384k` keeps you inside coefficients `i < 256k`; without the second,
`reject_on_overflow`'s offending byte index `(12*i+j)/8` cannot be shown to lie in the prefix.

### (e) Parameter `p` is unreferenced — CONFIRMED
Compiler-certified at `ValidKey.lean:47:16`. `isValidKey` is constant in `p`. A combined predicate
must have `p` *in its type*, so that `p` occurs in the checker and an `ek` for `.k3` cannot be
passed where `.k2` is expected.

**Summary of what is missing:** all five. Nothing in the corpus makes an ill-lengthed array
untypeable; nothing states the LENGTH check; nothing states Eq. (7.1) over the prefix; nothing
establishes the prefix↔coefficient index arithmetic; nothing uses `p`.

---

## 3. Smallest honest theorem that would make the claim true

Three tiers. I give the ladder because "smallest honest" is not one thing: there is a version
that makes the *word* LENGTH defensible, and a version that makes the *§7.2 Eq. (7.1)* claim
defensible. The finding claims the latter, so the latter is the target.

### Tier 0 — a real length *check* (still checks no array). 4 lemmas.

```lean
def lengthCheck (p : MLKEMParam) (n : Nat) : Bool := decide (n = canonicalLength p)

theorem lengthCheck_sound    {p n} (h : lengthCheck p n = true) : n = canonicalLength p
theorem lengthCheck_complete (p) : lengthCheck p (canonicalLength p) = true
theorem lengthCheck_rejects_offbyone_k2 : lengthCheck .k2 801  = false
theorem lengthCheck_rejects_wrong_k     : lengthCheck .k2 1568 = false
```

**Machine-checked by me, core Lean 4.22.0, zero errors.** This is what `isCanonicalLength` wants
to be. It is still not a check of any array, so on its own it does **not** make the finding true.

### Tier 1 — the length becomes a type. 3 declarations.

```lean
/-- Bounded-array erasure: bridge `Fin n → Nat` back to the total-function model. -/
def er {n : Nat} (B : Fin n → Nat) : Nat → Nat :=
  fun y => if h : y < n then B ⟨y, h⟩ else 0

theorem er_of_lt {n} {B : Fin n → Nat} {y} (hy : y < n) : er B y = B ⟨y, hy⟩
example    : (Fin (384 * 2 + 32)) = (Fin 800) := rfl
```

**Machine-checked by me, core Lean, zero errors.** `ek_type_is_800 := rfl` is the single line
where the FIPS 203 constant `384k+32` is welded to a Lean type. After it, an 801-byte array has
no type and cannot be an argument to anything.

### Tier 2 — the actual §7.2 composition. 3 declarations + the prefix lemma.

The combined predicate, with `p` *in the type* so the unused-variable warning is structurally
impossible:

```lean
/-- FIPS 203 §7.2, both halves, for parameter set p.
    The LENGTH half is not a conjunct: it is the index type of `ek`. -/
def ekValid (p : MLKEMParam) (ek : Fin (canonicalLength p) → Nat) : Prop :=
  (∀ y, ek ⟨y, _⟩ < 256) ∧ (∀ i, i < 256 * kOf p → seg (er ek) i < 3329)
```

and Eq. (7.1) over the prefix, which is what actually needs proving:

```lean
/-- §7.2 step 2, Eq (7.1): on the first 384k bytes, ByteEncode12 ∘ ByteDecode12 is the identity
    iff every 12-bit segment there is canonical.  This is the PREFIX-restricted form; the
    seed bytes (segments ≥ 256k) are deliberately outside the statement. -/
theorem s72_eq7_1_k2 (ek : Fin 800 → Nat)
    (hB   : ∀ y, ek ⟨y, _⟩ < 256)
    (hMod : ∀ i, i < 256 * 2 → seg (er ek) i < 3329)
    (y : Nat) (hy : y < 384 * 2) :
    encByte (fun i => dec (er ek) i) y = ek ⟨y, _⟩

/-- Rejection direction: a non-canonical segment inside the 384k prefix makes Eq (7.1) fail
    inside the prefix.  Reuses ByteEncode.reject_on_overflow; the index bound is what keeps
    its witness byte in the prefix. -/
theorem s72_eq7_1_reject_k2 (ek : Fin 800 → Nat)
    (hB  : ∀ y, ek ⟨y, _⟩ < 256)
    (hBad : ∃ i, i < 256 * 2 ∧ seg (er ek) i ≥ 3329) :
    ∃ y, y < 384 * 2 ∧ encByte (fun i => dec (er ek) i) y ≠ ek ⟨y, _⟩
```

`s72_eq7_1_k2` needs a new helper `enc_dec_eq_prefix`, because `enc_dec_eq` demands `hSeg` at
**every** `i : Nat` and we only have it for `i < 512`. That helper is ~15–25 lines: redo
`roundtrip_digit` (L353–355) with `gbit_byte` (L265) and a bound-restricted `dec_digit` (L322),
using the index lemma at exactly one place.

**Verified components** (core Lean 4.22.0, `lean --stdin`, zero downloads, zero errors):

| Component | Status |
|---|---|
| `er`, `er_of_lt` (Fin → total-function bridge) | machine-checked ✔ |
| `(Fin (384*2+32)) = (Fin 800)` | machine-checked ✔ |
| `lengthCheck` + 4 lemmas (Tier 0) | machine-checked ✔ |
| `(8*y+s)/12 < 256*k` for `y < 384k, s < 8` | machine-checked ✔ |
| `(12*i+j)/8 < 384*k` for `i < 256k, j < 12` | machine-checked ✔ |
| `384*k*8 = 12*(256*k)` | machine-checked ✔ |
| `s72_eq7_1_k2` / `enc_dec_eq_prefix` / `s72_eq7_1_reject_k2` (assembled) | **not machine-checked — needs Mathlib, see §6** |

**This is the smallest honest target.** Note that *deleting the tautology* `B = B` is **not** a
fix — it removes a `B = B` and leaves the predicate equal to the MODULUS half alone. The two
things that make the claim true are (i) moving the length into the type so an ill-lengthed array
is untypeable, and (ii) restating Eq. (7.1) over the `384k` prefix, which FORMAL-203 does not
provide.

---

## 4. Feasibility estimate

**Corpus scale, for calibration:** `ByteEncode.lean` 452 lines / 32 theorems / 8 defs;
`LengthCheck.lean` 201 / 18 / 2; `ValidKey.lean` 97 / 5 / 1. Total 750 lines, 55 theorems.

### New Mathlib imports required: **zero**

Every primitive the rebuild needs is Lean **core**, shipped inside the toolchain at
`%USERPROFILE%\.elan\toolchains\leanprover--lean4---v4.22.0\lib\lean\Init\Data\Fin\`
(`Basic.olean`, `Lemmas.olean` present — I listed it):

* `Fin`, `Fin.cast`, `Fin.ext`, `Fin.val_mk` — core. (`Fin.val_cast` does **not** exist; I
  probed for it and it is absent. Use `rfl` on `.val`, or `Fin.ext`.)
* `Nat.div_lt_iff_lt_mul`, `Nat.mul_div_left`, `Nat.mod_lt`, `Nat.lt_or_ge` — core.
* `omega`, `simp`, `rfl`, `decide`, `rintro`, `by_contra` — core.
* `Init.Data.Fin.Basic`, `Init.Data.Fin.Lemmas`, `Init.Data.Nat.Lemmas`,
  `Init.Data.Nat.Div.Basic` — core, no Mathlib.

`ring` is **not** core (I hit `unknown tactic` for `ring` in a core-only probe) — but none of the
three index lemmas need it; each closes with `Nat.div_lt_iff_lt_mul` + `omega`, which I verified.

The new file will of course `import Formal.ByteEncode`, which drags in `Mathlib.Tactic`
transitively via `wsum`'s `Finset`. That is unavoidable and costs nothing extra: CI already
builds that dependency. **No new package, no new import line in `lakefile.lean`, no manifest
change.**

### New declarations: ~15, ~80–100 lines, one new file (`Formal/EkCheck.lean`)

| Group | Count | Lines | Risk |
|---|---|---|---|
| `er`, `er_of_lt` | 2 | 12 | none — verified |
| index bounds ×2 + `384k*8 = 12*(256k)` | 3 | 10 | none — verified |
| `ek_type_is_800` | 1 | 1 | none — verified |
| `lengthCheck` + 4 lemmas (Tier 0) | 5 | 20 | none — verified |
| `ekValid` + `ekValid_of_ekValid` style projections | 2 | 10 | trivial |
| zero-array non-emptiness at `Fin 800` | 1 | 10 | low (`wsum_zero` exists at L51) |
| **`enc_dec_eq_prefix`** (prefix-restricted roundtrip) | 1 | 15–25 | **medium** |
| `s72_eq7_1_k2` + `s72_eq7_1_reject_k2` | 2 | 12 | low (one is `exact`) |

### Time: **about a day, not a week**

Reasoning, not vibes:

* The MODULUS content is **already proved** by FORMAL-203 and reused verbatim. Zero re-derivation
  of the hard bit arithmetic — the entire 452-line `ByteEncode.lean` is untouched.
* Every arithmetic obligation reduces to linear `Nat` reasoning, and **I machine-checked the three
  non-trivial ones in core Lean before writing this estimate.** The unknown is not "is this
  provable" but "does `omega` close it in one pass", which is a minutes-long loop.
* The iteration loop is fast: `lean --stdin` against the pinned toolchain ran in **0.7–0.8 s**
  with no Mathlib at all. Core-only scratch work for the bridge/index/checker layer is
  genuinely minutes-per-iteration.
* The only genuine cost is the `enc_dec_eq_prefix` lemma, and it is a *statement-design* problem
  (where exactly the `i < 256k` / `y < 384k` bounds attach), not a lemma-grinding problem.

**Confidence and the honest risk.** I rate "the whole rebuild is ≤ 2 days" at high confidence,
and "it is ≤ 1 day" at moderate. The specific risk is **vacuity-by-hypothesis-hoisting**: if
`s72_eq7_1_k2` is stated with `hMod` as a hypothesis, it is again a restatement — which is
precisely the FORMAL-205 failure mode recurring one level down. The mitigation is to make the
pairing explicit: prove `s72_eq7_1_k2` **and** `s72_eq7_1_reject_k2` together, so the theorem is
a biconditional over the prefix and cannot be satisfied by a predicate nobody can inhabit. This
must be stated in the finding, or the same audit will land again.

Second risk, lower: `mkOf p : MLKEMParam → Nat` does not exist yet (it would be a new 4-line
def over the three constructors). If one wants the whole predicate parametric in `p`, that is
where the parametric proofs get fiddly — `kOf` injectivity substitutes for `canonicalLength`'s.

### CI cost

`.github/workflows/formal.yml` triggers on `paths: [formal/**]` and runs
`lake update && lake exe cache get! && lake build` on `ubuntu-latest`, then greps
`! grep -q "declaration uses 'sorry'"` and `! grep -qi "error"`. **No workflow change needed** —
a new file under `formal/Formal/` triggers the existing job. The build graph is 3054 targets and
the log shows `Replayed` for unchanged modules, so the incremental cost of one added file is
seconds, not minutes. This is a *lightweight*-class workload per the charter's compute-routing
table, but since `.lake/packages` is deleted locally, **it must run in CI, not here** — which
matches the hard rule exactly.

---

## 5. Recommendation: **re-scope, don't retro-fit** — and schedule the rebuild separately

### 5.1 Re-scope FORMAL-205 now

Correct `fnd-2026-0006` to say exactly what the file proves: a predicate capturing the **MODULUS
half only**; T2 a restatement of `canonicalLength_k2`; T3 a restatement of `enc_dec_eq`; **the
§7.2 LENGTH/type check formalized nowhere**; and additionally — a point the audit missed —
**FORMAL-203's whole-array statement does not specialize to Eq. (7.1), so the MODULUS half is
also only half-formalized**, in that it ranges over the seed region where the spec does not.
Retitle away from "combined LENGTH+MODULUS".

### 5.2 Do *not* rewrite `ValidKey.lean` and re-claim it as "the same finding, corrected"

Three reasons, in order of weight:

1. **`msn-2026-0007` is `status: verified` with a `terminal_reason` that contains the false claim
   verbatim** (`missions/completed/msn-2026-0007.yaml:89`: "the complete s7.2 encapsulation-key
   check is now machine-checked end-to-end"). That sentence is not prose around a result — it is
   the stated justification for a terminal transition. Rewriting the artifacts in place, without
   re-opening the mission and without a fresh independent adversarial review, is the "never
   rewrite history to look cleaner" failure wearing a technical costume.

2. **The mission asked for a different artifact than the one delivered.**
   `msn-2026-0007.objective` says: "Define a dependent type `ValidKey .k2`". The delivered file
   defines a *predicate* with a vacuous conjunct, and the finding's own `limitations` concedes
   the subset-type conversion is "a follow-up (FORMAL-208 candidate)". So the acceptance criterion
   — a dependent type — was never met, and the acceptance was recorded as satisfied. This is a
   *verification-process* defect, not a Lean defect. No amount of new Lean repairs it; only
   re-opening the mission and re-verifying does.

3. **`prf-2026-0003.yaml:6` carries the same false claim** and is `status: verified,
   epistemic_status: verified_conclusion`. `fnd-2026-0006.yaml` has already been corrected
   (2026-10-03); the proof artifact and the mission terminal_reason have not. The correction is
   currently **half-applied**, which is worse than either end state: the graph now contains a
   disputed finding pointing at a verified proof that still asserts the refuted claim.

### 5.3 Then do schedule the rebuild — as a NEW mission, not as a rescue of FORMAL-205

The sketch in §3 is cheap (≈15 declarations, ≈1 day, zero new imports, no CI change), so leaving
the corpus permanently at "the §7.2 LENGTH check is not formalized" is the wrong call. But it
must be a new mission with its own experiment/observation/reproducer/review chain, its own
adversarial critic, and the bidirectional statement of §3. **FORMAL-208 is already reserved for
the predicate→subset-type conversion**, so this is a different objective and does not collide;
`frontier.continuation.evaluate_followup` should be the gate.

### 5.4 Immediate records-hygiene, independent of the above

Grep for `machine-checked end-to-end` across the repo returns the falsified phrase in **three
durable locations**, none yet corrected:

* `knowledge/proofs/prf-2026-0003.yaml:6`
* `missions/completed/msn-2026-0007.yaml:89`
* `missions/completed/msn-2026-0006.yaml:6` (FORMAL-204's summary — different sentence, same
  overclaim flavour, and `fnd-2026-0004` is already `disputed`)

These should be corrected as records hygiene **now**, under whatever mission is open, because the
correct disposition for a false headline is withdrawal, not leaving it readable.

Two smaller items I noticed that are independent of the main call:

* `fnd-2026-0004`/`fnd-2026-0006`'s `reproducer:` field says
  `cd C:\Users\Dhane\frontier\formal; lake build`. After the packages deletion, that reproducer
  **re-downloads ~5.5 GB**, which the charter's hard rule forbids on this machine. The reproducer
  should be rewritten as `gh workflow run formal-verify` (or push to `main`).
* `formal/.gitignore` shows `!formal/build_output*.log`, and `git ls-files` confirms the three logs
  are tracked — so the `unused variable` warnings *are* durable evidence, which is good. Keep them.

---

## 6. What I could not determine

* **COULD-NOT-DETERMINE: whether the assembled Tier-2 theorem compiles.** It imports
  `Formal.ByteEncode` → `import Mathlib.Tactic` → Mathlib oleans, and `formal/.lake/packages`
  does not exist (measured: 34 files / 1.15 MB remain, all our own products; `CHECKPOINT.md:262`
  records the 5,488 MB deletion). Verifying it would require the forbidden download. I verified
  every **non-Mathlib** component separately with `lean --stdin` against core only, and I
  enumerate exactly which those are in the table in §3 — but `enc_dec_eq_prefix`,
  `s72_eq7_1_k2` and `s72_eq7_1_reject_k2` are **sketched, not machine-checked**. They are
  theorem *statements* whose feasibility I argue from the verified primitives, not proofs I have
  seen accept.
* **COULD-NOT-DETERMINE: the `#print axioms` inventory.** Not committed anywhere in `knowledge/`.
  The `{propext, Classical.choice, Quot.sound}` claim for FORMAL-205 rests solely on a
  synthesizer's restatement. I did not run it (requires the build).
* **COULD-NOT-DETERMINE: current CI wall-clock and today's greenness.** I took
  run `35469449259` / `BUILD_EXIT=0` from the audit report; I did not re-query GitHub Actions.
* **COULD-NOT-DETERMINE: whether `lake update` still resolves Mathlib to rev
  `79e94a093aff4a60fb1b1f92d9681e407124c2ca` today.** `formal/lake-manifest.json` is gitignored
  and CI resolves from the `@ "v4.22.0"` tag pin in `lakefile.lean`. Tags are normally immutable,
  so this is very likely fine, but I did not verify it.
* **Undetermined and a judgement call, not a fact: which array model the repo should adopt.**
  The `Fin (canonicalLength p) → Nat` route is the only one under which an ill-lengthed array is
  *impossible*, which is why I recommend it. A `Nat → Nat` plus an explicit bound
  (`isValidKey (p) (n) (B)` with `n = canonicalLength p` as a hypothesis) is legitimate and
  smaller, but it is the same *shape* of argument the audit just rejected: the length appears as a
  proposition someone can supply trivially rather than as something the type system enforces. I do
  not know which the repo prefers, and the audit's own complaint makes the `Fin` route the safer
  default.

### What I verified, for the record

Read: all three `.lean` sources in full; `ValidKey.trace`; `formal.yml`; `lakefile.lean`;
`lean-toolchain`; `lake-manifest.json`; all three build logs; `fnd-2026-0003/0004/0006`;
`prf-2026-0003`; `msn-2026-0007`; FIPS 203 PDF pp.45–46 (§7.2 verbatim); `CHECKPOINT.md:259–283`;
`roles/README.md`. Measured: `formal/.lake` file count/size; `.olean` header bytes and mtimes;
git status; `git log --follow`. Ran: `lean --stdin` probes against the pinned toolchain, core
imports only, in `%TEMP%`, deleted afterwards — **zero network, zero Mathlib, zero build trees,
zero repo writes**. `git status` shows no new modifications from this session; the pre-existing
dirty files listed there were already modified before I started and I touched none of them.
