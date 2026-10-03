<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_formal_3_4_6.md -->

# Adversarial Audit — FORMAL-203 / FORMAL-204 / FORMAL-205

**Auditor role:** adversarial-critic
**Date:** 2026-10-03
**Targets:** `fnd-2026-0003` (FORMAL-203), `fnd-2026-0004` (FORMAL-204), `fnd-2026-0006` (FORMAL-205)
**Method:** read-only. No repo file edited, no commit, no `lake build`, no Mathlib download.
**Ground truth used:** the committed Lean sources under `C:\Users\Dhane\frontier\formal\Formal\`,
the kernel-accepted `.olean` proof terms, the three build logs, the CI job log of
GitHub Actions run `35469449259`, and `localdocs/refs/fips203.pdf`.

---

## 0. Summary of verdicts

| Finding | Kernel check | Theorem statements match prose? | Vacuity / weakening | Verdict |
|---|---|---|---|---|
| `fnd-2026-0003` (FORMAL-203) | **VERIFIED** | T1, T2 yes. **T3 `minimalCounterexample` over-claimed** | No circularity; hypothesis `∀ y, B y < 256` is *not* sufficient for FIPS 203 Eq. (7.1) | **SAFE TO DISCLOSE, CORRECTION NEEDED** (one scope claim is false) |
| `fnd-2026-0004` (FORMAL-204) | **VERIFIED** | Yes | **Severely weakened.** T1 is `rfl`; T2/T3 are ground-`Nat` arithmetic and do not model a byte array at all | **CORRECTION NEEDED** — prose overstates what is formalized; title/status misleading |
| `fnd-2026-0006` (FORMAL-205) | **VERIFIED** | **T2 does not match prose**; T3 does not use `isValidKey` | **T2 is circular**: `isValidKey_length_k2` has no dependence on `isValidKey`; T3 does not compose | **CORRECTION NEEDED** — central claim "combined LENGTH+MODULUS check is now machine-checked end-to-end" is **FALSE as stated** |

**Bottom line:** all three proofs are sound (no `sorry`, no `axiom`, no `native_decide`, kernel-accepted).
The problems are **not** soundness problems. They are **claim-scope** problems: the prose asserts
more than the theorem statements say. Two of the three findings are safe to disclose *after* the
statement text is corrected; FORMAL-205 is **not** safe to disclose as written, because its
headline claim is contradicted by its own source file.

---

## 1. Exact theorem statements (quoted verbatim, with file:line)

### 1.1 FORMAL-203 — `formal/Formal/ByteEncode.lean`

Supporting model definitions:

```lean
39: def bit (x j : Nat) : Nat := (x / 2 ^ j) % 2

259: def gbit (B : Nat → Nat) (p : Nat) : Nat := bit (B (p / 8)) (p % 8)

275: def seg (B : Nat → Nat) (i : Nat) : Nat :=
276:   wsum (fun j => gbit B (12 * i + j)) 12

285: def dec (B : Nat → Nat) (i : Nat) : Nat := seg B i % 3329

288: def ebit (F : Nat → Nat) (p : Nat) : Nat := bit (F (p / 12)) (p % 12)

295: def encByte (F : Nat → Nat) (y : Nat) : Nat :=
296:   wsum (fun t => ebit F (8 * y + t)) 8
```

The three claimed top-level theorems:

```lean
332: theorem canonicalRoundtrip :
333:     ∀ (F : Nat → Nat), (∀ i, F i < 3329) → ∀ i,
334:       dec (fun y => encByte F y) i = F i := by
```

```lean
420: theorem roundtrip_iff_canonical :
421:     ∀ (B : Nat → Nat), (∀ y, B y < 256) →
422:       ((∀ i, seg B i < 3329) ↔ (∀ y, encByte (fun i => dec B i) y = B y)) := by
```

```lean
436: def B0 : Nat → Nat := fun y => if y = 0 then 1 else if y = 1 then 13 else 0

440: theorem minimalCounterexample :
441:     B0 0 = 1 ∧ B0 1 = 13
442:       ∧ dec B0 0 = 0
443:       ∧ encByte (fun i => dec B0 i) 0 = 0 ∧ (0 : Nat) ≠ 1
444:       ∧ encByte (fun i => dec B0 i) 1 = 0 ∧ (0 : Nat) ≠ 13 := by
```

The contrapositive-direction helper that carries the real content of T2:

```lean
381: theorem reject_on_overflow (B : Nat → Nat) (hB : ∀ y, B y < 256)
382:     (h : ∃ i, seg B i ≥ 3329) : ∃ y, encByte (fun i => dec B i) y ≠ B y := by
```

### 1.2 FORMAL-204 — `formal/Formal/LengthCheck.lean`

```lean
56: inductive MLKEMParam where
57:   | k2 : MLKEMParam
58:   | k3 : MLKEMParam
59:   | k4 : MLKEMParam

64: def canonicalLength : MLKEMParam → Nat
65:   | .k2 => 384 * 2 + 32
66:   | .k3 => 384 * 3 + 32
67:   | .k4 => 384 * 4 + 32

71: theorem canonicalLength_k2 : canonicalLength .k2 = 800 := rfl
73: theorem canonicalLength_k3 : canonicalLength .k3 = 1184 := rfl
75: theorem canonicalLength_k4 : canonicalLength .k4 = 1568 := rfl

80: theorem not_canonicalLength_offbyone_k2 : ¬ 801 = canonicalLength .k2 := by
86: theorem not_canonicalLength_offbyone_k3 : ¬ 1185 = canonicalLength .k3 := by
92: theorem not_canonicalLength_offbyone_k4 : ¬ 1569 = canonicalLength .k4 := by

99: theorem canonicalLength_plus_one_neq (p : MLKEMParam) :
100:    ¬ canonicalLength p + 1 = canonicalLength p := by

108: theorem canonicalLength_distinct :
109:     canonicalLength .k2 ≠ canonicalLength .k3 ∧
110:     canonicalLength .k2 ≠ canonicalLength .k4 ∧
111:     canonicalLength .k3 ≠ canonicalLength .k4 := by

119: theorem not_canonicalLength_wrong_k_2to4 : ¬ 1568 = canonicalLength .k2 := by
125: theorem not_canonicalLength_wrong_k_4to2 : ¬ 800 = canonicalLength .k4 := by

132: theorem cross_param_set_rejection (p q : MLKEMParam) (hne : p ≠ q) :
133:    ¬ canonicalLength p = canonicalLength q := by

152: def isCanonicalLength (p : MLKEMParam) (n : Nat) : Prop := n = canonicalLength p

155: theorem isCanonicalLength_canonical (p : MLKEMParam) : isCanonicalLength p (canonicalLength p) := rfl
159/165/171/177/183: theorem isCanonicalLength_rejects_{offbyone_k2, offbyone_k3, offbyone_k4, wrong_k, wrong_k_rev}

194: theorem length_modulus_independent :
195:     canonicalLength .k2 = 384 * 2 + 32 ∧
196:     canonicalLength .k3 = 384 * 3 + 32 ∧
197:     canonicalLength .k4 = 384 * 4 + 32 := by exact ⟨rfl, rfl, rfl⟩
```

### 1.3 FORMAL-205 — `formal/Formal/ValidKey.lean`

```lean
47: def isValidKey (p : MLKEMParam) (B : Nat → Nat) : Prop :=
48:   B = B ∧ ∀ i, seg B i < 3329
```

```lean
59: theorem isValidKey_zero_k2 : isValidKey .k2 (fun _ => 0) := by
```

```lean
70: /-- T2 (LENGTH half lift): the length of a ValidKey is
71:     canonicalLength p.  At the byte-array level this is a
72:     statement about the domain, but the byte-array model uses
73:     total functions `Nat → Nat`, so the LENGTH check is
74:     deferred to the type of the array (`Fin (canonicalLength p)
75:     → Nat`). ... -/
78: theorem isValidKey_length_k2 : canonicalLength .k2 = 800 := by
79:   exact canonicalLength_k2
```

```lean
83: theorem isValidKey_roundtrip_k2 (B : Nat → Nat)
84:     (hB : ∀ y, B y < 256) (hSeg : ∀ i, seg B i < 3329) (y : Nat)
85:     (hy : y < canonicalLength .k2) :
86:     encByte (fun i => dec B i) y = B y := by

92: theorem isValidKey_roundtrip_general (B : Nat → Nat)
93:     (hB : ∀ y, B y < 256) (hSeg : ∀ i, seg B i < 3329) (y : Nat) :
94:     encByte (fun i => dec B i) y = B y :=
95:   enc_dec_eq B hB hSeg y
```

---

## 2. Finding-by-finding attack

### 2.1 `fnd-2026-0003` — FORMAL-203 (MODULUS half)

**Attempted attack: circularity of the roundtrip.** Failed. `canonicalRoundtrip` assumes only
`∀ i, F i < 3329` (coeff values below q) — *not* injectivity of `ByteEncode12`. The structural core
is `digit_bridge` (L307–320), which is proved from `coeff_div`/`coeff_mod` (pure arithmetic on
`12*i+j`), `enc_bit`, and `gbit_byte`. There is no injectivity assumption anywhere.

**Attempted attack: hypothesis scrubbing.** Partially succeeded against the *spec fidelity*, not
against the theorem. `roundtrip_iff_canonical` quantifies `B : Nat → Nat` with the hypothesis
`∀ y, B y < 256`. FIPS 203 Eq. (7.1) is
`test ← ByteEncode₁₂(ByteDecode₁₂(ek[0:384k]))` on `ek ∈ 𝔹^(384k+32)`. The Lean hypothesis
`∀ y, B y < 256` does **not** express "a byte array of length 384k"; it merely bounds each value
individually. Both findings disclose this ("the formal `B` is not a length-256 array",
`fnd-2026-0003` limitations), so it is a disclosed modelling choice, not a hidden weakening.
Note the *strength* of this generalization: `roundtrip_iff_canonical` is a biconditional over
**all** byte positions, whereas Eq. (7.1) only covers the first `384k` bytes — the formal
statement is strictly stronger than the spec on the content side.

**Attack on `minimalCounterexample` — THIS LANDS.**

The name and the finding prose over-claim in three ways.

1. **"has segment value `1 + 13*256 = 3329 = q` at i=0" — the `seg B0 0 = 3329` conjunct does
   not exist.** The theorem statement (L440–444) contains `B0 0 = 1`, `B0 1 = 13`,
   `dec B0 0 = 0`, `encByte (dec B0) 0 = 0 ∧ 0 ≠ 1`, `encByte (dec B0) 1 = 0 ∧ 0 ≠ 13`.
   There is no `seg B0 0 = 3329`, so the stated segment value is **implied** by the rest of the
   theorem, not asserted by it.
2. **"minimal" is unformalized and almost certainly false under FIPS 203's byte order.**
   FIPS 203 p.30 (PDF p.30) fixes little-endian bit order (Algorithm 3 line 3: `B[⌊i/8⌋] += b[i]·2^(i mod 8)`),
   and Algorithm 5 line 4 places `b[i·d+j]` with `a ← a/2` each step. `B0 0 = 1` contributes
   `1` to segment bit 0; `B0 1 = 13` contributes `13·256 = 3328` to segment bits 8..11. Segment
   value = `1 + 3328 = 3329 = q`, so `dec B0 0 = 0` is correct.
   But the segment is selected by `wsum (fun j => gbit B (12*i+j)) 12` (L275–276), i.e. global bit
   positions `0..11` — only **bytes 0 and 1 are read**. To get segment value exactly 3329, any byte
   pair `(y, z)` with `low + 256·high = 3329` works, e.g. `y = 0xD1 (209), z = 0x0C (12)`:
   `209 + 3072 = 3281`… using `low = 3329 mod 256 = 1`, `high = 3329 / 256 = 13`. The pair
   `(1, 13)` **is** the unique two-byte witness given `0 ≤ high ≤ 15`, but nothing proves that, and
   nothing bounds the number of non-zero bytes needed. So "minimal" is an unproven adjective.
   (The R2 review, `.scratch/formal-203-r2/REPORT.md` §3.3, initially mis-recomputed this as
   `1 + 13*16 = 209`, caught itself mid-paragraph and corrected to `1 + (0x0D << 8) = 3329`. The
   final arithmetic is right; the "minimal" adjective was never audited.)
3. **"The coefficient q fails Eq (7.1)" — `B0` does not fail Eq. (7.1).** Eq. (7.1) evaluates
   `ByteEncode₁₂(ByteDecode₁₂(ek[0:384k]))` and compares against `ek[0:384k]`. For `B0` the
   theorem shows exactly that: `encByte (dec B0) 0 ≠ B0 0` and `encByte (dec B0) 1 ≠ B0 1`.
   So the *rejection* is correct — but `B0` **fails the LENGTH half too**, and is not an
   encapsulation key. It is not a counterexample *to Eq. (7.1)*; it is a witness that a particular
   2-byte array does not survive the re-encode identity. The finding's own summary says
   "The coefficient q fails Eq (7.1)", which inverts the direction of Eq. (7.1)'s statement.

**Minor, non-blocking:** the R2 report itself flags that the R2 review artifact lives in
`.scratch/`, which the charter treats as non-durable, while `fnd-2026-0003` cites it in
`provenance.sources` — so that source does not resolve for a fresh clone.

**Verdict: CORRECTION NEEDED (statement-scope only).** The proofs are sound, T1/T2 are accurate and
stronger than Eq. (7.1). The `minimalCounterexample` prose must be rewritten to say what L440–444
actually states. `disclosure: public` is otherwise fine — this is ML-KEM spec arithmetic, and
nothing here is security-sensitive.

---

### 2.2 `fnd-2026-0004` — FORMAL-204 (LENGTH half)

**Attack: is this vacuous?** Largely yes. Concretely:

1. **No byte array is modelled anywhere in `LengthCheck.lean`.** The file has no `B : Nat → Nat`,
   no `Fin`, no length-indexed type. The "length check" is `isCanonicalLength p n := n = canonicalLength p`
   (L152) — a definition, not a check of any input.
2. **T1 is definitional unfolding.** `canonicalLength_k2 : canonicalLength .k2 = 800 := rfl` (L71).
   `rfl` on `384*2+32 = 800`. This is kernel-checking the evaluator of the Lean kernel on arithmetic
   literals. It is genuinely *true*, and it is genuinely *zero content* beyond confirming that the
   definition says what the author typed. `fnd-2026-0004` calls this "kernel-checked", which is
   true but should not be read as a proof about ML-KEM.
3. **T2 and T3 are ground closed `Nat` arithmetic.** `¬ 801 = 800`, `¬ 1185 = 1184`, `¬ 1569 = 1568`,
   `¬ 1568 = 800`. These hold with no hypotheses whatsoever — they are `omega`-decided facts about
   literals that a calculator can check. `cross_param_set_rejection` (L132) is genuinely parametric
   in `p q` but is still pure arithmetic over a three-constructor inductive.
4. **The header itself concedes the emptiness.** `LengthCheck.lean` L39–45:
   "This file formalizes the LENGTH half of §7.2. It does not combine with the MODULUS half
   (ByteEncode.lean); that combination is a follow-up." And L189–193 brands the two halves
   "independent" — `length_modulus_independent` (L194) is `⟨rfl, rfl, rfl⟩`.

**Constant check — this PASSES.** `canonicalLength` uses the real FIPS 203 constants:
`384*2+32 = 800`, `384*3+32 = 1184`, `384*4+32 = 1568`. I verified these against
`localdocs/refs/fips203.pdf` PDF p.44 (`ek ∈ 𝔹^(384k+32)`) and PDF p.45 (§7.2 step 1,
"If ek is not an array of bytes of length 384k + 32 …, then input checking failed").
Also note `dk ∈ 𝔹^(768k+96)` on PDF p.44 — not modelled here, correctly, since it belongs to §7.3.

**Dangling in-code reference.** `LengthCheck.lean` L27 refers to `not_isCanonicalLength_*` as the
name of the rejection theorems. No such identifier exists (grep: 0 matches beyond that comment);
the actual names are `isCanonicalLength_rejects_offbyone_k2` etc. and
`not_canonicalLength_offbyone_k2` etc. Cosmetic, but it is a broken reference in a file that is
cited as evidence.

**Verdict: CORRECTION NEEDED — title and status are misleading.**
`fnd-2026-0004`'s `statement:` says these "are kernel-verified" and offers them as the LENGTH half
of the §7.2 check. They are kernel-verified, but they are arithmetic on literals that contains no
statement about any byte array. The title "FIPS 203 §7.2 LENGTH half (Lean 4 kernel-verified)"
implies a formalization of the type check; what exists is a verification that `384·k + 32`
evaluates to 800/1184/1568. Recommend either (a) retitle to "FIPS 203 §7.2 canonical byte lengths
`384k+32` (arithmetic, kernel-checked)" and downgrade the epistemic framing, or (b) keep the title
but add an explicit first-line limitation stating no byte-array type is modelled. Currently
`disclosure: public` is acceptable — nothing secret — but a reader would be misled about depth.

---

### 2.3 `fnd-2026-0006` — FORMAL-205 (combined)

**Attack: does it compose FORMAL-203 + FORMAL-204? NO.** This is the decisive finding.

```lean
47: def isValidKey (p : MLKEMParam) (B : Nat → Nat) : Prop :=
48:   B = B ∧ ∀ i, seg B i < 3329
```

* `B = B` is `propext`-reflexivity — a tautology. It is not a length check. It carries **zero**
  information about length or about `p`.
* The parameter `p` is completely unused. The build log proves this independently:
  `formal/build_output_r3.log` records `warning: Formal/ValidKey.lean:47:16: unused variable 'p'`.
* There is no `Fin`, no `canonicalLength` in the body, no `isCanonicalLength`. Confirmed by grep:
  `Fin` appears in `formal/` **only inside comments** (ValidKey.lean L11, L44, L74; LengthCheck.lean
  L18, L21, L112), never in a type signature. `canonicalLength` is referenced in `ValidKey.lean`
  only at L11/L22/L44/L71/L74/L77 (all prose) and L85/L87/L78/L79 (the T2 restatement and T3's
  dead `hy`).

**Attack: is T2 circular? YES — and it is worse than circular, it is vacuous.**

`isValidKey_length_k2 : canonicalLength .k2 = 800` (L78–79) is one line: `exact canonicalLength_k2`.
It is literally FORMAL-204's `canonicalLength_k2`, restated. Its docstring claims "T2 (LENGTH half
lift): the length of a ValidKey is canonicalLength p" — but `isValidKey` does not appear anywhere in
its statement. `fnd-2026-0006`'s own `statement:` field concedes this ("restates FORMAL-204
canonicalLength_k2"), while the finding's `summary:` asserts the opposite ("**combined** FIPS 203
§7.2 encapsulation-key check (LENGTH + MODULUS halves)"). The summary and the statement block
contradict each other inside a single file.

**Attack: is T3 weaker than what it claims? YES.** `isValidKey_roundtrip_general` (L92–95) has
statement

```
(B : Nat → Nat) → (∀ y, B y < 256) → (∀ i, seg B i < 3329) → ∀ y, encByte (fun i => dec B i) y = B y
```

which is **character-for-character identical** to FORMAL-203's `enc_dec_eq` (`ByteEncode.lean`
L363–365). It is `enc_dec_eq B hB hSeg y`, one line. It does not mention `isValidKey`, it does not
mention `p`, it does not mention `k2`. It carries no length information and therefore **does not
compose** FORMAL-203 with FORMAL-204; it re-proves, identically, a statement FORMAL-203 already
proved.

**Attack: is `isValidKey_roundtrip_k2` (L83) the real "combined" theorem? It is strictly weaker.**
Its `hy : y < canonicalLength .k2` hypothesis is *unused* — proven by the build log:
`formal/build_output_r3.log` records `warning: Formal/ValidKey.lean:85:5: unused variable 'hy'`.
An unused bound on `y` in a `∀ y` statement weakens nothing and adds nothing; it is dead weight.
`fnd-2026-0006` cites T3 as `isValidKey_roundtrip_general` and omits this fourth theorem entirely.

**Attack: non-emptiness (T1) — is it meaningful? Trivially yes, trivially vacuous.**
`isValidKey_zero_k2 : isValidKey .k2 (fun _ => 0)` (L59). It proves the predicate has a witness.
But since the predicate's first conjunct is `B = B` and second is the MODULUS half alone, the
"non-emptiness" evidence is about the MODULUS half only. It says nothing about a length check,
because there is none.

**Dangling internal references.** `ValidKey.lean` L19–26 names the theorems `isValidKey_zero`,
`isValidKey_length`, `isValidKey_roundtrip`; the actual names are `isValidKey_zero_k2`,
`isValidKey_length_k2`, `isValidKey_roundtrip_k2` (+ `_general`). Also L44 and L74 assert "The
LENGTH half is implicit: a `Fin (canonicalLength p) → Nat` type would enforce the length" — this
describes a type the file never has.

**FIPS 203 comparison — §7.2 requires (a) type check `len(ek) == 384k+32` and (b) modulus check
`ByteEncode₁₂(ByteDecode₁₂(ek[0:384k])) == ek[0:384k]`.**

* (b) is formalized: `roundtrip_iff_canonical` (FORMAL-203) + `isValidKey_roundtrip_general`.
* (a) is **not formalized at all**. No statement anywhere in `formal/` says "if `ek` has length
  `384k+32` then it passes the check" or "if `ek` has any other length it is rejected as an
  encapsulation key". The only quantified length statement is
  `canonicalLength_plus_one_neq` (`¬ canonicalLength p + 1 = canonicalLength p`, L99–100), which is
  an elementary fact about addition.

**Verdict: CORRECTION NEEDED — BLOCKING.** `fnd-2026-0006`'s `summary:` asserts
"the complete s7.2 encapsulation-key check is now machine-checked end-to-end", and
`statement:` repeats "Together with FORMAL-203 …, FORMAL-204 …, and FORMAL-205 (this file,
combined half), the complete s7.2 encapsulation-key check is now machine-checked end-to-end."
This is **false** and is **disproved by the artifact's own source file** (`ValidKey.lean` L47–48:
`B = B ∧ ∀ i, seg B i < 3329`, plus the build log's `unused variable 'p'` warning). FORMAL-205 is a
thin wrapper that adds no length content and no composition. As written it must not be disclosed
as-is: `disclosure: public` with that summary would put a false statement into the public record.

---

## 3. Build-verification status — **VERIFIED (not "could not verify")**

I did not run `lake build` and did not download Mathlib. I verified the build three independent ways:

**(a) Local kernel-accepted proof terms exist and match the toolchain.**
`formal/.lake/build/lib/lean/` (gitignored per `.gitignore:78`, deliberately retained per
`CHECKPOINT.md` "Deliberately KEPT: `formal/.lake/build` (1.2 MB, 34 files)" — matches my
measurement of **1.15 MB / 32 files**):

| File | Bytes | Source mtime | olean mtime |
|---|---|---|---|
| `Formal/ByteEncode.olean` | 734,936 | 2026-08-26 04:02:15 | 2026-08-29 04:45:01 |
| `Formal/LengthCheck.olean` | 177,504 | 2026-08-29 22:19:25 | 2026-08-29 22:19:38 |
| `Formal/ValidKey.olean` | 77,136 | 2026-08-29 23:18:19 | 2026-08-29 23:18:32 |

Every olean is **newer than its source**, so no `.lean` file was edited after its last successful
compile. Raw header bytes of all three begin `olean4.22.0ba2cbbf09d4978f416e0ebd1fceeebc2c4138c05`,
confirming the exact toolchain pin claimed in all three findings.

**(b) CI kernel check, independently retrieved.** GitHub Actions run `35469449259`, workflow
`formal.yml`, `conclusion: success`, head SHA `a9338798…` (2026-09-19). Job log (retrieved via
`gh run view --log`) contains:

```
✔ [3050/3054] Built Formal.LengthCheck
⚠ [3051/3054] Built Formal.ByteEncode
⚠ [3052/3054] Built Formal.ValidKey
✔ [3053/3054] Built Formal
Build completed successfully.
BUILD_EXIT=0
```

The workflow itself greps `! grep -q "declaration uses 'sorry'" build.log` and `! grep -qi "error" build.log`.

**(c) Byte-identical sources.** Git blob hashes for `formal/Formal/{ByteEncode,LengthCheck,ValidKey}.lean`
are **identical** at `HEAD` (`07607e37`), at the CI head `a9338798`, and in the working tree
(`ByteEncode` `13c7409e46`, `LengthCheck` `f94e2882fb`, `ValidKey` `487c1d8575`). The successful
CI run compiled exactly the files now on disk.

**Soundness constructs — none present.** Grep over `formal/**/*.lean` for
`sorry | native_decide | axiom | admit | unsafe | partial | opaque` → **0 matches**.
`decide` occurs only in `minimalCounterexample`'s body (L443–450) on the fully concrete `B0` and on
concrete `Nat` literals — sound (`decide` reduces through the kernel; `native_decide` does not).

**Axiom inventory — COULD NOT DETERMINE independently.** `#print axioms` output is **not committed**
anywhere in `knowledge/`. The only primary trace is `.scratch/formal-203-r2/REPORT.md` §2 (FORMAL-203
only), which lives in scratch. The claims for FORMAL-204 (`{propext, Quot.sound}`) and FORMAL-205
(`{propext, Classical.choice, Quot.sound}`) rest solely on a synthesizer's restatement
("`tool: synthesizing lake build output + #print axioms output`"), with no primary artifact.
This does **not** undermine soundness — an .olean containing `sorryAx` or `Classical.choice` is still
kernel-accepted, and CI grepped for `sorry` — but the *inventory* itself is unverified evidence.

**Provenance gap (minor).** CI run `33271390449` (FORMAL-205, 2026-08-29, success) has head SHA
`a6d10876…`, which is **not an ancestor** of `f083ff4` (the commit that added `ValidKey.lean`) — i.e.
that run predates the FORMAL-205 source and is irrelevant. The run that actually covers FORMAL-205 is
`35469449259` (2026-09-19). No finding cites the latter; the findings cite local logs from
2026-08-29 whose runs are not the ones that prove the shipped tree. Minor, because (b) and (c) close
the gap with stronger evidence.

---

## 4. Corrections required, in priority order

1. **`fnd-2026-0006` — BLOCKING.** Delete/replace the sentence "the complete s7.2
   encapsulation-key check is now machine-checked end-to-end" (appears in `summary:`, in
   `statement:`, and in `prf-2026-0003`'s summary). The correct statement: FORMAL-205 adds a
   predicate `isValidKey p B := B = B ∧ (∀ i, seg B i < 3329)` that captures the **MODULUS half
   only**, with `p` unused and the LENGTH half absent; its three theorems are (T1) non-emptiness of
   that predicate, (T2) a restatement of FORMAL-204's `canonicalLength_k2`, (T3) a restatement of
   FORMAL-203's `enc_dec_eq`. Until corrected, this finding must not be published.
2. **`fnd-2026-0004`** — retitle from "§7.2 LENGTH half" to canonical-length arithmetic, or add a
   first-line limitation: *no byte-array type is modelled; the theorems are ground `Nat` arithmetic
   over `384·k + 32`*. Consider `epistemic_status` downgrade from `verified_conclusion` to something
   weaker than a formalization claim, since `rfl` on `384*2+32 = 800` is not a proof about ML-KEM.
3. **`fnd-2026-0003`** — rewrite the T3 / `minimalCounterexample` description to match L440–444:
   it states `B0 0 = 1 ∧ B0 1 = 13 ∧ dec B0 0 = 0 ∧ encByte(dec B0) 0 = 0 ∧ 0 ≠ 1 ∧
   encByte(dec B0) 1 = 0 ∧ 0 ≠ 13`. Drop "has segment value 1 + 13*256 = 3329" (implied, not
   asserted) and drop "minimal" (unproven). Rephrase "The coefficient q fails Eq (7.1)" — `B0` does
   not fail Eq. (7.1); Eq. (7.1) evaluates to `0x00 0x00` for `B0` and the §7.2 modulus check
   therefore rejects `B0`.
4. **All three** — commit the `#print axioms` output as a durable artifact (or record it in
   `formal/axioms.txt`) so the axiom inventories in `prf-2026-0001/0002/0003` and
   `vrf-2026-0003/0005/0007` are backed by primary evidence rather than a synthesizer's restatement.
5. **Cosmetic** — fix `LengthCheck.lean` L27 (`not_isCanonicalLength_*` does not exist) and
   `ValidKey.lean` L19–26, L44, L74 (stale theorem names; describes a `Fin (canonicalLength p) → Nat`
   type the file does not have). Move `.scratch/formal-203-r2/REPORT.md` into `knowledge/reviews/`
   so the source cited by `fnd-2026-0003.provenance.sources` resolves for a fresh clone.

---

## 5. Disclosure recommendation

| Finding | Disclosure |
|---|---|
| `fnd-2026-0003` | **Safe to disclose** as `public` after correcting the `minimalCounterexample` prose. |
| `fnd-2026-0004` | **Safe to disclose** as `public` after retitling/adding the "no byte-array type modelled" limitation. Nothing is security-sensitive; nothing is wrong about ML-KEM. |
| `fnd-2026-0006` | **NOT safe to disclose as written.** Its central claim is falsified by its own source file. Correct first, then disclose. |

No security-sensitive material is involved. ML-KEM-512 is FIPS 203 §7.2 input validation; the
findings describe the spec's own public rejection semantics and generic arithmetic. Nothing here
constitutes an undisclosed vulnerability, so `escalate/security-sensitive` is **not** warranted.
The defects are overstatement of formal coverage, which is exactly the failure mode the charter's
"never make an output sound more impressive by overstating evidence" rule targets.
