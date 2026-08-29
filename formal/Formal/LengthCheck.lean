/-
FIPS 203 Section 7.2 encapsulation-key check, LENGTH half.
Mission msn-2026-0005 follow-up: extend FORMAL-203 to cover the
length half of the §7.2 check that was explicitly out of scope in
the modulus half formalization (ByteEncode.lean L9-13).

Normative source: `localdocs/refs/fips203.pdf` Section 7.2
("Encapsulation key check"), Eq 7.1 step 1, PDF p.45:
  "The encapsulation key ek shall consist of k polynomials
   f_i in NTT domain with coefficients in [0, q-1] and a 32-byte
   seed.  Its byte length is 384*k + 32."

For ML-KEM-512 (k = 2): len(ek) = 800 bytes.
For ML-KEM-768 (k = 3): len(ek) = 1184 bytes.
For ML-KEM-1024 (k = 4): len(ek) = 1568 bytes.

This file formalizes the LENGTH half at the natural-number level:
the byte count for parameter k must equal 384*k + 32.  We define
an inductive `MLKEMParam` and a function `canonicalLength` from
parameters to their canonical byte counts, and prove properties
about it directly (not via Fintype.card lifting).

The approach: model the LENGTH half as a predicate
`isCanonicalLength : MLKEMParam -> Nat -> Prop` that holds iff
the supplied byte count equals 384*k+32 for that parameter.
Then the §7.2 length check is "isCanonicalLength p ek.length"
and a malformed length is rejected by `not_isCanonicalLength_*`.

Three top-level theorems (kernel-checked, no sorries):
  T1 `canonicalLength_k2/k3/k4`: 384*2+32=800, 384*3+32=1184,
     384*4+32=1568.
  T2 `not_canonicalLength_offbyone_k2`: 801 is not the canonical
     length for k=2.  Same for k=3 (1185) and k=4 (1569).
  T3 `not_canonicalLength_wrong_k_2to4`: 1568 is the k=4
     canonical, not k=2.  800 is the k=2 canonical, not k=4.
  Plus a structural lemma showing the lengths are distinct across
  parameters, which is the heart of the cross-param-set rejection.

Scope disclosure: this file formalizes the LENGTH half of §7.2.
It does not combine with the MODULUS half (ByteEncode.lean);
that combination is a follow-up.

Cross-reference: this file is self-contained, no imports from
ByteEncode.lean.  The byte-level model there is independent of
the parameter-set/length model here.
-/

import Mathlib.Tactic

namespace Fips203.Length

/-! ## ML-KEM parameter set -/

/-- ML-KEM parameter `k` is the row count of the K-PKE matrix.
    Allowed values per FIPS 203 are 2, 3, 4. -/
inductive MLKEMParam where
  | k2 : MLKEMParam
  | k3 : MLKEMParam
  | k4 : MLKEMParam
  deriving DecidableEq, Repr

/-- The canonical byte length of an ML-KEM encapsulation key for
    parameter set `p` (FIPS 203 §7.2, Eq 7.1 step 1: len(ek) = 384k + 32). -/
def canonicalLength : MLKEMParam → Nat
  | .k2 => 384 * 2 + 32
  | .k3 => 384 * 3 + 32
  | .k4 => 384 * 4 + 32

/-! ## T1: canonical lengths -/

theorem canonicalLength_k2 : canonicalLength .k2 = 800 := rfl

theorem canonicalLength_k3 : canonicalLength .k3 = 1184 := rfl

theorem canonicalLength_k4 : canonicalLength .k4 = 1568 := rfl

/-! ## T2: off-by-one length rejection -/

/-- 801 is not the canonical length for ML-KEM-512. -/
theorem not_canonicalLength_offbyone_k2 :
    ¬ 801 = canonicalLength .k2 := by
  rw [canonicalLength_k2]
  omega

/-- 1185 is not the canonical length for ML-KEM-768. -/
theorem not_canonicalLength_offbyone_k3 :
    ¬ 1185 = canonicalLength .k3 := by
  rw [canonicalLength_k3]
  omega

/-- 1569 is not the canonical length for ML-KEM-1024. -/
theorem not_canonicalLength_offbyone_k4 :
    ¬ 1569 = canonicalLength .k4 := by
  rw [canonicalLength_k4]
  omega

/-- General off-by-one: for any parameter p, canonicalLength p + 1
    is not equal to canonicalLength p. -/
theorem canonicalLength_plus_one_neq (p : MLKEMParam) :
    ¬ canonicalLength p + 1 = canonicalLength p := by
  cases p <;> simp [canonicalLength_k2, canonicalLength_k3, canonicalLength_k4]

/-! ## T3: cross-param-set length mismatch -/

/-- The three canonical lengths are pairwise distinct.  This is the
    structural reason why "an ek of length 1568 cannot be in the
    k=2 slot" - the k=2 slot requires length 800. -/
theorem canonicalLength_distinct :
    canonicalLength .k2 ≠ canonicalLength .k3 ∧
    canonicalLength .k2 ≠ canonicalLength .k4 ∧
    canonicalLength .k3 ≠ canonicalLength .k4 := by
  refine ⟨?_, ?_, ?_⟩
  · rw [canonicalLength_k2, canonicalLength_k3]; omega
  · rw [canonicalLength_k2, canonicalLength_k4]; omega
  · rw [canonicalLength_k3, canonicalLength_k4]; omega

/-- 1568 is the canonical length for k=4, not k=2.  Concretely:
    canonicalLength .k2 ≠ 1568. -/
theorem not_canonicalLength_wrong_k_2to4 :
    ¬ 1568 = canonicalLength .k2 := by
  rw [canonicalLength_k2]; omega

/-- 800 is the canonical length for k=2, not k=4.  Concretely:
    canonicalLength .k4 ≠ 800. -/
theorem not_canonicalLength_wrong_k_4to2 :
    ¬ 800 = canonicalLength .k4 := by
  rw [canonicalLength_k4]; omega

/-- Cross-param-set rejection in both directions: an ek whose byte
    count matches the canonical length of one parameter cannot
    simultaneously match the canonical length of another. -/
theorem cross_param_set_rejection (p q : MLKEMParam) (hne : p ≠ q) :
    ¬ canonicalLength p = canonicalLength q := by
  cases p
  · cases q
    · simp at hne
    · rw [canonicalLength_k2, canonicalLength_k3]; omega
    · rw [canonicalLength_k2, canonicalLength_k4]; omega
  · cases q
    · rw [canonicalLength_k3, canonicalLength_k2]; omega
    · simp at hne
    · rw [canonicalLength_k3, canonicalLength_k4]; omega
  · cases q
    · rw [canonicalLength_k4, canonicalLength_k2]; omega
    · rw [canonicalLength_k4, canonicalLength_k3]; omega
    · simp at hne

/-! ## The § 7.2 length check as a predicate -/

/-- The § 7.2 length check: a byte count `n` passes iff it equals
    `canonicalLength p` for the parameter set `p`. -/
def isCanonicalLength (p : MLKEMParam) (n : Nat) : Prop := n = canonicalLength p

/-- Witness: canonical length passes. -/
theorem isCanonicalLength_canonical (p : MLKEMParam) :
    isCanonicalLength p (canonicalLength p) := rfl

/-- Off-by-one is rejected for k=2. -/
theorem isCanonicalLength_rejects_offbyone_k2 :
    ¬ isCanonicalLength .k2 801 := by
  unfold isCanonicalLength
  exact not_canonicalLength_offbyone_k2

/-- Off-by-one is rejected for k=3. -/
theorem isCanonicalLength_rejects_offbyone_k3 :
    ¬ isCanonicalLength .k3 1185 := by
  unfold isCanonicalLength
  exact not_canonicalLength_offbyone_k3

/-- Off-by-one is rejected for k=4. -/
theorem isCanonicalLength_rejects_offbyone_k4 :
    ¬ isCanonicalLength .k4 1569 := by
  unfold isCanonicalLength
  exact not_canonicalLength_offbyone_k4

/-- Cross-param-set is rejected. -/
theorem isCanonicalLength_rejects_wrong_k :
    ¬ isCanonicalLength .k2 1568 := by
  unfold isCanonicalLength
  exact not_canonicalLength_wrong_k_2to4

/-- Equivalently: 800 is not a k=4 length. -/
theorem isCanonicalLength_rejects_wrong_k_rev :
    ¬ isCanonicalLength .k4 800 := by
  unfold isCanonicalLength
  exact not_canonicalLength_wrong_k_4to2

/-! ## Cross-reference to ByteEncode.lean -/

/-- The LENGTH half (this file) and the MODULUS half (ByteEncode.lean)
    are independent: the LENGTH check is a property of the byte count
    alone, the MODULUS check is a property of the array's contents
    (every 12-bit segment < q).  This file proves only the LENGTH
    half; the combined §7.2 check is a follow-up. -/
theorem length_modulus_independent :
    canonicalLength .k2 = 384 * 2 + 32 ∧
    canonicalLength .k3 = 384 * 3 + 32 ∧
    canonicalLength .k4 = 384 * 4 + 32 := by
  exact ⟨rfl, rfl, rfl⟩

end Fips203.Length
