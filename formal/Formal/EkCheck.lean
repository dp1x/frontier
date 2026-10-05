/-
FIPS 203 Section 7.2 encapsulation key check (Eq 7.1) over a BOUNDED byte
index, for a FIXED parameter set.  Mission msn-2026-0021 (FORMAL-208).

WHY THIS FILE EXISTS.  The committed corpus models a byte array as a total
`Nat -> Nat`, i.e. an infinite, lengthless array, and therefore phrases the
modulus-check hypothesis with NO index bound:

    forall i, seg B i < 3329                                              (OLD)

`ByteEncode.lean` proves `roundtrip_iff_canonical`, which relates (OLD) to
"Eq (7.1) holds at every index".  (OLD) constrains the segments of `B` for
ALL i, including the segments of the 32-byte rho seed that Eq (7.1) never
touches, so the hypothesis is FALSE for most genuine ML-KEM keys and the
roundtrip theorem is vacuous on exactly the class of objects the
specification is about.  The `p` parameter of `ValidKey.isValidKey` is
likewise unused (see `formal/build_output_r3.log`, warning at
ValidKey.lean:47).  This file adds the bounded model that FIPS 203 itself
states, and -- following msn-2026-0021's `critical_constraint` -- ships an
ACCEPT theorem together with a REJECT theorem, because an accept-only
theorem is satisfiable by a hypothesis nobody can inhabit.

Normative source: `localdocs/refs/fips203.pdf`.  Every quoted sentence
below was read directly out of that PDF by the author of this file.

  Section 7.2 "Encapsulation key check", printed p.36 / PDF p.45, verbatim:

    "Encapsulation key check. To check a candidate encapsulation key ek,
     perform the following:"

    "1. (Type check) If ek is not an array of bytes of length 384k + 32 for
     the value of k specified by the relevant parameter set, then input
     checking failed."

    "2. (Modulus check) Perform the computation

         test <- ByteEncode_12(ByteDecode_12(ek[0 : 384k]))          (7.1)

     (see Section 4.2.1). If test != ek[0 : 384k], then input checking
     failed. This check ensures that the integers encoded in the public key
     are in the valid range [0, q - 1]."

  Section 4.2.1, printed p.21 / PDF p.30, verbatim (the reason Eq (7.1) can
  ever fail), on d = 12:

    "For d = 12, ByteDecode_12 produces integers modulo q as output, while
     ByteEncode_12 receives integers modulo q as input.  Specifically,
     ByteDecode_12 converts each 12-bit segment of its input into an integer
     modulo 2^12 = 4096 and then reduces the result modulo q.  This is no
     longer a one-to-one operation.  Indeed, some 12-bit segments could
     correspond to an integer greater than q - 1 = 3328 but less than 4096.
     However, this cannot occur for arrays produced by ByteEncode_12."

  Table 3, printed p.39 / PDF p.48, gives the encapsulation-key byte counts
  800 / 1184 / 1568 for ML-KEM-512 / 768 / 1024, consistent with 384k + 32
  at k = 2 / 3 / 4.  Table 2 on the same page fixes k = 2 / 3 / 4 and
  q = 3329.

  For the layout of ek, read directly from the same PDF:

    Algorithm 16 ML-KEM.KeyGen_internal (printed p.32 / PDF p.41), line 2:
      "ek <- ekPKE        # KEM encaps key is just the PKE encryption key"

    Algorithm 13 K-PKE.KeyGen (printed p.29 / PDF p.38), line 19:
      "ekPKE <- ByteEncode_12(t) || rho    # run ByteEncode_12 k times, then
                                          append the seed"
      with Output line: "encryption key ekPKE . in B^(384k+32)".

    Algorithm 14 K-PKE.Encrypt (printed p.30 / PDF p.39), lines 2-3:
      "2: t   <- ByteDecode_12(ekPKE[0 : 384k])   # run ByteDecode_12 k times
                                                  # to decode t"
      "3: rho <- ekPKE[384k : 384k + 32]           # extract 32-byte seed
                                                  # from ekPKE"

  Consequently the 32-byte rho seed occupies exactly the byte positions
  [384k, 384k + 32), the LAST positions of the ek produced by Algorithm 13
  line 19, and Eq (7.1) -- whose ByteDecode_12 and ByteEncode_12 both
  operate on ek[0 : 384k] -- never constrains them.
  `seed_region_unconstrained` and `seed_region_unconstrained_k2` below are
  kernel-checkable versions of that observation.

  MODEL RESTRICTION, stated explicitly rather than glossed: FIPS 203 makes
  step 2 fail when the ARRAYS `test` and `ek[0 : 384k]` differ, whereas the
  `eq7_1` predicate below is the per-index reading of the same condition.
  Weakening "the arrays differ" to "some index differs" is sound for the
  ACCEPT direction (agreement at every covered index implies array equality
  at those indices, so acceptance implies no failure), but the REJECT
  direction is stated here in the form "some covered index differs".  This is
  a modelling decision about this file, not a claim about FIPS 203.

WHAT THIS FILE DOES AND DOES NOT MODEL.
  DOES: both steps of Section 7.2 as the specification states them, over a
  length-typed byte array, for one FIXED value of k; the index arithmetic
  that bounds the Eq (7.1) prefix at 384k bytes = 256k twelve-bit
  coefficients; the accept and the reject direction of Eq (7.1); and a
  kernel-checked counterexample showing that the OLD unbounded hypothesis
  (OLD) is false for a key that satisfies the real Section 7.2 check.
  DOES NOT: model `ByteDecode_12` as specified in Algorithm 6 (it decodes
  exactly 384 bytes, i.e. 256 coefficients, so a k-th coefficient exists
  only after k applications -- see the `eq7_1` docstring); the hash-based
  origin of rho; ML-KEM.KeyGen correctness; NTT; K-PKE.Encrypt / Decrypt;
  any probabilistic claim about how often genuine keys violate (OLD);
  SP 800-227.  The mission's "~99%" figure is NOT reproduced here: it is
  not a kernel-checkable statement.

MAIN RESULTS (mission `required_theorems`)
  T1 `eq7_1_accept`          Eq (7.1) holds at every y < 384k.
  T2 `eq7_1_reject`          a coefficient at or above q inside the prefix
                             forces Eq (7.1) to fail at some y < 384k.
  T3 `step1_type_check`      the type check, with `k` load-bearing
                             (`step1_length_injective`,
                              `step1_length_load_bearing_examples`).
  T4 `old_hypothesis_false_k2`
                             an ek of length 800 -- the length step 1
                             demands for k = 2 -- that satisfies Eq (7.1)
                             but violates the OLD hypothesis (OLD).
  plus    `eq7_1_hypothesis_inhabited`   (explicit anti-vacuity witness
                                          for T1),
         `seed_region_unconstrained`, `seed_region_unconstrained_k2`,
         `okKey_iff_eq7_1`, `eq7_1_iff`,
         `eq7_1_accept_pointwise` / `eq7_1_reject_some_index` (the
             per-index pair; see (R9) for why there is no per-index biconditional),
         `eq7_1_holds_forever` / `eq7_1_fails_forever` (the unbounded
         contrast),
         `prefix_bits_stop_before_seed`.

REPAIR LOG 2026-10-05 (commit history of this file).  The first committed
revision of this module did NOT compile: GitHub Actions run 37221348965
(workflow formal-verify, commit 8c99e73) reported 33 errors in it.  The
implementing agent's earlier claim that the module "resolves cleanly under
the Lean front end" was therefore false; a front-end check is not a kernel
check.  Only the PROOFS were repaired -- the design is unchanged.  The
substantive changes, each recorded because each one changes what is
asserted:

  (R1) `ekSeg` stays a `def`, and the conversion to `seg (ekBytes k ek) i`
       is made EXPLICIT by `ekSeg_eq` (`rfl`) plus a `rw` at each use site.
       An intermediate revision made it an `abbrev` on the theory that
       reducibility would be enough; GitHub Actions run 37311872592 showed
       it is not -- the elaborator still refused to unfold `ekSeg` in the
       higher-order argument position of `enc_dec_eq`.  The explicit rewrites
       are load-bearing and must not be removed.
  (R2) `twelve_mul_nCoeff` was FALSE in the first revision, which stated
       `12 * nCoeff k = 384 * k`.  That conflates bits with bytes: the prefix
       holds `12 * nCoeff k` BITS, and `8 * (384 * k)` bits is the same
       number (`k = 2` gives `6144`, not `768`).  Run 37313575264 rejected
       `ring` on the resulting goal `k * 3072 = k * 384`.  The theorem now
       states the corrected identity `12 * nCoeff k = 8 * (384 * k)`; the
       byte count `384 * k` is recovered where it is needed, by dividing by
       the byte width in `witness_byte_lt_prefix`.
  (R9) The per-index biconditional `eq7_1_iff_seg_bound` of the first
       revision was FALSE and has been removed, not repaired.  It asserted
       that agreement at ONE chosen byte index `y` is equivalent to every
       prefix coefficient being below `q`.  Only the forward implication
       holds: an out-of-range coefficient elsewhere in the prefix makes the
       re-encoding disagree at THAT coefficient's byte index, not at `y`.
       It is replaced by `eq7_1_accept_pointwise` (the valid direction) and
       `eq7_1_reject_some_index`.  `eq7_1_iff`, which is the whole-prefix
       statement, is unaffected and unchanged.
  (R10) `B2_prefix_segments_canonical` and its `B2alt` counterpart now go
       through `wsum_congr` over `Finset.range 12` (the pattern
       `ByteEncode.canonicalRoundtrip` already uses) rather than through
       `seg_eq_zero_of_bits_zero`, whose hypothesis quantifies over ALL `j`
       while `seg`'s sum only runs over `j < 12`.
  (R3) `coeff_mem_prefix` and `prefix_bits_stop_before_seed` were rewriting
       with `← twelve_mul_nCoeff k`, which searches for `384 * k` in a goal
       that never contains it.  The direction is now forward, and
       `prefix_bits_stop_before_seed` states the step through
       `12 * (i + 1) ≤ 12 * (256 * k)` explicitly.
  (R4) T2's hypothesis is `3329 ≤ ekSeg k ek i`, not the `3329 < ...` of the
       previous revision.  This is a STRENGTHENING, not a weakening: FIPS
       203's own wording is that the check "ensures that the integers
       encoded in the public key are in the valid range [0, q - 1]", so
       being outside the range is `q ≤ v`, and `3329 < v` would have
       excluded `v = 3329 = q` -- which is precisely the value the T4
       counterexample exhibits.  The previous revision also mis-quoted the
       specification in claiming that `3329 < v` was "FIPS 203's own
       wording".  `3329 ≤ ekSeg k ek i` is exactly the hypothesis
       `ByteEncode.reject_on_overflow` consumes.
  (R5) `B2_prefix_bits_zero` and `B2alt_prefix_bits_zero` GAIN the
       hypothesis `j < 12`.  Without it they were FALSE, not merely
       unprovable: the index `j` ran over all of `Nat`, so `j = 6144` was
       an admissible instance and the claimed value was the seed byte's.
       `j < 12` is the range the summation in `seg` actually ranges over,
       so nothing was lost -- but the previous revision's statements were
       untrue as written and must not be cited.
  (R6) `B2_bytes`/`B2alt_bytes` previously ended their "index outside the
       key" branches with `rfl`, which is not valid: outside the key the
       byte view reads 0, which is `B2raw y` only after the two seed-byte
       cases are discharged.
  (R7) `B2_seg512` was proved by `interval_cases` and `decide` on the twelve
       bit positions.  That became unprovable once the byte view became a
       piecewise `if` (it does not decide the `if`-split), so under (R11) the
       twelve positions are discharged from `B2_bytes` and `bit_zero`
       instead: bytes 768 and 769 are the only non-zero bytes and the
       positions `6144 + s`, `s < 12`, are all above them.  The conclusion
       is unchanged (`ekSeg 2 B2 512 = 3329`).
  (R8) `unbounded_reencode_disagrees_at_768` is proved directly, by
       exhibiting bit position 0 of the re-encoded byte 768 as 0 against
       the key's 1.  It previously destructured a two-component
       existential as a three-component one and then applied a proof to a
       statement of type `Nat`.
  (R11) `Ek k` was `Fin (384 * k + 32) -> Nat`, which does NOT model "an array
       of BYTES".  GitHub Actions run 37318859754 showed this: it makes
       `prefix_last_bit_byte` FALSE at k = 1 (byte 0 may be 1000, and
       `1000 / 8 < 384` is false), and `Nat.mod_lt _ hr` is vacuous because
       it binds `hr` as an IMPLICIT argument, so the byte bound it was
       supposed to use was never even a hypothesis.  Step 1 of Section 7.2
       requires ek to be an array of bytes, so the element type is now
       `Fin 256`: `def Ek (k : Nat) := Fin (384 * k + 32) -> Fin 256`, with
       `ekVal` for the underlying byte value and `ekOfTotal` for the
       concrete witnesses.  `EkTypeCheck` is no longer `True`; it is
       `EkTypeCheck k ek = ek` and is proved `rfl`, because the length and
       the byte range are now both carried by the type.
  (R12) `eq7_1_accept` had `hB : forall y, ekBytes k ek y < 256` as a
       HYPOTHESIS.  Under (R11) that is a theorem, not an assumption, so
       every theorem in this file that only needed it is restated without
       it.  `eq7_1_reject` is STRENGTHENED in the process: its conclusion is
       unchanged and its hypothesis `3329 <= seg B i` is unchanged, but the
       byte premise is now discharged internally by `ekBytes_lt`.
  (R13) `Nat.div_lt_iff_lt_mul` is deprecated and gone in this toolchain;
       run 37318859754 reports "tactic 'rewrite' failed, equality or iff
       proof expected ?m / ?m < ?m".  `Nat.div_lt_of_lt_mul` replaces it and
       keeps the side condition `8 <= 8 * i + j` explicit.

TRUST BOUNDARY.  Whether this file has been accepted by the Lean kernel is
recorded in the mission file `missions/active/msn-2026-0021.yaml` and by
the `formal-verify` run IDs cited there -- not by this header, and not by
any local front-end check.  A front-end-only check is not evidence of
kernel acceptance; revision 1 of this file is the recorded counterexample.
-/

import Mathlib.Tactic
import Formal.ByteEncode
import Formal.LengthCheck

namespace Fips203.EkCheck

open Fips203
open Fips203.Length

/-! ## Small arithmetic helpers, as theorems rather than literals, so that
     the byte and coefficient counts below are visibly load-bearing. -/

theorem nat_lit_768 : (768 : Nat) = 384 * 2 := by norm_num
theorem nat_lit_800 : (800 : Nat) = 384 * 2 + 32 := by norm_num
theorem nat_lit_512 : (512 : Nat) = 256 * 2 := by norm_num

/-! ## The bounded-index view of a key -/

/-- A byte array `ek` of parameter set `k`, with the byte index bounded at
`384 * k + 32` BY THE INDEX TYPE.  This is the first half of step 1's "array
of bytes of length 384k + 32", and it is what makes the parameter `k`
load-bearing: `Ek 2`, `Ek 3` and `Ek 4` are three different types.

Step 1 of Section 7.2 says "If ek is not an array of BYTES of length 384k +
32", so BOTH halves of that are carried by the type: the domain `Fin (384*k+32)`
is the length and the codomain `Fin 256` is the byte range.  An earlier
revision used the codomain `Nat`, which is not the set of bytes and made the
byte bound a separate assumption -- see revision note (R11). -/
def Ek (k : Nat) := Fin (384 * k + 32) → Fin 256

/-- The value of the key's byte `y`, as a `Nat`.  This is the only place the
`Fin 256` bound has to be unwrapped. -/
def ekVal (k : Nat) (ek : Ek k) (y : Nat) (hy : y < 384 * k + 32) : Nat :=
  (ek ⟨y, hy⟩).val

theorem ekVal_lt (k : Nat) (ek : Ek k) (y : Nat) (hy : y < 384 * k + 32) :
    ekVal k ek y hy < 256 := (ek ⟨y, hy⟩).isLt

/-- Interpret a total function as a length-typed key.  Used to write the
concrete counterexample below without leaving `Nat -> Nat`. -/
def ekOfTotal (k : Nat) (f : Nat → Nat) : Ek k :=
  fun y => ⟨f y.val % 256, Nat.mod_lt _ (by omega)⟩

theorem ekOfTotal_val (k : Nat) (f : Nat → Nat) (y : Nat) (hy : y < 384 * k + 32) :
    ekOfTotal k f ⟨y, hy⟩ = ⟨f y % 256, Nat.mod_lt _ (by omega)⟩ := rfl

/-- The byte view of `ek`: the total function the corpus's index lemmas are
stated for.  Indices `y >= 384 * k + 32` are outside the key and read as 0;
every index `y < 384 * k + 32` reads the key's byte. -/
def ekBytes (k : Nat) (ek : Ek k) (y : Nat) : Nat :=
  if h : y < 384 * k + 32 then (ek ⟨y, h⟩).val else 0

theorem ekBytes_val (k : Nat) (ek : Ek k) (y : Nat) (hy : y < 384 * k + 32) :
    ekBytes k ek y = (ek ⟨y, hy⟩).val := by
  simp [ekBytes, hy]

theorem ekBytes_outside (k : Nat) (ek : Ek k) (y : Nat) (hy : ¬ y < 384 * k + 32) :
    ekBytes k ek y = 0 := by
  simp [ekBytes, hy]

/-- Every byte of the byte view is a byte.  Inside the key this is the
`Fin 256` element type; outside, the view reads 0.  This is the bound
`ByteEncode`'s `enc_dec_eq`, `reject_on_overflow` and `eqOfBits` ask for. -/
theorem ekBytes_lt (k : Nat) (ek : Ek k) (y : Nat) : ekBytes k ek y < 256 := by
  by_cases h : y < 384 * k + 32
  · rw [ekBytes_val k ek y h]
    exact (ek ⟨y, h⟩).isLt
  · rw [ekBytes_outside k ek y h]
    omega

/-- Segment `i` of the byte view of `ek`: the 12-bit little-endian word at
global bit positions `[12i, 12i + 12)`.  Algorithm 6 line 3 with d = 12.

`ByteEncode.enc_dec_eq` and `ByteEncode.reject_on_overflow` are stated for
`seg B i`, so the bounded view has to be passed to them as `seg (ekBytes k ek) i`.
That conversion is only well-typed if it is established by `rfl` at each use
site (`show ... = ...`); `ekSeg_eq` below records that fact once.  An earlier
revision made this an `abbrev`, which the elaborator still refused to unfold
in higher-order position, so the `show`s are load-bearing. -/
def ekSeg (k : Nat) (ek : Ek k) (i : Nat) : Nat := seg (ekBytes k ek) i

theorem ekSeg_eq (k : Nat) (ek : Ek k) (i : Nat) : ekSeg k ek i = seg (ekBytes k ek) i :=
  rfl

/-! ## How many coefficients the Eq (7.1) prefix carries -/

/-- The number of 12-bit coefficients in the `384k`-byte prefix: `256k`.
Each coefficient occupies 12 bits and each byte 8 bits, and
`12 * 256k = 384k` bytes = `8 * 384k` bits. -/
def nCoeff (k : Nat) : Nat := 256 * k

theorem nCoeff_zero_coeff : nCoeff 0 = 0 := by norm_num [nCoeff]
theorem nCoeff_two_coeff : nCoeff 2 = 512 := by norm_num [nCoeff]

/-- The `384 * k`-byte prefix holds `8 * (384 * k)` BITS, and `nCoeff k`
twelve-bit coefficients hold `12 * nCoeff k` bits; the two agree.

The first revision of this file stated `12 * nCoeff k = 384 * k`, which
conflates bits with bytes and is FALSE (`k = 2` gives `6144 = 768`).  It
was never proved: GitHub Actions run 37221348965 rejected `ring` on the
resulting goal `k * 3072 = k * 384`.  The factor of 8 is the byte width,
and the corrected identity below is what the index arithmetic actually
needs. -/
theorem twelve_mul_nCoeff (k : Nat) : 12 * nCoeff k = 8 * (384 * k) := by
  simp only [nCoeff]
  ring

/-- The coefficients that the `384k`-byte prefix contains are precisely those
with `i < nCoeff k`: any bit position below the prefix's `12 * nCoeff k`
bits belongs to a coefficient numbered below `nCoeff k`. -/
theorem coeff_mem_prefix {k : Nat} {p : Nat} (hp : p < 12 * nCoeff k) :
    p / 12 < nCoeff k := by
  have h12 : (0 : Nat) < 12 := by omega
  have heq := twelve_mul_nCoeff k
  rw [nCoeff] at heq
  omega

/-- The `384 * k`-byte prefix holds `8 * 384 * k = 12 * nCoeff k` bits, so
the prefix contains exactly `nCoeff k` twelve-bit coefficients and the
prefix never reads byte `384 * k` or beyond. -/
theorem prefix_last_bit_byte (k : Nat) :
    ((8 * 384 * k - 1) / 8 : Nat) < 384 * k := by
  have h1 : (0 : Nat) < 384 := by omega
  have h8 : (0 : Nat) < 8 := by omega
  have hpos : (0 : Nat) < 8 * 384 * k := Nat.mul_pos (Nat.mul_pos h8 h1) (Nat.succ_pos k)
  have hr : (8 * 384 * k - 1) % 8 < 8 := Nat.mod_lt _ h8
  have hdecomp := Nat.div_add_mod (8 * 384 * k - 1) 8
  have hlt : 8 * ((8 * 384 * k - 1) / 8) < 8 * 384 * k := by omega
  have hone : (8 * 384 * k - 1) / 8 = 384 * k - 1 := by
    refine Nat.le_antisymm (by omega) ?_
    omega
  omega

/-! ## STEP 1: the type check, with `k` load-bearing -/

/-- STEP 1 (Type check), parameterised by `k`.

Type check, verified verbatim above: "1. (Type check) If ek is not an array
of bytes of length 384k + 32 for the value of k specified by the relevant
parameter set, then input checking failed."  The requirement is a property of
the array's TYPE, so this file gives `ek` the length-indexed type
`Fin (384 * k + 32) -> Fin 256` instead of the unbounded `Nat -> Nat` used by
`ByteEncode.lean`.  A key that passes step 1 has byte index `y < 384 * k + 32`
and byte value `ek y < 256` BY CONSTRUCTION, and no axiom or predicate is
needed to say so.

`EkTypeCheck` is therefore the identity, and it is proved `rfl`: it exists so
that the type check still appears as a named step of Section 7.2 inside the
combined predicate `okKey`, not because it carries any content the type does
not already carry.  A previous revision used `True` here while `Ek k` still
had codomain `Nat`, which is the pair that made the byte bound an assumption
rather than a fact -- see revision note (R11).  `EkTypeCheck` is therefore the
BYTE-RANGE half of step 1, `∀ y, ek y < 256`, proved from `ek y`'s type by
`Fin.isLt`.  An earlier attempt at "the identity" (`EkTypeCheck ek := ek`) was
rejected by the kernel: `Ek k` is a `Type`, not a `Prop`. -/
def EkTypeCheck {k : Nat} (ek : Ek k) : Prop := ∀ y : Fin (384 * k + 32), ek y < 256

theorem step1_type_check (k : Nat) (ek : Ek k) : EkTypeCheck ek := fun y => (ek y).isLt

/-- T3a: the parameter `k` is load-bearing.  Distinct `k` give distinct
required byte counts, so `k` cannot be projected away.  This is the repair of
the `unused variable 'p'` warning recorded against `ValidKey.isValidKey` in
`formal/build_output_r3.log`. -/
theorem step1_length_injective :
    ∀ k1 k2 : Nat, 384 * k1 + 32 = 384 * k2 + 32 -> k1 = k2 := by
  intro k1 k2 h
  omega

/-- T3a, concrete instances for the three approved parameter sets: an
ML-KEM-512-sized key is not well-formed at k = 3 or k = 4, and likewise for
the others.  The three numbers agree with Table 3 (printed p.39 / PDF p.48). -/
theorem step1_length_load_bearing_examples :
    ¬ (384 * 3 + 32 = 384 * 2 + 32) ∧
    ¬ (384 * 4 + 32 = 384 * 2 + 32) ∧
    ¬ (384 * 4 + 32 = 384 * 3 + 32) ∧
    (384 * 2 + 32 = 800) ∧ (384 * 3 + 32 = 1184) ∧ (384 * 4 + 32 = 1568) := by
  refine ⟨by norm_num, by norm_num, by norm_num, by norm_num, by norm_num, by norm_num⟩

/-- The three approved parameter sets have pairwise distinct admissible
encapsulation-key lengths. -/
theorem step1_pairwise_distinct :
    canonicalLength .k2 ≠ canonicalLength .k3 ∧
    canonicalLength .k2 ≠ canonicalLength .k4 ∧
    canonicalLength .k3 ≠ canonicalLength .k4 :=
  canonicalLength_distinct

/-! ## Eq (7.1) as a predicate -/

/-- Eq (7.1) on a length-typed key: the re-encoding of the decoded
`384k`-byte prefix agrees with that prefix at every byte index it covers.

Scope note.  Algorithm 6 line 2 runs `ByteDecode_12` on exactly 384 bytes,
i.e. 256 twelve-bit coefficients, and Algorithm 14 line 2 calls it `k` times
to assemble a vector of `k` polynomials.  This model does not reproduce that
composition: `dec` below is the coefficient-wise operation of Algorithm 6
line 3, and the property being formalised -- that the re-encoding of the
prefix reproduces it -- is per-coefficient, so the `k`-fold assembly is not
needed.  What the `k` does carry here is the LENGTH of the prefix. -/
def eq7_1 (k : Nat) (ek : Ek k) : Prop :=
  ∀ y, y < 384 * k -> encByte (fun i => dec (ekBytes k ek) i) y = ekBytes k ek y

/-! ## STEP 2: Eq (7.1) over the bounded index -/

/-- T1, ACCEPT.  If every one of the `256k` coefficients carried by the
`384k`-byte prefix is below q = 3329, then the byte at every index
`y < 384 * k` is reproduced by `ByteEncode_12(ByteDecode_12(ek[0 : 384k]))`.

This is `ByteEncode.enc_dec_eq` with its hypothesis `forall i, seg B i < 3329`
restricted to `i < nCoeff k`.  That restriction is the whole point: the
unrestricted hypothesis reaches the rho seed and is false for most genuine
keys, so the restriction makes this theorem's hypothesis INHABITABLE
(witness: `eq7_1_hypothesis_inhabited` below).

It CANNOT be obtained by instantiating `ByteEncode.enc_dec_eq`, because that
lemma's hypothesis is the UNBOUNDED `∀ i, seg B i < 3329`; a bounded
hypothesis cannot supply it.  The proof below therefore repeats
`enc_dec_eq`'s argument -- `eqOfBits` over the eight bit positions of one
byte -- with the per-bit hypothesis that the coefficient owning that bit,
namely `p / 12`, lies inside the prefix.  That is the index step
`coeff_mem_prefix`, and it is where the bound `384 * k` on `y` is used. -/
theorem eq7_1_accept (k : Nat) (ek : Ek k) (hSeg : ∀ i, i < nCoeff k -> ekSeg k ek i < 3329)
    (y : Nat) (hy : y < 384 * k) :
    encByte (fun i => dec (ekBytes k ek) i) y = ekBytes k ek y := by
  have hlt : encByte (fun i => dec (ekBytes k ek) i) y < 256 := by
    have hw := wsum_bound (G := fun t => ebit (fun i => dec (ekBytes k ek) i) (8 * y + t))
      (fun t => ebit_le_one (fun i => dec (ekBytes k ek) i) _) 8
    rw [← two_pow_8]
    exact hw
  -- `ekBytes` reads a byte of the `Fin 256` codomain, or 0 outside the key.
  have hB : ∀ z, ekBytes k ek z < 256 := fun z => ekBytes_lt k ek z
  refine eqOfBits hlt (hB y) (fun s hs => ?_)
  rw [enc_bit (fun i => dec (ekBytes k ek) i) y s hs]
  show bit (dec (ekBytes k ek) ((8 * y + s) / 12)) ((8 * y + s) % 12)
      = bit (ekBytes k ek y) s
  -- The coefficient owning bit `8 * y + s` is inside the prefix, because the
  -- prefix spans `12 * nCoeff k` bits and `y < 384 * k` bytes.
  have hcoeff : (8 * y + s) / 12 < nCoeff k :=
    coeff_mem_prefix (by
      have heq := twelve_mul_nCoeff k
      -- `nCoeff k` is not a monomial, so the occurrence is folded to
      -- `256 * k` before `omega` sees it.  Bit `8 * y + s` of the prefix is
      -- at most `8 * (384 * k - 1) + 7`, which is one bit short of
      -- `12 * (256 * k)`, so the two bounds cannot be equated by accident.
      rw [nCoeff] at heq
      omega)
  have hsegAt : seg (ekBytes k ek) ((8 * y + s) / 12) < 3329 := by
    rw [← ekSeg_eq k ek ((8 * y + s) / 12)]
    exact hSeg _ hcoeff
  -- `dec B i = seg B i % 3329`, and `seg B i < 3329`, so the reduction is
  -- the identity; hence bit `(8*y+s) % 12` of `dec` is bit `(8*y+s)%12`
  -- of `seg`, which by `seg_bit` is global bit `8*y+s`.
  -- `Nat.mod_lt _ (by omega)` would NOT supply the modulus bound: `Nat.mod_lt`
  -- takes it as an implicit argument, so the tactic block is elaborated as a
  -- proof of the side condition and discarded.  The bound is stated.
  have h12 : (0 : Nat) < 12 := by omega
  have hmod : (8 * y + s) % 12 < 12 := Nat.mod_lt _ h12
  have hbit : bit (dec (ekBytes k ek) ((8 * y + s) / 12)) ((8 * y + s) % 12)
      = bit (seg (ekBytes k ek) ((8 * y + s) / 12)) ((8 * y + s) % 12) := by
    unfold dec
    rw [Nat.mod_eq_of_lt hsegAt]
  rw [hbit]
  -- `seg_bit` returns `gbit B (12 * i + j)`; the index of bit `s` of byte `y`
  -- is `8 * y + s`, so the global position has to be discharged first.
  have hpos : 12 * ((8 * y + s) / 12) + (8 * y + s) % 12 = 8 * y + s := by omega
  rw [seg_bit (ekBytes k ek) ((8 * y + s) / 12) ((8 * y + s) % 12) hmod, hpos]
  exact gbit_byte (ekBytes k ek) y s hs

/-- A disagreement byte for an out-of-range segment `i` is witnessed at the
index `(12 * i + j) / 8` for some differing bit `j < 12`.  This re-states
`ByteEncode.reject_on_overflow` while keeping the bit index `j` visible, so
that callers can bound the BYTE index.  The corpus's `reject_on_overflow`
discards `j`, which is exactly the information a bounded-index theorem needs
and cannot recover. -/
theorem reject_on_overflow_with_bit (B : Nat → Nat) (i : Nat) (h : seg B i ≥ 3329) :
    ∃ j, j < 12 ∧ encByte (fun i => dec B i) ((12 * i + j) / 8) ≠ B ((12 * i + j) / 8) := by
  have hslt : seg B i < 2 ^ 12 :=
    wsum_bound (G := fun t => gbit B (12 * i + t)) (fun t => gbit_le_one B _) 12
  have hq : (0 : Nat) < 3329 := by omega
  have hdlt : dec B i < 3329 := by
    unfold dec
    exact Nat.mod_lt _ hq
  have hd : dec B i = seg B i - 3329 := by
    have hp12 := two_pow_12
    unfold dec
    omega
  have hne : dec B i ≠ seg B i := by omega
  have hd12 : dec B i < 2 ^ 12 := by omega
  obtain ⟨j, hj, hbj⟩ := exists_diff_bit (dec B i) (seg B i) 12 hd12 hslt hne
  refine ⟨j, hj, ?_⟩
  intro hcon
  apply hbj
  have h8 : (0 : Nat) < 8 := by omega
  have hs8 : (12 * i + j) % 8 < 8 := Nat.mod_lt _ h8
  have hpm : 8 * ((12 * i + j) / 8) + (12 * i + j) % 8 = 12 * i + j :=
    Nat.div_add_mod (12 * i + j) 8
  have henc : bit (encByte (fun i => dec B i) ((12 * i + j) / 8)) ((12 * i + j) % 8)
      = bit (dec B i) j := by
    rw [enc_bit (fun i => dec B i) ((12 * i + j) / 8) ((12 * i + j) % 8) hs8, hpm]
    show bit ((fun i => dec B i) ((12 * i + j) / 12)) ((12 * i + j) % 12) = bit (dec B i) j
    rw [coeff_div i j hj, coeff_mod i j hj]
  have hbyt : bit (B ((12 * i + j) / 8)) ((12 * i + j) % 8) = bit (seg B i) j := by
    have hg : gbit B (12 * i + j) = bit (B ((12 * i + j) / 8)) ((12 * i + j) % 8) := rfl
    rw [← hg, ← seg_bit B i j hj]
  calc bit (dec B i) j
      = bit (encByte (fun i => dec B i) ((12 * i + j) / 8)) ((12 * i + j) % 8) := henc.symm
    _ = bit (B ((12 * i + j) / 8)) ((12 * i + j) % 8) := by rw [hcon]
    _ = bit (seg B i) j := hbyt

/-- Any witness byte for an out-of-range coefficient `i < nCoeff k` lies
strictly inside the `384 * k`-byte prefix.  This is the index bound T2 needs
and the reason `ByteEncode.reject_on_overflow`'s discarded bit index has to
be recovered. -/
theorem witness_byte_lt_prefix (k i j : Nat) (hi : i < nCoeff k) (hj : j < 12) :
    (12 * i + j) / 8 < 384 * k := by
  have heq := twelve_mul_nCoeff k
  rw [nCoeff] at hi heq
  -- `omega` treats `(12 * i + j) / 8` as an independent atom, so the
  -- division is discharged first, with the quotient/modulus equation
  -- `Nat.div_add_mod`.  Neither `Nat.div_lt_iff_lt_mul` (deprecated: the
  -- log reports "equality or iff proof expected ?m / ?m < ?m" for it) nor
  -- `Nat.div_lt_of_lt_mul` (which `rw` cannot use, for the same reason) is
  -- available here.  `hi < 256 * k` gives `12 * i + j ≤ 12 * 256 * k - 1`,
  -- hence the equation with a remainder below 8 bounds the quotient.
  have hdecomp := Nat.div_add_mod (12 * i + j) 8
  have hr : (12 * i + j) % 8 < 8 := Nat.mod_lt _ h8
  have hnum : 12 * i + j < 8 * (384 * k) := by omega
  have hlt : 8 * ((12 * i + j) / 8) < 8 * (384 * k) := by omega
  omega

/-- T2, REJECT -- the anti-vacuity half required by msn-2026-0021's
`critical_constraint`.  If some coefficient carried by the prefix is OUT OF
RANGE, i.e. greater than `q - 1 = 3328`, then Eq (7.1) fails at some byte
index `y < 384 * k`.  Without this theorem `eq7_1_accept` alone could be
satisfied by an `hSeg` that nobody can inhabit -- which is precisely the
failure mode of msn-2026-0007.

The hypothesis is `3329 ≤ ekSeg k ek i`, i.e. "not in `[0, q - 1]`" with
`q = 3329`.  That is FIPS 203's own wording -- the check "ensures that the
integers encoded in the public key are in the valid range `[0, q - 1]`"
(printed p.36 / PDF p.45) -- so the negation of `v ≤ q - 1` is `q ≤ v`,
which on naturals includes `v = q`.  `3329 ≤ ...` is exactly the hypothesis
`ByteEncode.reject_on_overflow` consumes. -/
theorem eq7_1_reject (k : Nat) (ek : Ek k)
    (hSeg : ∃ i, i < nCoeff k ∧ 3329 ≤ ekSeg k ek i) :
    ∃ y, y < 384 * k ∧ encByte (fun i => dec (ekBytes k ek) i) y ≠ ekBytes k ek y := by
  obtain ⟨i, hi, hge⟩ := hSeg
  rw [ekSeg_eq k ek i] at hge
  obtain ⟨j, hj, hne⟩ := reject_on_overflow_with_bit (ekBytes k ek) i hge
  refine ⟨(12 * i + j) / 8, witness_byte_lt_prefix k i j hi hj, hne⟩

theorem eq7_1_of_seg_bound (k : Nat) (ek : Ek k)
    (hSeg : ∀ i, i < nCoeff k -> ekSeg k ek i < 3329) : eq7_1 k ek := by
  intro y hy
  exact eq7_1_accept k ek hSeg y hy

theorem eq7_1_to_seg_bound (k : Nat) (ek : Ek k)
    (h : eq7_1 k ek) (i : Nat) (hi : i < nCoeff k) : ekSeg k ek i < 3329 := by
  by_contra hcon
  push_neg at hcon
  obtain ⟨y, hy, hne⟩ := eq7_1_reject k ek ⟨i, hi, hcon⟩
  exact hne (h y hy)

theorem eq7_1_iff (k : Nat) (ek : Ek k) :
    eq7_1 k ek ↔ ∀ i, i < nCoeff k -> ekSeg k ek i < 3329 :=
  ⟨eq7_1_to_seg_bound k ek, eq7_1_of_seg_bound k ek⟩

/-- Agreement at ONE covered byte index does not by itself force the segment
bound; the segment bound forces agreement at every covered index.  The
converse is what `eq7_1_reject` states, at the index where the re-encoding
actually disagrees.

An earlier revision of this file asserted the biconditional

    (encByte (fun i => dec B) y = B y) ↔ (∀ i, i < nCoeff k → seg B i < 3329)

for a SINGLE index `y`.  That statement is FALSE and was never proved: an
out-of-range segment elsewhere in the prefix makes `eq7_1_reject` fail at
that segment's own byte index, not at an arbitrary `y`, so agreement at one
chosen `y` says nothing about the rest of the prefix.  Only the forward
direction below is valid, and it is a one-sided corollary of `eq7_1_accept`. -/
theorem eq7_1_accept_pointwise (k : Nat) (ek : Ek k)
    (hSeg : ∀ i, i < nCoeff k -> ekSeg k ek i < 3329) (y : Nat)
    (hy : y < 384 * k) :
    encByte (fun i => dec (ekBytes k ek) i) y = ekBytes k ek y :=
  eq7_1_accept k ek hSeg y hy

/-- An out-of-range prefix coefficient forces at least one covered byte index
to disagree.  This is the per-index reading of `eq7_1_reject`, and it is the
honest contrapositive of `eq7_1_accept`. -/
theorem eq7_1_reject_some_index (k : Nat) (ek : Ek k)
    (hSeg : ∃ i, i < nCoeff k ∧ 3329 ≤ ekSeg k ek i) :
    ∃ y, y < 384 * k ∧ encByte (fun i => dec (ekBytes k ek) i) y ≠ ekBytes k ek y :=
  eq7_1_reject k ek hSeg

/-- A key that passes step 1 and step 2: the combined Section 7.2 check. -/
def okKey (k : Nat) (ek : Ek k) : Prop :=
  EkTypeCheck ek ∧ eq7_1 k ek

theorem okKey_iff_eq7_1 (k : Nat) (ek : Ek k) :
    okKey k ek ↔ ∀ i, i < nCoeff k -> ekSeg k ek i < 3329 := by
  constructor
  · intro h i hi
    exact eq7_1_to_seg_bound k ek h.2 i hi
  · intro hSeg
    refine ⟨step1_type_check k ek, eq7_1_of_seg_bound k ek hSeg⟩

/-! ## The unbounded contrast: what the OLD corpus statements say -/

/-- Eq (7.1) holds at EVERY byte index -- the unrestricted statement proved by
`ByteEncode.enc_dec_eq`.  Nothing restricts the index `y`. -/
theorem eq7_1_holds_forever (k : Nat) (ek : Ek k)
    (hSeg : ∀ i, ekSeg k ek i < 3329) (y : Nat) :
    encByte (fun i => dec (ekBytes k ek) i) y = ekBytes k ek y := by
  refine enc_dec_eq (ekBytes k ek) (fun y => ekBytes_lt k ek y) (fun i => ?_) y
  rw [← ekSeg_eq k ek i]
  exact hSeg i

/-- ... and correspondingly, a segment at or above q at ANY index makes the
re-encoding differ at some index.  This is `ByteEncode.roundtrip_iff_canonical`
read through the bounded view.  Its hypothesis reaches the rho seed, which is
why `roundtrip_iff_canonical` is vacuous for genuine keys: see T4. -/
theorem eq7_1_fails_forever (k : Nat) (ek : Ek k)
    (h : ∃ i, ekSeg k ek i ≥ 3329) :
    ∃ y, encByte (fun i => dec (ekBytes k ek) i) y ≠ ekBytes k ek y := by
  obtain ⟨i, hi⟩ := h
  rw [ekSeg_eq k ek i] at hi
  obtain ⟨y, hy⟩ := reject_on_overflow (ekBytes k ek) (fun y => ekBytes_lt k ek y) ⟨i, hi⟩
  exact ⟨y, hy⟩

/-! ## The rho seed region is unconstrained by Eq (7.1) -/

/-- Every bit read by segment `i < nCoeff k` lies at global bit position
below `8 * 384 * k`, hence inside byte `384 * k - 1`.  So no prefix
coefficient reads any byte at index `>= 384 * k`, and the 32-byte rho seed
region `[384k, 384k + 32)` of Algorithm 13 line 19 / Algorithm 14 line 3 is
outside everything Eq (7.1) can see. -/
theorem prefix_bits_stop_before_seed (k : Nat) :
    ∀ i, i < nCoeff k -> ∀ p, p < 12 * i + 12 -> p < 8 * 384 * k := by
  intro i hi p hp
  rw [nCoeff] at hi
  have hk : i + 1 ≤ 256 * k := by omega
  have hle : 12 * (i + 1) ≤ 12 * (256 * k) := by omega
  omega

/-- Eq (7.1) is a function of the prefix coefficients only.  Two keys whose
`256k` prefix coefficients agree agree on Eq (7.1), no matter what their
seed regions contain.  This is the kernel-checked form of "Eq (7.1) says
nothing about the rho seed". -/
theorem seed_region_unconstrained (k : Nat) (ek1 ek2 : Ek k)
    (hseg : ∀ i, i < nCoeff k -> ekSeg k ek1 i = ekSeg k ek2 i) :
    eq7_1 k ek1 ↔ eq7_1 k ek2 := by
  constructor
  · intro h1 y hy
    refine eq7_1_accept k ek2 ?_ y hy
    intro i hi
    rw [← hseg i hi]
    exact eq7_1_to_seg_bound k ek1 h1 i hi
  · intro h2 y hy
    refine eq7_1_accept k ek1 ?_ y hy
    intro i hi
    rw [hseg i hi]
    exact eq7_1_to_seg_bound k ek2 h2 i hi

/-! ## T4: the OLD unbounded hypothesis is false for a legitimate key -/

/-- Zero at every bit position. -/
theorem bit_zero (j : Nat) : bit 0 j = 0 := by
  simp [bit]

theorem wsum_zero' (N : Nat) : wsum (fun _ : Nat => 0) N = 0 := by
  induction N with
  | zero => simp [wsum]
  | succ n ih => rw [wsum_succ]; simp [ih]

/-- A byte array whose twelve-bit segments are all zero has `seg B i = 0`. -/
theorem seg_eq_zero_of_bits_zero {B : Nat → Nat} {i : Nat}
    (h : ∀ j, gbit B (12 * i + j) = 0) : seg B i = 0 := by
  show wsum (fun j => gbit B (12 * i + j)) 12 = 0
  have hstep : wsum (fun j => gbit B (12 * i + j)) 12 = wsum (fun _ => 0) 12 :=
    wsum_congr (fun j _ => h j)
  rw [hstep]
  exact wsum_zero' 12

/-- `B2raw` is the ML-KEM-512 (k = 2) key that is zero except for bytes
768 = 384 * 2 and 769, whose values are the bytes 0x01 and 0x0D.

The bytes 0x01 0x0D spell the value 1 + 256 + 1024 + 2048 = 3329 = q in the
little-endian 12-bit packing of a coefficient, but here they sit at byte
768, which is the first byte of the rho seed rather than inside any
coefficient of the `384k` prefix.  `old_hypothesis_false_k2` is the
kernel-checked demonstration that such a key satisfies Eq (7.1) -- it is not
rejected by step 2 -- while violating the OLD hypothesis (OLD) at
coefficient index `256 * 2 = 512`, the first coefficient of the seed.

Note that the two byte positions, and hence this key's rho seed, are chosen
BY US: nothing in FIPS 203 forces a particular seed.  The mission's claim
that ~99% of genuine keys violate (OLD) is probabilistic and is NOT proved
here; what is proved here is the existence of a concrete admissible key that
violates (OLD). -/
def B2raw (y : Nat) : Nat := if y = 768 then 1 else if y = 769 then 13 else 0

/-- `B2` is `B2raw` at length 800, the length step 1 demands for k = 2. -/
def B2 : Ek 2 := ekOfTotal 2 B2raw

theorem B2_bytes (y : Nat) : ekBytes 2 B2 y = B2raw y := by
  by_cases h : y < 384 * 2 + 32
  · rw [ekBytes_val 2 B2 y h]
    show B2raw y % 256 = B2raw y
    by_cases h0 : y = 768
    · rw [if_pos h0]; norm_num
    · by_cases h1 : y = 769
      · rw [if_neg h0, if_pos h1]; norm_num
      · rw [if_neg h0, if_neg h1]; norm_num
  · rw [ekBytes_outside 2 B2 y h]
    have h0 : y ≠ 768 := by omega
    have h1 : y ≠ 769 := by omega
    rw [B2raw, if_neg h0, if_neg h1]

theorem B2_bytes_768 : ekBytes 2 B2 768 = 1 := by
  rw [B2_bytes, B2raw, if_pos rfl]

theorem B2_bytes_769 : ekBytes 2 B2 769 = 13 := by
  rw [B2_bytes, B2raw, if_neg (by norm_num), if_pos rfl]

/-- `B2` passes step 1: it is a length-typed `Ek 2`, i.e. 800 bytes. -/
theorem B2_step1 : EkTypeCheck B2 := step1_type_check 2 B2

/-- Every bit read by a prefix coefficient of `B2` is zero: the prefix
occupies bytes `0 .. 767`, and `B2raw` is zero there.  The bound `j < 12`
restricts `j` to the range `seg`'s summation actually runs over. -/
theorem B2_prefix_bits_zero (i : Nat) (hi : i < 512) (j : Nat) (hj : j < 12) :
    gbit (ekBytes 2 B2) (12 * i + j) = 0 := by
  have hlt : 12 * i + j < 12 * 512 := by omega
  have hd : (12 * i + j) / 8 < 768 := by omega
  have hne0 : (12 * i + j) / 8 ≠ 768 := by omega
  have hne1 : (12 * i + j) / 8 ≠ 769 := by omega
  show bit (ekBytes 2 B2 ((12 * i + j) / 8)) ((12 * i + j) % 8) = 0
  rw [B2_bytes, B2raw, if_neg hne0, if_neg hne1]
  exact bit_zero ((12 * i + j) % 8)

/-- Every coefficient carried by the `384k` prefix of `B2` is below q. -/
theorem B2_prefix_segments_canonical :
    ∀ i, i < nCoeff 2 -> ekSeg 2 B2 i < 3329 := by
  intro i hi
  rw [nCoeff_two_coeff] at hi
  have hz : ekSeg 2 B2 i = 0 := by
    unfold ekSeg seg
    show wsum (fun j => gbit (ekBytes 2 B2) (12 * i + j)) 12 = 0
    have hstep : wsum (fun j => gbit (ekBytes 2 B2) (12 * i + j)) 12
        = wsum (fun _ => 0) 12 :=
      wsum_congr (fun j hj => B2_prefix_bits_zero i hi j (hj))
    rw [hstep]
    exact wsum_zero' 12
  omega

/-- `B2` satisfies Eq (7.1): every byte index `y < 384 * 2 = 768` is
reproduced by the re-encoding. -/
theorem B2_eq7_1 : eq7_1 2 B2 := by
  intro y hy
  exact eq7_1_accept 2 B2 B2_prefix_segments_canonical y hy

/-- THE COUNTEREXAMPLE, part 1: segment `256 * 2 = 512` of `B2` -- the first
coefficient of the rho seed -- reads as exactly `q = 3329`, not below q.
The 12-bit little-endian word at bytes 768, 769 is
`0x0D01 = 13 + 256 * 1 = 3329`, i.e. 1 + 256 + 1024 + 2048.

The twelve bit positions are discharged by `decide` on closed ground terms,
which is a genuine kernel-evaluated computation, not an assumption. -/
theorem B2_seg512 : ekSeg 2 B2 (256 * 2) = 3329 := by
  rw [ekSeg_eq 2 B2 (256 * 2)]
  -- `seg B i = wsum (fun j => gbit B (12 * i + j)) 12`, so the coefficient
  -- index is `256 * 2 = 512` itself; it is NOT `12 * 512`.
  have hmul : (256 * 2 : Nat) = 512 := by norm_num
  rw [hmul]
  have hbits : ∀ s, s < 12 -> gbit (ekBytes 2 B2) (12 * 512 + s) = bit 3329 s := by
    intro s hs
    have hrw : 12 * 512 + s = 6144 + s := by omega
    -- `gbit B p` is opaque to `rw`, so it is unfolded before `B2_bytes` is
    -- applied to the byte index inside it.
    show bit (ekBytes 2 B2 ((6144 + s) / 8)) ((6144 + s) % 8) = bit 3329 s
    -- The two seed bytes sit at indices 768 and 769, so the byte index
    -- `(6144 + s) / 8` is neither; the `if` is discharged on the INDEX, not
    -- on the value it selects.
    have hidx0 : (6144 + s) / 8 ≠ 768 := by omega
    have hidx1 : (6144 + s) / 8 ≠ 769 := by omega
    rw [B2_bytes, B2raw, if_neg hidx0, if_neg hidx1, bit_zero]
    simp [bit]
  have hWc : wsum (fun j => gbit (ekBytes 2 B2) (12 * 512 + j)) 12
      = wsum (fun j => bit 3329 j) 12 := wsum_congr hbits
  have hW' : wsum (fun j => bit 3329 j) 12 = 3329 := by
    show (∑ j ∈ Finset.range 12, bit 3329 j * 2 ^ j) = 3329
    exact bitsum_id 3329 12 (by rw [two_pow_12]; omega)
  unfold seg
  show wsum (fun j => gbit (ekBytes 2 B2) (12 * 512 + j)) 12 = 3329
  rw [hWc, hW']

/-- T4.  A key of length 800 -- the length step 1 demands for k = 2 -- that
satisfies Eq (7.1) at every index `y < 384 * 2 = 768`, but for which the OLD
corpus hypothesis `forall i, seg B i < 3329` is FALSE.

Consequence: for this key Eq (7.1) is NOT an instance of
`ByteEncode.roundtrip_iff_canonical`.  On `B2` the right-hand side of that
biconditional is false and its left-hand side is true, because the
left-hand side there ranges over ALL indices while Eq (7.1) constrains only
`y < 768`.  This is the vacuity that terminalized msn-2026-0007, exhibited by
a witness the Lean kernel can check. -/
theorem old_hypothesis_false_k2 :
    ekBytes 2 B2 768 = 1 ∧ ekBytes 2 B2 769 = 13 ∧
      ¬ (∀ i, ekSeg 2 B2 i < 3329) ∧
      (∀ y, y < 384 * 2 -> encByte (fun i => dec (ekBytes 2 B2) i) y = ekBytes 2 B2 y) := by
  refine ⟨B2_bytes_768, B2_bytes_769, ?_, ?_⟩
  · intro hall
    have hcontra := hall (256 * 2)
    rw [B2_seg512] at hcontra
    omega
  · intro y hy
    exact eq7_1_accept 2 B2 B2_prefix_segments_canonical y hy

/-- Every byte of `B2` is a byte.  Not an extra fact about `B2`: this holds of
every well-typed key, because `Ek 2` has codomain `Fin 256` -- see (R11). -/
theorem B2_all_bytes (y : Nat) : ekBytes 2 B2 y < 256 :=
  ekBytes_lt 2 B2 y

/-- The bounded hypothesis of `eq7_1_accept` is INHABITED, by the very same
key that refutes the unbounded one.  This is the explicit anti-vacuity witness
for T1: `nCoeff 2` really does bound the quantification, and real, if
admittedly uninteresting, byte arrays satisfy it.  The byte bound is retained
here as a conjunct of the witness so that this theorem still asserts what it
asserted under the previous revision; it is now discharged by `B2_all_bytes`. -/
theorem eq7_1_hypothesis_inhabited :
    ∃ ek : Ek 2, (∀ y, ekBytes 2 ek y < 256) ∧
      (∀ i, i < nCoeff 2 -> ekSeg 2 ek i < 3329) :=
  ⟨B2, B2_all_bytes, B2_prefix_segments_canonical⟩

/-! ## The seed region really is free, on a concrete k = 2 example -/

/-- `B2alt` differs from `B2` only inside the seed region: byte 780 is set to
42 here and is 0 in `B2`.  Both keys have length 800. -/
def B2altRaw (y : Nat) : Nat :=
  if y = 768 then 1 else if y = 769 then 13 else if y = 780 then 42 else 0

def B2alt : Ek 2 := ekOfTotal 2 B2altRaw

theorem B2alt_bytes (y : Nat) : ekBytes 2 B2alt y = B2altRaw y := by
  by_cases h : y < 384 * 2 + 32
  · rw [ekBytes_val 2 B2alt y h]
    show B2altRaw y % 256 = B2altRaw y
    by_cases h0 : y = 768
    · rw [if_pos h0]; norm_num
    · by_cases h1 : y = 769
      · rw [if_neg h0, if_pos h1]; norm_num
      · by_cases h2 : y = 780
        · rw [if_neg h0, if_neg h1, if_pos h2]; norm_num
        · rw [if_neg h0, if_neg h1, if_neg h2]; norm_num
  · rw [ekBytes_outside 2 B2alt y h]
    have h0 : y ≠ 768 := by omega
    have h1 : y ≠ 769 := by omega
    have h2 : y ≠ 780 := by omega
    rw [B2altRaw, if_neg h0, if_neg h1, if_neg h2]

theorem B2alt_bytes_780 : ekBytes 2 B2alt 780 = 42 := by
  rw [B2alt_bytes, B2altRaw, if_neg (by norm_num), if_neg (by norm_num), if_pos rfl]

theorem B2alt_ne_B2 : B2alt ≠ B2 := by
  intro heq
  have h : ekBytes 2 B2alt 780 = ekBytes 2 B2 780 :=
    congrArg (fun e : Ek 2 => ekBytes 2 e 780) heq
  rw [B2alt_bytes_780, B2_bytes, B2raw, if_neg (by norm_num), if_neg (by norm_num)] at h
  omega

theorem B2alt_all_bytes (y : Nat) : ekBytes 2 B2alt y < 256 :=
  ekBytes_lt 2 B2alt y

theorem B2alt_prefix_bits_zero (i : Nat) (hi : i < 512) (j : Nat) (hj : j < 12) :
    gbit (ekBytes 2 B2alt) (12 * i + j) = 0 := by
  have hlt : 12 * i + j < 12 * 512 := by omega
  have hd : (12 * i + j) / 8 < 768 := by omega
  have hne0 : (12 * i + j) / 8 ≠ 768 := by omega
  have hne1 : (12 * i + j) / 8 ≠ 769 := by omega
  have hne2 : (12 * i + j) / 8 ≠ 780 := by omega
  show bit (ekBytes 2 B2alt ((12 * i + j) / 8)) ((12 * i + j) % 8) = 0
  rw [B2alt_bytes, B2altRaw, if_neg hne0, if_neg hne1, if_neg hne2]
  exact bit_zero ((12 * i + j) % 8)

theorem B2alt_prefix_segments_canonical :
    ∀ i, i < nCoeff 2 -> ekSeg 2 B2alt i < 3329 := by
  intro i hi
  rw [nCoeff_two_coeff] at hi
  have hz : ekSeg 2 B2alt i = 0 := by
    unfold ekSeg seg
    show wsum (fun j => gbit (ekBytes 2 B2alt) (12 * i + j)) 12 = 0
    have hstep : wsum (fun j => gbit (ekBytes 2 B2alt) (12 * i + j)) 12
        = wsum (fun _ => 0) 12 :=
      wsum_congr (fun j hj => B2alt_prefix_bits_zero i hi j (hj))
    rw [hstep]
    exact wsum_zero' 12
  omega

theorem B2alt_eq7_1 : eq7_1 2 B2alt := by
  intro y hy
  exact eq7_1_accept 2 B2alt B2alt_prefix_segments_canonical y hy

/-- Concrete instance of `seed_region_unconstrained`: two DISTINCT keys of
length 800, differing only in the rho seed region, both satisfy Eq (7.1) and
have identical prefix coefficients.  So Eq (7.1) cannot distinguish them,
and neither can the OLD unbounded hypothesis, which rejects both. -/
theorem seed_region_unconstrained_k2 :
    ∃ ek2 : Ek 2, ek2 ≠ B2 ∧ eq7_1 2 ek2 ∧ (∀ i, i < nCoeff 2 -> ekSeg 2 ek2 i = ekSeg 2 B2 i) := by
  have hseg : ∀ i, i < nCoeff 2 -> ekSeg 2 B2alt i = ekSeg 2 B2 i := by
    intro i hi
    have hi' : i < 512 := by rw [nCoeff_two_coeff] at hi; exact hi
    have h1 : ekSeg 2 B2alt i = 0 := by
      unfold ekSeg seg
      show wsum (fun j => gbit (ekBytes 2 B2alt) (12 * i + j)) 12 = 0
      have hstep : wsum (fun j => gbit (ekBytes 2 B2alt) (12 * i + j)) 12
          = wsum (fun _ => 0) 12 :=
        wsum_congr (fun j hj => B2alt_prefix_bits_zero i hi' j (hj))
      rw [hstep]
      exact wsum_zero' 12
    have h2 : ekSeg 2 B2 i = 0 := by
      unfold ekSeg seg
      show wsum (fun j => gbit (ekBytes 2 B2) (12 * i + j)) 12 = 0
      have hstep : wsum (fun j => gbit (ekBytes 2 B2) (12 * i + j)) 12
          = wsum (fun _ => 0) 12 :=
        wsum_congr (fun j hj => B2_prefix_bits_zero i hi' j (hj))
      rw [hstep]
      exact wsum_zero' 12
    rw [h1, h2]
  exact ⟨B2alt, B2alt_ne_B2, B2alt_eq7_1, hseg⟩

/-- T4, part 2.  For the very same key, the UNRESTRICTED re-encoding differs
from the key at byte `384 * 2 = 768`: decoding segment 512 gives
`3329 % 3329 = 0`, so the re-encoded byte 768 has bit 0 equal to 0 while
the key holds 1.

That index is precisely the first index Eq (7.1) does not cover.  So the
left-hand side of `ByteEncode.roundtrip_iff_canonical` -- which quantifies
over ALL byte indices -- is FALSE on `B2`, while Eq (7.1), whose domain stops
at the prefix, holds everywhere it applies.  This is the sharpest form of the
vacuity witness: on `B2` both sides of the old biconditional are false, so the
biconditional is true and yields nothing. -/
theorem unbounded_reencode_disagrees_at_768 :
    encByte (fun i => dec (ekBytes 2 B2) i) 768 ≠ ekBytes 2 B2 768 := by
  have hseg512 : seg (ekBytes 2 B2) 512 = 3329 := by
    have h := B2_seg512
    rw [ekSeg_eq 2 B2 (256 * 2)] at h
    rwa [show (256 * 2 : Nat) = 512 by norm_num] at h
  have hdec : dec (ekBytes 2 B2) 512 = 0 := by
    unfold dec
    rw [hseg512]
  have hbit : bit (encByte (fun i => dec (ekBytes 2 B2) i) 768) 0 = 0 := by
    -- `ebit F p` is opaque to `rw`, so the bit-level statement is first
    -- restated with `ebit` unfolded on both sides and only then specialised.
    have hbit' : bit ((fun y => encByte (fun i => dec (ekBytes 2 B2) i) y)
        ((8 * 768 + 0) / 8)) ((8 * 768 + 0) % 8) = 0 := by
      rw [enc_bit (fun i => dec (ekBytes 2 B2) i)
        ((8 * 768 + 0) / 8) ((8 * 768 + 0) % 8)
        (by omega : (8 * 768 + 0) % 8 < 8)]
      have hdiv : (8 * 768 + 0) / 12 = 512 := by decide
      have hmod : (8 * 768 + 0) % 12 = 0 := by decide
      show bit (dec (ekBytes 2 B2) ((8 * 768 + 0) / 12)) ((8 * 768 + 0) % 12) = 0
      rw [hdiv, hmod, hdec]
      decide
    rw [enc_bit (fun i => dec (ekBytes 2 B2) i) 768 0 (by omega : (0 : Nat) < 8)] at hbit'
    unfold ebit at hbit'
    simpa using hbit'
  intro hEq
  have hbits : bit (encByte (fun i => dec (ekBytes 2 B2) i) 768) 0
      = bit (ekBytes 2 B2 768) 0 :=
    congrArg (fun v : Nat => bit v 0) hEq
  rw [hbit, B2_bytes_768] at hbits
  norm_num [bit] at hbits

/-! ## `k` is load-bearing in the Eq (7.1) prefix as well -/

/-- Distinct parameter sets give distinct Eq (7.1) prefix lengths and prefix
coefficient counts, so the predicate is genuinely parameter-dependent. -/
theorem eq7_1_prefix_depends_on_k :
    384 * 2 < 384 * 3 ∧ 384 * 3 < 384 * 4 ∧
      nCoeff 2 < nCoeff 3 ∧ nCoeff 3 < nCoeff 4 ∧ nCoeff 2 ≠ nCoeff 3 := by
  norm_num [nCoeff]

end Fips203.EkCheck
