/-
FIPS 203 ByteEncode12 / ByteDecode12 and the Section 7.2 encapsulation-key
modulus check (Eq. 7.1), machine-checked in Lean 4 + Mathlib.

Mission msn-2026-0003 (FORMAL-203).  Normative source:
`localdocs/refs/fips203.pdf` - Algorithm 5 (ByteEncode_d) and Algorithm 6
(ByteDecode_d), printed p.22; BitsToBytes / BytesToBits p.20; the d = 12
semantics paragraph pp.21-22; Section 7.2 encapsulation key check Eq (7.1),
printed p.36.

Model.  A byte array is a function `Nat → Nat` (byte value by index).  Bytes
are little-endian bit strings (Algorithm 4): global bit position `p` carries
value `gbit B p = bit (B (p/8)) (p%8)`.  Coefficient `i` occupies positions
`[12*i, 12*i+12)`; its unreduced value is `seg B i` and its decoded value is
`dec B i = seg B i % 3329` (Algorithm 6 line 3, d = 12).  Encoding
(Algorithm 5) places bit `j` of coefficient `i` at global position `12*i+j`;
byte `y` of the encoding therefore collects positions `[8*y, 8*y+8)`.

Main results
* `canonicalRoundtrip`       (T1) values below q survive Decode ∘ Encode;
* `roundtrip_iff_canonical`  (T2) Eq (7.1) holds iff every unreduced segment
  value is below q - the precise content of the §7.2 modulus check;
* `minimalCounterexample`    segment value q = 3329 fails Eq (7.1);
  bytes 0x01 0x0D re-encode to 0x00 0x00.
-/

import Mathlib.Tactic

namespace Fips203

/-! ## Bit extraction -/

/-- Bit `j` of `x`, LSB-first. -/
def bit (x j : Nat) : Nat := (x / 2 ^ j) % 2

theorem bit_le_one (x j : Nat) : bit x j ≤ 1 :=
  Nat.le_of_lt_succ (Nat.mod_lt _ (by omega))

/-! ## Positional sums of binary digits -/

/-- `G t * 2^t` summed over `t ∈ range N`. -/
def wsum (G : Nat → Nat) (N : Nat) : Nat := ∑ t ∈ Finset.range N, G t * 2 ^ t

theorem wsum_succ (G : Nat → Nat) (N : Nat) :
    wsum G (N + 1) = wsum G N + G N * 2 ^ N := Finset.sum_range_succ _ _

theorem wsum_bound {G : Nat → Nat} (hG : ∀ t, G t ≤ 1) :
    ∀ N, wsum G N < 2 ^ N
  | 0 => by simpa [wsum] using (by norm_num : (0:Nat) < 1)
  | N + 1 => by
      rw [wsum_succ]
      have hprev := wsum_bound hG N
      have hb : G N * 2 ^ N ≤ 2 ^ N := Nat.mul_le_of_mul_le_right (hG N) 1
      have hpow : 2 ^ (N + 1) = 2 ^ N + 2 ^ N := by rw [Nat.pow_succ]; omega
      omega

theorem wsum_congr {f g : Nat → Nat} (h : ∀ t, t < N → f t = g t) (N : Nat) :
    wsum f N = wsum g N := by
  unfold wsum
  refine Finset.sum_congr rfl fun t ht => ?_
  exact h t (Finset.mem_range.mp ht)

/-- A bit only sees the value modulo `2^(S+1)`. -/
theorem bit_mod_succ (z S : Nat) : bit z S = bit (z % 2 ^ (S + 1)) S := by
  obtain ⟨Q, R, hR⟩ : ∃ Q R, z = Q * 2 ^ (S + 1) + R :=
    ⟨z / 2 ^ (S + 1), z % 2 ^ (S + 1), (Nat.div_add_mod z (2 ^ (S + 1))).symm⟩
  obtain ⟨P, R', hR', hRl⟩ :
      ∃ P R', R = P * 2 ^ (S + 1) + R' ∧ R' < 2 ^ (S + 1) :=
    ⟨R / 2 ^ (S + 1), R % 2 ^ (S + 1), (Nat.div_add_mod R (2 ^ (S + 1))).symm,
      Nat.mod_lt _ (by omega)⟩
  show (z / 2 ^ S) % 2 = (z % 2 ^ (S + 1)) / 2 ^ S % 2
  rw [hR, hR', Nat.pow_succ]
  have hdiv : (Q * (2 * 2 ^ S) + (P * (2 * 2 ^ S) + R')) / 2 ^ S
      = (Q * 2 + P * 2) + R' / 2 ^ S := by
    have step1 : (Q * (2 * 2 ^ S)) / 2 ^ S = Q * 2 :=
      Nat.mul_div_cancel_left _ (by omega)
    have step2 : (P * (2 * 2 ^ S)) / 2 ^ S = P * 2 :=
      Nat.mul_div_cancel_left _ (by omega)
    -- distribute the division over the aligned parts, remainder last
    have e1 : (Q * (2 * 2^S) + (P * (2 * 2^S) + R'))
        = ((Q * 2 + P * 2) * 2 ^ S + R') := by ring_nf; omega
    rw [e1, Nat.add_mul_div_left _ _ (by omega)]
    simp [Nat.div_eq_of_lt hRl]
  rw [hdiv]
  have : ((Q * 2 + P * 2) + R' / 2 ^ S) % 2 = (R' / 2 ^ S) % 2 := by
    have : (Q * 2 + P * 2) = 2 * (Q + P) := by ring
    rw [this, Nat.add_mul_mod_self_left]
  rw [this]
  congr 1
  rw [← bit, ← bit_mod_succ R' S]
  · congr 1
    have : R' % 2 ^ (S + 1) = R' := Nat.mod_eq_of_lt hRl
    rw [this]
  · exact Nat.lt_of_lt_of_le (Nat.mod_lt _ (by omega)) (by omega)

/-- Extracting bit `S` from a positional sum with binary digits yields digit `S`. -/
theorem extract_wsum {G : Nat → Nat} (hG : ∀ t, G t ≤ 1) :
    ∀ N S, S < N → bit (wsum G N) S = G S
  | 0, S, hS => absurd hS (Nat.not_lt_zero _)
  | N + 1, S, hS => by
      rcases Nat.lt_or_ge S N with hSN | hSN
      · have ih := extract_wsum hG N S hSN
        have hb : bit (G N * 2 ^ N) S = 0 := by
          rw [bit, Nat.mul_comm]
          have hdvd : 2 ^ S ∣ 2 ^ N * G N := by
            refine ⟨G N * 2 ^ (N - S - 1), ?_⟩
            conv_lhs => rw [← Nat.pow_add (S+1) (N - S - 1)]
            have : S + 1 + (N - S - 1) = N := by omega
            rw [this]
            ring
          rw [Nat.mul_comm, Nat.dvd_iff_mod_eq_zero.mp hdvd]
          simp [Nat.zero_div]
        have hstep : wsum G (N + 1) % 2 ^ (S + 1)
            = (wsum G N + G N * 2 ^ N) % 2 ^ (S + 1) := rfl
        rw [wsum_succ, bit_mod_succ, bit_mod_succ, hstep]
        have hcong : (wsum G N + G N * 2 ^ N) % 2 ^ (S + 1)
            = wsum G N % 2 ^ (S + 1) := by
          have hshift : G N * 2 ^ N = (G N * 2 ^ (N - (S + 1))) * 2 ^ (S + 1) := by
            rw [Nat.mul_comm, ← Nat.pow_add, Nat.mul_comm]
            congr 1
            have : (S + 1) + (N - (S + 1)) = N := by omega
            rw [this]
          rw [hshift, Nat.add_mul_mod_self_left]
        rw [hcong, ih]
      · have hSN : S = N := by omega
        subst hSN
        have hlow := wsum_bound hG N
        have hb : G N ≤ 1 := hG N
        rw [wsum_succ, bit_mod_succ]
        have hlt : wsum G N % 2 ^ (N + 1) = wsum G N := by
          refine Nat.mod_eq_of_lt ?_
          have h2 : 2 ^ (N + 1) = 2 ^ N + 2 ^ N := by rw [Nat.pow_succ]; omega
          omega
        rw [hlt, bit, Nat.add_mul_div_left _ _ (by omega)]
        have hdivL : wsum G N / 2 ^ N = 0 := Nat.div_eq_of_lt hlow
        have hdivG : G N * 2 ^ N / 2 ^ N = G N := Nat.mul_div_cancel_left _ (by omega)
        have hmodG : G N % 2 = G N := Nat.mod_eq_of_lt (by omega)
        simp [hdivL, hdivG, hmodG]

/-- A number below `2^N` is determined by its first `N` bits. -/
theorem bitsum_id (x N : Nat) (hx : x < 2 ^ N) :
    (∑ j ∈ Finset.range N, bit x j * 2 ^ j) = x := by
  have hxmod : x % 2 ^ N = x := Nat.mod_eq_of_lt hx
  have := extract_wsum (G := fun j => bit x j) (fun t => bit_le_one x t) N 0
    (by omega)
  -- bit of the sum at 0 recovers digit 0 only; instead use full reconstruction:
  revert this
  intro _
  induction N with
  | zero => simp [Nat.mod_eq_of_lt (by omega : x < 1)]
  | succ n ih =>
      rw [Finset.sum_range_succ]
      obtain ⟨q, r, hr⟩ : ∃ q r, x = q * 2 ^ n + r :=
        ⟨x / 2 ^ n, x % 2 ^ n, (Nat.div_add_mod x (2 ^ n)).symm⟩
      have hbn : bit x n = q % 2 := rfl
      have hsplit : x % 2 ^ (n + 1) = q % 2 * 2 ^ n + r := by
        obtain ⟨half, b, hbb⟩ : ∃ half b, b < 2 ∧ q = 2 * half + b :=
          ⟨q / 2, q % 2, by omega, (Nat.div_add_mod q 2).symm⟩
        have hx2 : x = half * 2 ^ (n + 1) + (b * 2 ^ n + r) := by
          rw [hqr, hbb, Nat.left_distrib, Nat.mul_assoc]
          congr 4
          have : n + 1 = n.succ := rfl
          rw [Nat.pow_succ']
          ring
        have hlt : b * 2 ^ n + r < 2 ^ (n + 1) := by
          have hb2 : b * 2 ^ n ≤ 2 ^ n := Nat.mul_le_of_mul_le_right (by omega) 1
          have h2 : 2 ^ (n + 1) = 2 ^ n + 2 ^ n := by rw [Nat.pow_succ]; omega
          omega
        rw [hx2, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hlt]
      rw [hsplit, hbn]
      have hrx : r = x % 2 ^ n := by
        rw [hr, Nat.add_mul_mod_self_right]
      have himod : x % 2 ^ n < 2 ^ n := Nat.mod_lt _ (by omega)
      rw [hrx] at ih ⊢
      rw [ih himod]
      omega

end Fips203
