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

theorem bit_le_one (x j : Nat) : bit x j ≤ 1 := by
  unfold bit
  exact Nat.le_of_lt_succ (Nat.mod_lt _ (by omega))

theorem two_pow_pos (S : Nat) : 0 < 2 ^ S := by
  induction S with
  | zero => exact Nat.zero_lt_one
  | succ n ih => rw [Nat.pow_succ]; omega

theorem two_pow_8 : (2 : Nat) ^ 8 = 256 := by norm_num

theorem two_pow_12 : (2 : Nat) ^ 12 = 4096 := by norm_num

/-! ## Aligned division / modulo shifts -/

/-- Multiples of `M` vanish under `% M`. -/
private theorem mod_shift (M m r : Nat) : (M * m + r) % M = r % M := by
  rw [Nat.add_comm, Nat.add_mul_mod_self_left]

/-- Aligned division: the multiple of `M` contributes its coefficient. -/
private theorem div_shift {M : Nat} (hM : 0 < M) (m r : Nat) :
    (M * m + r) / M = m + r / M := by
  have hr := Nat.div_add_mod r M
  have hx : M * ((M * m + r) / M) + (M * m + r) % M = M * m + r :=
    Nat.div_add_mod (M * m + r) M
  rw [mod_shift M m r] at hx
  have key : M * ((M * m + r) / M) = M * m + M * (r / M) := by omega
  have hrd : M * (m + r / M) = M * m + M * (r / M) := Nat.right_distrib M m (r / M)
  refine Nat.eq_of_mul_eq_mul_left hM ?_
  rw [hrd]
  exact key

/-! ## Positional sums of binary digits -/

/-- `G t * 2^t` summed over `t ∈ range N`. -/
def wsum (G : Nat → Nat) (N : Nat) : Nat := ∑ t ∈ Finset.range N, G t * 2 ^ t

theorem wsum_succ (G : Nat → Nat) (N : Nat) :
    wsum G (N + 1) = wsum G N + G N * 2 ^ N := by
  unfold wsum
  exact Finset.sum_range_succ _ _

theorem wsum_bound {G : Nat → Nat} (hG : ∀ t, G t ≤ 1) :
    ∀ N, wsum G N < 2 ^ N
  | 0 => by
      have h1 : wsum G 0 = 0 := by unfold wsum; simp
      have h2 : (2 : Nat) ^ 0 = 1 := rfl
      omega
  | N + 1 => by
      rw [wsum_succ]
      have hprev := wsum_bound hG N
      have hpow : (2 : Nat) ^ (N + 1) = 2 ^ N + 2 ^ N := by rw [Nat.pow_succ]; ring
      rcases Nat.lt_or_ge (G N) 1 with h0 | h1
      · have hz : G N = 0 := by omega
        rw [hz, Nat.zero_mul, Nat.zero_add]
        omega
      · have ho : G N = 1 := by omega
        rw [ho, Nat.one_mul]
        omega

theorem wsum_congr {N : Nat} {f g : Nat → Nat} (h : ∀ t, t < N → f t = g t) :
    wsum f N = wsum g N := by
  unfold wsum
  refine Finset.sum_congr rfl fun t ht => ?_
  exact congrArg (fun v => v * 2 ^ t) (h t (Finset.mem_range.mp ht))

/-- A bit only sees the value modulo `2^(S+1)`. -/
theorem bit_mod_succ (z S : Nat) : bit z S = bit (z % 2 ^ (S + 1)) S := by
  unfold bit
  have hM : 0 < 2 ^ S := two_pow_pos S
  have hrl : z % 2 ^ S < 2 ^ S := Nat.mod_lt _ hM
  have hr0 : z % 2 ^ S / 2 ^ S = 0 := Nat.div_eq_of_lt hrl
  have hbrack : 2 ^ S * (z / 2 ^ S % 2) + z % 2 ^ S < 2 ^ (S + 1) := by
    rcases Nat.lt_or_ge (z / 2 ^ S % 2) 1 with h0 | h1
    · have hze : z / 2 ^ S % 2 = 0 := by omega
      rw [hze, Nat.zero_mul]
      have hp : (2 : Nat) ^ (S + 1) = 2 ^ S + 2 ^ S := by rw [Nat.pow_succ]; ring
      omega
    · have hon : z / 2 ^ S % 2 = 1 := by omega
      rw [hon, Nat.one_mul]
      have hp : (2 : Nat) ^ (S + 1) = 2 ^ S + 2 ^ S := by rw [Nat.pow_succ]; ring
      omega
  have hgen : ∀ K L r : Nat,
      2 ^ S * (2 * K + L) + r = 2 ^ (S + 1) * K + (2 ^ S * L + r) := by
    intro K L r
    rw [Nat.right_distrib, ← Nat.pow_succ, Nat.add_assoc]
  have hmodE : z % 2 ^ (S + 1)
      = 2 ^ S * (z / 2 ^ S % 2) + z % 2 ^ S := by
    have hz := Nat.div_add_mod z (2 ^ S)
    have hq := Nat.div_add_mod (z / 2 ^ S) 2
    rw [← hq] at hz
    rw [hgen] at hz
    conv_lhs => rw [← hz]
    rw [mod_shift]
    exact Nat.mod_eq_of_lt hbrack
  rw [hmodE, div_shift hM, hr0, Nat.add_zero]

/-- Extracting bit `S` from a positional sum with binary digits yields digit `S`. -/
theorem extract_wsum {G : Nat → Nat} (hG : ∀ t, G t ≤ 1) :
    ∀ N S, S < N → bit (wsum G N) S = G S
  | 0, S, hS => absurd hS (Nat.not_lt_zero S)
  | N + 1, S, hS => by
      rcases Nat.lt_or_ge S N with hSN | hSN
      · have ih := extract_wsum hG N S hSN
        have hexp : N - (S + 1) + (S + 1) = N := by omega
        have hshift : G N * 2 ^ N
            = (G N * 2 ^ (N - (S + 1))) * 2 ^ (S + 1) := by
          rw [Nat.mul_assoc, ← Nat.pow_add, hexp]
        have hcong : (wsum G N + G N * 2 ^ N) % 2 ^ (S + 1)
            = wsum G N % 2 ^ (S + 1) := by
          rw [hshift, Nat.mul_comm (G N * 2 ^ (N - (S + 1))) (2 ^ (S + 1)),
            Nat.add_mul_mod_self_left]
        rw [wsum_succ, bit_mod_succ, hcong, ← bit_mod_succ, ih]
      · have hseq : S = N := by omega
        subst hseq
        have hGN : G N ≤ 1 := hG N
        unfold bit
        rw [wsum_succ, Nat.mul_comm (G N) (2 ^ N),
          Nat.add_mul_div_left _ _ (two_pow_pos N),
          Nat.div_eq_of_lt (wsum_bound hG N), Nat.zero_add]
        exact Nat.mod_eq_of_lt (by omega)

/-! ## Bit uniqueness -/

/-- Numbers below `2^N` are determined by their first `N` bits. -/
theorem eqOfBits_gen (u v : Nat) (N : Nat) (hu : u < 2 ^ N) (hv : v < 2 ^ N)
    (h : ∀ s, s < N → bit u s = bit v s) : u = v := by
  induction N generalizing u v with
  | zero =>
      have hp0 : (2 : Nat) ^ 0 = 1 := rfl
      have hu0 : u = 0 := by omega
      have hv0 : v = 0 := by omega
      rw [hu0, hv0]
  | succ n ih =>
      have hpow : (2 : Nat) ^ (n + 1) = 2 ^ n * 2 := by rw [Nat.pow_succ]
      have hbit0 : ∀ w, bit w 0 = w % 2 := by
        intro w
        show (w / 2 ^ 0) % 2 = w % 2
        rw [show (2 : Nat) ^ 0 = 1 from rfl]
        omega
      have hb0 : 0 < n + 1 := by omega
      have hbu : u % 2 = v % 2 :=
        (hbit0 u).symm.trans ((h 0 hb0).trans (hbit0 v))
      have hshift : ∀ (w s : Nat), bit (w / 2) s = bit w (s + 1) := by
        intro w s
        show ((w / 2) / 2 ^ s) % 2 = (w / 2 ^ (s + 1)) % 2
        rw [Nat.div_div_eq_div_mul_div, Nat.mul_comm 2 (2 ^ s), ← Nat.pow_succ]
      have hhigh : ∀ s, s < n → bit (u / 2) s = bit (v / 2) s := by
        intro s hs
        rw [hshift u s, hshift v s]
        exact h (s + 1) (by omega)
      have hdu : u / 2 < 2 ^ n := by omega
      have hdv : v / 2 < 2 ^ n := by omega
      have hq : u / 2 = v / 2 := ih (u / 2) (v / 2) hdu hdv hhigh
      omega

/-- A number below `2^N` is the positional sum of its first `N` bits. -/
theorem bitsum_id (x N : Nat) (hx : x < 2 ^ N) :
    (∑ j ∈ Finset.range N, bit x j * 2 ^ j) = x := by
  have hbits : ∀ S, S < N → bit (wsum (fun j => bit x j) N) S = bit x S :=
    extract_wsum (G := fun j => bit x j) (fun t => bit_le_one x t) N
  have hbound : wsum (fun j => bit x j) N < 2 ^ N :=
    wsum_bound (fun t => bit_le_one x t) N
  have hfinal : wsum (fun j => bit x j) N = x :=
    eqOfBits_gen (wsum (fun j => bit x j) N) x N hbound hx hbits
  calc (∑ j ∈ Finset.range N, bit x j * 2 ^ j)
      = wsum (fun j => bit x j) N := rfl
    _ = x := hfinal

/-- Two bytes are equal once all their bits agree. -/
theorem eqOfBits {u v : Nat} (hu : u < 256) (hv : v < 256)
    (h : ∀ s, s < 8 → bit u s = bit v s) : u = v :=
  eqOfBits_gen u v 8 hu hv h

/-! ## Coefficient-aligned division / modulo -/

theorem mul_add_div {c : Nat} (hc : 0 < c) {a b : Nat} (hab : a < c) :
    (b * c + a) / c = b := by
  have h : b * c + a = a + c * b := by ring
  rw [h, Nat.add_mul_div_left _ _ hc, Nat.div_eq_of_lt hab]

theorem mul_add_mod {c a b : Nat} (hab : a < c) :
    (b * c + a) % c = a := by
  have h : b * c + a = a + c * b := by ring
  rw [h, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hab]

theorem coeff_div (i j : Nat) (hj : j < 12) : (12 * i + j) / 12 = i :=
  mul_add_div (by omega) hj

theorem coeff_mod (i j : Nat) (hj : j < 12) : (12 * i + j) % 12 = j :=
  mul_add_mod hj

/-! ## FIPS 203 model -/

/-- Global bit position `p` of byte array `B` (Algorithm 4, little-endian). -/
def gbit (B : Nat → Nat) (p : Nat) : Nat := bit (B (p / 8)) (p % 8)

theorem gbit_le_one (B : Nat → Nat) (p : Nat) : gbit B p ≤ 1 := by
  unfold gbit
  exact bit_le_one _ _

theorem gbit_byte (B : Nat → Nat) (y s : Nat) (hs : s < 8) :
    gbit B (8 * y + s) = bit (B y) s := by
  unfold gbit
  have h1 : 8 * y + s = y * 8 + s := by ring
  have hd : (y * 8 + s) / 8 = y := mul_add_div (by omega) hs
  have hmd : (y * 8 + s) % 8 = s := mul_add_mod hs
  rw [h1, hd, hmd]

/-- Unreduced value of coefficient `i` (Algorithm 6, d = 12): the 12-bit
little-endian word read from global positions `[12*i, 12*i+12)`. -/
def seg (B : Nat → Nat) (i : Nat) : Nat :=
  wsum (fun j => gbit B (12 * i + j)) 12

theorem seg_bit (B : Nat → Nat) (i j : Nat) (hj : j < 12) :
    bit (seg B i) j = gbit B (12 * i + j) := by
  have h := extract_wsum (G := fun t => gbit B (12 * i + t))
    (fun t => gbit_le_one B (12 * i + t)) 12 j hj
  exact h

/-- Decoded coefficient: `seg` reduced mod q = 3329 (Algorithm 6 line 3). -/
def dec (B : Nat → Nat) (i : Nat) : Nat := seg B i % 3329

/-- Bit `p%12` of coefficient `p/12` in the encoded domain (Algorithm 5). -/
def ebit (F : Nat → Nat) (p : Nat) : Nat := bit (F (p / 12)) (p % 12)

theorem ebit_le_one (F : Nat → Nat) (p : Nat) : ebit F p ≤ 1 := by
  unfold ebit
  exact bit_le_one _ _

/-- Byte `y` of the d = 12 encoding: positions `[8*y, 8*y+8)`, little-endian. -/
def encByte (F : Nat → Nat) (y : Nat) : Nat :=
  wsum (fun t => ebit F (8 * y + t)) 8

theorem enc_bit (F : Nat → Nat) (y s : Nat) (hs : s < 8) :
    bit (encByte F y) s = ebit F (8 * y + s) := by
  have h := extract_wsum (G := fun t => ebit F (8 * y + t))
    (fun t => ebit_le_one F (8 * y + t)) 8 s hs
  exact h

/-! ## T1: canonical values survive Decode ∘ Encode -/

/-- Byte-position `12*i+j` decodes back to bit `j` of coefficient `i`. -/
theorem digit_bridge (F : Nat → Nat) (i j : Nat) (hj : j < 12) :
    gbit (fun y => encByte F y) (12 * i + j) = bit (F i) j := by
  have hy : (12 * i + j) / 12 = i := coeff_div i j hj
  have hm : (12 * i + j) % 12 = j := coeff_mod i j hj
  have h8 : 8 * ((12 * i + j) / 8) + (12 * i + j) % 8 = 12 * i + j :=
    Nat.div_add_mod (12 * i + j) 8
  have hbr : bit (encByte F ((12 * i + j) / 8)) ((12 * i + j) % 8)
      = ebit F (12 * i + j) := by
    rw [enc_bit F ((12 * i + j) / 8) ((12 * i + j) % 8) (by omega), h8]
  have heb : ebit F (12 * i + j)
      = bit (F ((12 * i + j) / 12)) ((12 * i + j) % 12) := rfl
  have hgb : gbit (fun y => encByte F y) (12 * i + j)
      = bit (encByte F ((12 * i + j) / 8)) ((12 * i + j) % 8) := rfl
  rw [hgb, hbr, heb, hy, hm]

theorem dec_digit (B : Nat → Nat) (hSeg : ∀ i, seg B i < 3329) (p : Nat) :
    bit (dec B (p / 12)) (p % 12) = gbit B p := by
  have hd : dec B (p / 12) = seg B (p / 12) % 3329 := rfl
  have hml : p % 12 < 12 := Nat.mod_lt p (by omega)
  have hsegb : bit (seg B (p / 12)) (p % 12)
      = gbit B (12 * (p / 12) + p % 12) :=
    seg_bit B (p / 12) (p % 12) hml
  have hp : 12 * (p / 12) + p % 12 = p := by omega
  rw [hd, Nat.mod_eq_of_lt (hSeg (p / 12)), hsegb, hp]

theorem canonicalRoundtrip :
    ∀ (F : Nat → Nat), (∀ i, F i < 3329) → ∀ i,
      dec (fun y => encByte F y) i = F i := by
  intro F hF i
  have hconv : wsum (fun j => gbit (fun y => encByte F y) (12 * i + j)) 12
      = wsum (fun j => bit (F i) j) 12 := by
    refine wsum_congr (fun j hj => ?_)
    show gbit (fun y => encByte F y) (12 * i + j) = bit (F i) j
    exact digit_bridge F i j hj
  have hd : dec (fun y => encByte F y) i
      = wsum (fun j => gbit (fun y => encByte F y) (12 * i + j)) 12 % 3329 := rfl
  have hsum : wsum (fun j => bit (F i) j) 12
      = ∑ t ∈ Finset.range 12, bit (F i) t * 2 ^ t := rfl
  have hb12 : F i < 2 ^ 12 := by
    rw [two_pow_12]
    exact Nat.lt_trans (hF i) (by norm_num : (3329 : Nat) < 4096)
  rw [hd, hconv, hsum, bitsum_id (F i) 12 hb12]
  exact Nat.mod_eq_of_lt (hF i)

/-! ## T2: the § 7.2 modulus check is exactly canonicity -/

theorem roundtrip_digit (B : Nat → Nat) (hSeg : ∀ i, seg B i < 3329)
    (y s : Nat) (hs : s < 8) :
    bit (encByte (fun i => dec B i) y) s = bit (B y) s := by
  have h1 : bit (encByte (fun i => dec B i) y) s
      = bit (dec B ((8 * y + s) / 12)) ((8 * y + s) % 12) := by
    rw [enc_bit (fun i => dec B i) y s hs]
    exact rfl
  rw [h1, dec_digit B hSeg (8 * y + s)]
  exact gbit_byte B y s hs

theorem enc_dec_eq (B : Nat → Nat) (hB : ∀ y, B y < 256)
    (hSeg : ∀ i, seg B i < 3329) (y : Nat) :
    encByte (fun i => dec B i) y = B y := by
  have hlt : encByte (fun i => dec B i) y < 256 := by
    have hw := wsum_bound (G := fun t => ebit (fun i => dec B i) (8 * y + t))
      (fun t => ebit_le_one (fun i => dec B i) (8 * y + t)) 8
    rw [← two_pow_8]
    exact hw
  refine eqOfBits hlt (hB y) (fun s hs => ?_)
  exact roundtrip_digit B hSeg y s hs

theorem exists_diff_bit (u v : Nat) (N : Nat) (hu : u < 2 ^ N) (hv : v < 2 ^ N)
    (hne : u ≠ v) : ∃ s, s < N ∧ bit u s ≠ bit v s := by
  by_contra hcon
  push_neg at hcon
  exact hne (eqOfBits_gen u v N hu hv hcon)

/-- A byte array with an out-of-range segment fails the re-encoding check. -/
theorem reject_on_overflow (B : Nat → Nat) (hB : ∀ y, B y < 256)
    (h : ∃ i, seg B i ≥ 3329) : ∃ y, encByte (fun i => dec B i) y ≠ B y := by
  obtain ⟨i, hi⟩ := h
  have hslt : seg B i < 2 ^ 12 :=
    wsum_bound (G := fun t => gbit B (12 * i + t))
      (fun t => gbit_le_one B (12 * i + t)) 12
  have hdlt : dec B i < 3329 := by
    unfold dec
    exact Nat.mod_lt _ (by omega)
  have hd : dec B i = seg B i - 3329 := by
    have hp12 := two_pow_12
    unfold dec
    omega
  have hd12 : dec B i < 2 ^ 12 := by rw [two_pow_12]; omega
  obtain ⟨j, hj, hbj⟩ :=
    exists_diff_bit (dec B i) (seg B i) 12 hd12 hslt (by omega)
  refine ⟨(12 * i + j) / 8, ?_⟩
  have hs8 : (12 * i + j) % 8 < 8 := Nat.mod_lt _ (by omega)
  have hL : bit (encByte (fun i => dec B i) ((12 * i + j) / 8))
        ((12 * i + j) % 8) = bit (dec B i) j := by
    rw [enc_bit (fun i => dec B i) ((12 * i + j) / 8) ((12 * i + j) % 8) hs8]
    have hpm : 8 * ((12 * i + j) / 8) + (12 * i + j) % 8 = 12 * i + j :=
      Nat.div_add_mod (12 * i + j) 8
    rw [hpm]
    show bit ((fun i => dec B i) ((12 * i + j) / 12)) ((12 * i + j) % 12)
        = bit (dec B i) j
    rw [coeff_div i j hj, coeff_mod i j hj]
  have hR : bit (B ((12 * i + j) / 8)) ((12 * i + j) % 8) = bit (seg B i) j := by
    have hg : gbit B (12 * i + j)
        = bit (B ((12 * i + j) / 8)) ((12 * i + j) % 8) := rfl
    rw [← hg, ← seg_bit B i j hj]
  intro hcon
  apply hbj
  calc bit (dec B i) j
      = bit (encByte (fun i => dec B i) ((12 * i + j) / 8))
          ((12 * i + j) % 8) := hL.symm
    _ = bit (B ((12 * i + j) / 8)) ((12 * i + j) % 8) := by rw [hcon]
    _ = bit (seg B i) j := hR

theorem roundtrip_iff_canonical :
    ∀ (B : Nat → Nat), (∀ y, B y < 256) →
      ((∀ i, seg B i < 3329) ↔ (∀ y, encByte (fun i => dec B i) y = B y)) := by
  intro B hB
  constructor
  · intro hSeg y
    exact enc_dec_eq B hB hSeg y
  · intro hEnc i
    by_contra hcon
    push_neg at hcon
    obtain ⟨y, hy⟩ := reject_on_overflow B hB ⟨i, hcon⟩
    exact hy (hEnc y)

/-! ## Minimal counterexample for the § 7.2 check -/

/-- Minimal overflow input: bytes `0x01 0x0D`, all others zero. -/
def B0 : Nat → Nat := fun y => if y = 0 then 1 else if y = 1 then 13 else 0

/-- Segment value q = 3329 (bytes `0x01 0x0D`) decodes to 0 and re-encodes to
`0x00 0x00 ≠ 0x01 0x0D`: the § 7.2 modulus check rejects it. -/
theorem minimalCounterexample :
    B0 0 = 1 ∧ B0 1 = 13
      ∧ dec B0 0 = 0
      ∧ encByte (fun i => dec B0 i) 0 = 0 ∧ (0 : Nat) ≠ 1
      ∧ encByte (fun i => dec B0 i) 1 = 0 ∧ (0 : Nat) ≠ 13 := by
  have h1 : B0 0 = 1 := by decide
  have h2 : B0 1 = 13 := by decide
  have h3 : dec B0 0 = 0 := by decide
  have h4 : encByte (fun i => dec B0 i) 0 = 0 := by decide
  have h5 : encByte (fun i => dec B0 i) 1 = 0 := by decide
  exact ⟨h1, h2, h3, h4, by decide, h5, by decide⟩

end Fips203
