/-
CORE-ONLY ARITHMETIC PROBE for formal/Formal/EkCheck.lean.

This file is EVIDENCE, not part of the `lean_lib Formal` library: nothing
imports it and formal/Formal.lean does NOT import it, so it is never built by
.github/workflows/formal.yml.  It is committed so that the arithmetic
assertions in EkCheck.lean have a reproducible machine-checked witness.

What it establishes.  EkCheck.lean asserts concrete numeric facts about the
ML-KEM-512 counterexample key `B2` (zero, except byte 768 = 0x01 and byte 769
= 0x0D, at length 800).  This probe re-implements the bit-level operations of
ByteEncode.lean -- `bit`, `wsum`, `gbit`, `seg`, `dec`, `ebit`, `encByte` -- by
plain structural recursion instead of via `Finset.sum`, and evaluates them
with the kernel's `decide`.  It therefore shares NO code with EkCheck.lean.

It checks:
  * `seg B2 512 = 3329` -- the bytes 0x01 0x0D spell q at the rho seed;
  * `seg B2 i = 0` for every prefix coefficient `i < 512`;
  * `B2 y = 0` for every covered byte `y < 768`;
  * every byte read by a prefix coefficient has index `< 768`;
  * Eq (7.1) holds at EVERY byte index `y < 768` -- checked by evaluating the
    re-encoding, not by assuming it.  This takes about 8 minutes of kernel
    time (`maxRecDepth 400000`, `maxHeartbeats 3000000`);
  * NEGATIVE RESULT: the unrestricted re-encoding DISAGREES at byte 768, the
    first byte of the seed and the first index Eq (7.1) does not cover;
  * the index arithmetic for k = 2, 3, 4.

It does NOT establish that EkCheck.lean compiles.  See
knowledge/reports/rpt-2026-0018.yaml.

Recorded run: toolchain leanprover/lean4:v4.22.0, commit
ba2cbbf09d4978f416e0ebd1fceeebc2c4138c05, local, Windows, no Mathlib, no
network.  Exit code 0, no error lines.  `#print axioms` transcript:

'Probe.seg512' does not depend on any axioms
'Probe.prefix_segments_zero' does not depend on any axioms
'Probe.old_hypothesis_false' does not depend on any axioms
'Probe.eq7_1_holds_on_B2' does not depend on any axioms
'Probe.unbounded_reencode_disagrees_at_seed' does not depend on any axioms
'Probe.t4_summary' depends on axioms: [propext, Quot.sound]
-/
/-
CORE-ONLY PROBE (no Mathlib, no import of the corpus).

Purpose: machine-check the NUMERIC content of `Formal/EkCheck.lean`'s
counterexample by re-implementing the bit-level operations of
`ByteEncode.lean` (bit, wsum, gbit, seg) by plain structural recursion
instead of via `Finset.sum`, and evaluating them with the kernel's `decide`.

This is a FEASIBILITY PROBE, not evidence that `Formal/EkCheck.lean` itself
compiles: it shares no code with that file.  What it does establish is that
the byte/bit arithmetic the module asserts is arithmetically correct:

  * `seg B2 512 = 3329` for B2 zero except bytes 768 = 0x01, 769 = 0x0D;
  * `seg B2 i = 0` for every i < 512, because the prefix bits are zero;
  * segment 512 starts at global bit 12 * 512 = 6144 = byte 768, which is
    the first byte of the rho seed for k = 2 (384 * 2 = 768);
  * `encByte (dec B2) y = B2 y` is NOT claimed here -- that direction is
    Eq (7.1) and needs the corpus's eqOfBits argument.  What is checked is
    the contrapositive-free fact used by T4: the violation lives OUTSIDE
    the 384k prefix and therefore cannot affect any byte index y < 768,
    because every bit read by a prefix coefficient has index < 2 * 384 * 2.

Toolchain: leanprover/lean4:v4.22.0 (the pinned toolchain; core only).
Run:  lean probe.lean
-/

namespace Probe

def bit (x j : Nat) : Nat := (x / 2 ^ j) % 2

/-- Positional sum over `range N`, by structural recursion. -/
def wsum (G : Nat → Nat) : Nat → Nat
  | 0 => 0
  | N + 1 => wsum G N + G N * 2 ^ N

theorem wsum_succ' (G : Nat → Nat) (N : Nat) :
    wsum G (N + 1) = wsum G N + G N * 2 ^ N := rfl

def gbit (B : Nat → Nat) (p : Nat) : Nat := bit (B (p / 8)) (p % 8)

def seg (B : Nat → Nat) (i : Nat) : Nat := wsum (fun j => gbit B (12 * i + j)) 12

/-- The concrete key: zero, except byte 768 = 1 and byte 769 = 13. -/
def B2raw (y : Nat) : Nat := if y = 768 then 1 else if y = 769 then 13 else 0

def B2 : Nat → Nat := B2raw

/-- Segment 512 of B2 is exactly q = 3329. -/
theorem seg512 : seg B2 512 = 3329 := by decide

/-- Segment 512 begins at byte 768, the first byte of the rho seed. -/
theorem seg512_start_byte : (12 * 512 : Nat) / 8 = 768 := by decide

/-- The `384 * 2 = 768`-byte prefix holds `768 * 8 = 6144 = 12 * 512` bits,
so segment 512 is the first segment lying entirely outside it. -/
theorem prefix_bits_k2 : (8 * 384 * 2 : Nat) = 12 * 512 := by decide

/-- `384 * 2 = 768` is the first byte of the rho seed region of a k = 2 key. -/
theorem seed_start_k2 : (384 * 2 : Nat) = 768 := by decide

/-- `256 * 2 = 512` coefficients fill the `384 * 2 = 768`-byte prefix. -/
theorem coeff_count_k2 : (256 * 2 : Nat) = 512 := by decide

/-- The key has the length step 1 demands for k = 2. -/
theorem ek_length_k2 : (384 * 2 + 32 : Nat) = 800 := by decide

/-- Every prefix coefficient is 0.  Checked by evaluating `seg B2` on all
512 prefix coefficients with the kernel's `decide`. -/
theorem prefix_segments_zero :
    ∀ i, i < 512 -> seg B2 i = 0 := by
  set_option maxRecDepth 100000 in decide

/-- The prefix bytes read by Eq (7.1) are all zero. -/
theorem prefix_bytes_zero :
    ∀ y, y < 768 -> B2 y = 0 := by
  set_option maxRecDepth 100000 in decide

/-- Every byte read by a prefix coefficient has index below 768, i.e. every
bit read by segment `i < 512` lies in a byte strictly below the seed. -/
theorem prefix_bit_positions_below_seed :
    ∀ i, i < 512 -> ∀ j, j < 12 -> (12 * i + j) / 8 < 768 := by
  set_option maxRecDepth 100000 in decide

/-- NEGATIVE RESULT, recorded: the OLD unbounded hypothesis is FALSE for this
key, because segment 512 = 3329 >= q.  This is the vacuity witness. -/
theorem old_hypothesis_false : 3329 ≤ seg B2 512 := by decide

/-- The bytes 0x01 0x0D spell q = 3329 as a 12-bit little-endian word:
1 + 256 + 1024 + 2048 = 3329, bit by bit. -/
theorem bytes_spell_q :
    bit 1 0 = 1 ∧ bit 1 1 = 0 ∧ bit 1 2 = 0 ∧ bit 1 3 = 0 ∧ bit 1 4 = 0 ∧
    bit 1 5 = 0 ∧ bit 1 6 = 0 ∧ bit 1 7 = 0 ∧ bit 1 8 = 0 ∧ bit 1 9 = 0 ∧
    bit 1 10 = 0 ∧ bit 1 11 = 0 ∧
    bit 13 0 = 1 ∧ bit 13 1 = 0 ∧ bit 13 2 = 1 ∧ bit 13 3 = 1 ∧ bit 13 4 = 0 ∧
    bit 13 5 = 0 ∧ bit 13 6 = 0 ∧ bit 13 7 = 0 ∧ bit 13 8 = 0 ∧ bit 13 9 = 0 ∧
    bit 13 10 = 0 ∧ bit 13 11 = 0 := by decide

/-! ## Machine-checked index arithmetic, k = 2 / 3 / 4 -/

theorem lengths : (384 * 2 + 32 : Nat) = 800 ∧ (384 * 3 + 32 : Nat) = 1184 ∧
    (384 * 4 + 32 : Nat) = 1568 := by decide

theorem coeffs : (256 * 2 : Nat) = 512 ∧ (256 * 3 : Nat) = 768 ∧
    (256 * 4 : Nat) = 1024 := by decide

theorem prefix_bytes : (12 * 256 * 2 : Nat) / 8 = 768 ∧
    (12 * 256 * 3 : Nat) / 8 = 1152 ∧ (12 * 256 * 4 : Nat) / 8 = 1536 := by decide

/-- The three parameter sets give distinct admissible byte counts, so `k` is
load-bearing. -/
theorem k_load_bearing :
    384 * 2 + 32 ≠ 384 * 3 + 32 ∧ 384 * 2 + 32 ≠ 384 * 4 + 32 ∧
      384 * 3 + 32 ≠ 384 * 4 + 32 := by decide

/-- The last bit of the last prefix coefficient lies inside byte 767, never
in the seed: `8 * 768 - 1 = 6143` and `6143 / 8 = 767`. -/
theorem last_prefix_bit : ((8 * 384 * 2 - 1) : Nat) / 8 = 767 := by decide

/-! ## The other half of T4, checked by evaluation rather than by the
     corpus's `eqOfBits` chain.

The corpus proves Eq (7.1) for B2 through `enc_dec_eq`, which uses
`eqOfBits`; that argument is not re-implemented here.  Instead the re-encoding
is EVALUATED directly on all 768 covered byte indices.  Both sides are zero
there, so this is a check of the re-encoding computation itself, not merely
of an assumption about it. -/

def dec (B : Nat → Nat) (i : Nat) : Nat := seg B i % 3329

def ebit (F : Nat → Nat) (p : Nat) : Nat := bit (F (p / 12)) (p % 12)

def encByte (F : Nat → Nat) (y : Nat) : Nat := wsum (fun t => ebit F (8 * y + t)) 8

set_option maxRecDepth 400000
set_option maxHeartbeats 3000000

/-- Eq (7.1) HOLDS for `B2` at every byte index `y < 384 * 2 = 768`. -/
theorem eq7_1_holds_on_B2 :
    ∀ y, y < 384 * 2 -> encByte (fun i => dec B2 i) y = B2 y := by
  decide

/-- NEGATIVE RESULT, and the sharpest form of the vacuity witness: at the
seed byte 768 the UNRESTRICTED re-encoding DISAGREES with the key.  Decoding
segment 512 gives `3329 % 3329 = 0`, so the re-encoded byte is 0 while the
key holds 1.

This is exactly the index that Eq (7.1) does not cover: `y = 768` is not
`< 384 * 2 = 768`.  So the old corpus biconditional `roundtrip_iff_canonical`
has a FALSE left-hand side on this key at index 768, while Eq (7.1) -- whose
domain stops at the prefix -- is satisfied everywhere it applies. -/
theorem unbounded_reencode_disagrees_at_seed :
    encByte (fun i => dec B2 i) 768 ≠ B2 768 := by
  decide

/-- The two halves of T4, in one statement: Eq (7.1) holds on the whole
prefix, the OLD unbounded hypothesis fails, and the unrestricted
re-encoding disagrees at the first seed byte. -/
theorem t4_summary :
    (∀ y, y < 384 * 2 -> encByte (fun i => dec B2 i) y = B2 y) ∧
      ¬ (∀ i, seg B2 i < 3329) ∧
      ¬ (∀ y, encByte (fun i => dec B2 i) y = B2 y) := by
  have hlt512 := show ¬ seg B2 512 < 3329 from by
    rw [seg512]; omega
  refine ⟨eq7_1_holds_on_B2, fun h1 => hlt512 (h1 512), fun h2 => ?_⟩
  exact unbounded_reencode_disagrees_at_seed (h2 768)

#print axioms Probe.seg512
#print axioms Probe.prefix_segments_zero
#print axioms Probe.old_hypothesis_false
#print axioms Probe.eq7_1_holds_on_B2
#print axioms Probe.unbounded_reencode_disagrees_at_seed
#print axioms Probe.t4_summary

end Probe
