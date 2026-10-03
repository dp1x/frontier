<!-- Preserved from .scratch/ (gitignored, not durable).
     Supports knowledge/reports/rpt-2026-0017.yaml.
     Original filename: rustls_harness_fix_spec.md -->

# Fix specification — rustls_loopback §7.2 harness defects

**Target:** `knowledge/findings/fnd-2026-0005.yaml` (status `disputed`), via `rev-2026-0018` / `.scratch/audit_fnd_0005.md`
**Role:** failure-analyst + experiment-designer. READ-ONLY over `knowledge/`, `missions/`, `src/`. Harness unmodified.
**Date:** 2026-10-03
**Scratch artifacts produced:** `.scratch/fips203_layout_check.py`, `.scratch/truncation_check.py`

Every claim below is tagged **VERIFIED** (I read or executed it this session),
**INFERRED** (reasoned from source with the gap named), or
**COULD-NOT-DETERMINE**.

---

## 0. Bottom line

All three defects in the audit are **confirmed**, and I reproduced the byte
arithmetic independently rather than accepting it. Two corrections to the brief
you gave me:

- **Your offset range for t̂ is wrong.** You wrote "t̂ occupies ek[384k .. 384k+1152),
  i.e. ek[1152..2304)". The true range is **`ek[0 : 384k]` = `ek[0 : 1152)`** —
  the slice `ek[0:384k]` is verbatim in FIPS 203 Eq 7.1. `ek[1152:2304)` runs past
  the end of a 1184-byte ek and would swallow ρ. **VERIFIED** (§2).
- **The "384 B" comment is not merely wrong in one place — the same file already
  contradicts it.** `go_loopback/main.go:121` says `seedStart = 1152 // ek[1152:1184]
  is the rho seed`, which is correct. Three lines above, `go_loopback/main.go:114`
  says t̂ is 384 B. The harness's constants were right and its comment was wrong —
  the defect is a stale comment, not a mis-derived offset, *except* for `polyLo`/`tailHi`
  which genuinely were mis-derived. **VERIFIED**.

The decisive design finding is in §4: **the §7.2 LENGTH half is provably
unreachable on the rustls wire path.** It cannot be fixed by editing the
`truncate_last_byte` offset; that row must be replaced by a library-parse row.
The mechanism discriminator the brief asks for exists and is stronger than
suggested — `aws_lc_rs::kem::EncapsulationKey::new` returns a *distinct error type*
for the length class. **VERIFIED** from source at the pinned tag.

---

## 1. Defective code, quoted with `file:line`

### 1.1 The wrong t̂ constant — `rustls_loopback/main.go:62-71`

```go
62→// lane edits over the little-endian packed 12-bit coefficient layout:
63→// coeff[i] low half occupies byte pair (b0,b1) as b0 | ((b1&0x0F)<<8);
64→// ek layout is 384 B encoded t-hat (modulus-checked) then 32 B rho seed
65→// (unconstrained). Same constants as go_loopback/main.go:115-130.
66→const (
67→	coeffQ    = 3329 // == q, exactly at the rejection boundary
68→	coeffQMax = 4095 // largest 12-bit value
69→	polyLo    = 762  // last ByteDecode12 triplet holds coeffs 254,255
70→	tailHi    = 764  // coeff255 = (b[763]>>4) | b[764]<<4
71→)
```

Line 64 is the root cause. `384` is `ByteEncode₁₂` of **one** polynomial
(𝔹^{32·12} = 𝔹^384, FIPS 203 Alg 5 line "Output: byte array B ∈ 𝔹^{32d}"). For
ML-KEM-768, `k = 3`, so t̂ is `3 × 384 = 1152` bytes. `polyLo = 762` is calibrated
to a hypothetical **768-byte** t̂ (`768/2 − 3`), not 1152.

The cross-reference on line 65 is itself wrong: the constants are at
`go_loopback/main.go:116-122`, not `115-130`. **VERIFIED**.

### 1.2 The mis-targeted coefficient — `rustls_loopback/main.go:232-235`

```go
232→	case "wire_coeff255_eq_4095":
233→		ch.body[d+polyLo+1] |= 0xF0
234→		ch.body[d+tailHi] = 0xFF
235→		return true, fmt.Sprintf("ek[%d..%d] rewritten to coeff255==4095", polyLo+1, tailHi)
```

Writes `ek[763]` and `ek[764]` = triplet 254 = global coefficient **509**
(poly 1, local index 253). coeff255 lives at `ek[381..383]`. **VERIFIED by
execution** (`.scratch/fips203_layout_check.py`, section E): the set of
coefficients whose raw 12-bit lane value changes is exactly `[509]`.

The return string is also wrong — it reports `ek[763..764] rewritten to
coeff255==4095` and that string reached the console log verbatim
(`reports/rustls_loopback_console.log:16`).

### 1.3 The truncation that never touched the ek — `rustls_loopback/main.go:236-248`

```go
236→	case "truncate_last_byte":
237→		cut := d + shareSize - 1
238→		if ch.entryLen != shareSize || cut >= len(ch.body) {
239→			return false, fmt.Sprintf("unexpected entry length %d", ch.entryLen)
240→		}
...
248→		return true, "ek shrunk to 1183 B, all six length fields repaired (-1)"
```

with `shareSize = ekSize + x25519Size = 1184 + 32 = 1216` (line 58) and
`d := ch.entryPos + 4` (line 215, ek-first).

`cut = d + 1215` = **share offset 1215**, which is `X25519[31]`, the last byte of
the classical tail. The comment on line 237 says `// last ek byte`, which would be
share offset **1183**. **VERIFIED by execution** (`.scratch/truncation_check.py`):
`cut == ek_size - 1` is `False`, `cut >= ek_size` is `True`; ek stays 1184 B,
X25519 becomes 31 B, total share 1215 B.

Line 248's string is therefore false in two ways: ek did not shrink, and it did
not become 1183.

### 1.4 The header comment, also false — `rustls_loopback/main.go:17-20`

```go
17→//      key_share list, locates the 1216-byte X25519MLKEM768 entry, rewrites
18→//      the trailing 1184-byte ML-KEM ek portion in-place per variant
19→//      (canonical control, coeff0 = q, coeff0 = 4095, coeff255 = 4095,
20→//      truncate last ek byte), and forwards the rest of the stream verbatim.
```

"trailing" is wrong (ek is PQ-first, so it *leads* the share), and "truncate last
ek byte" is the false claim from §1.3. The harness's own CITE line at
`main.go:652` gets it right — `ek portion is bytes 0..1184 of the share` — so
the file internally contradicts itself. **VERIFIED**.

### 1.5 The same three defects duplicated in the Go harness

`go_loopback/main.go`:

```go
114→// ek layout is 384 B encoded t-hat (modulus-checked) then 32 B rho seed
115→// (unconstrained), so the last coefficient lane sits at bytes 762..764.
116→const (
...
119→	polyLo    = 762  // last ByteDecode12 triplet holds coeffs 254,255
120→	tailHi    = 764  // coeff255 = (b[763]>>4) | b[764]<<4
121→	seedStart = 1152 // ek[1152:1184] is the rho seed, no modulus constraint
122→)
```

Line 121 is **correct** and lines 114-115 are **wrong**, 7 lines apart in the same
const block. Line 114's model would place ρ at `ek[384:416]`; line 121's places it
at `ek[1152:1184]`.

Same defects at: `136` (`coeff255_4095` editor), `328-330` (wire case),
`335` (`cut := d + shareSize - 1`), `346` (the false `"ek shrunk to 1183 B"`).

**Important nuance the audit's fix list understates:** the Go harness's
**library-parse** family *does* test the LENGTH half correctly:

```go
152→	trunc := base[:len(base)-1]
153→	_, err = mlkem.NewEncapsulationKey768(trunc)
```

`base` is the ek itself (line 127), so this yields a genuine 1183-byte ek, and the
committed report `go_loopback/reports/go_loopback_report.tsv:6` records
`library-parse|truncate_last_byte|1183|rejected|length|mlkem: invalid encapsulation key length`.
**VERIFIED**. So obs-2026-0011's *library-parse* length row is genuine evidence;
only its *tls-wire* row is defective, and for the same `shareSize` reason. That
row is currently recorded as `UNMET` with `no-alert-seen:EOF`, so it supports
nothing either way.

### 1.6 A third harness in this repo already gets coeff255 right

`interop/protocol-placement/ssh_loopback/stagec/main.go:102-109`:

```go
102→// coeff255_4095: set the last 12-bit coefficient (coeff 255) to 4095.
...
107→func stimCoeff255Max(pk2 []byte) {
108→	pk2[382] = (pk2[382] & 0x0F) | 0xF0 // high nibble of byte 382 = 0xF
109→	pk2[383] = 0xFF
110→}
```

and `ssh_loopback/main.go:103-104` even shows the author catching the same trap
in-flight: *"Last coefficient at byte positions: 3*255 - 1 = 764 ... **Wait:**
each 3 bytes hold 2 coefficients. coeff i is at bytes [3*(i//2), ...]"*.

This is independent in-repo corroboration that `ek[381..383]` is correct, and it
confines the defect to the two `*_loopback/main.go` harnesses. **VERIFIED**.

### 1.7 Downstream propagation

| Artifact | Location | Defect echoed |
|---|---|---|
| `reports/rustls_loopback_console.log` | line 16 | `"ek[763..764] rewritten to coeff255==4095"` |
| `reports/rustls_loopback_console.log` | line 18 | `"ek shrunk to 1183 B, ..."` |
| `fnd-2026-0005.yaml` | `statement` block, all 4 tamper rows | presents `truncate_last_byte` as a §7.2 length case |
| `fnd-2026-0005.yaml` | `limitations` | "3 coefficient overflow patterns (coeff0=q, coeff0=4095, coeff255=4095)" |
| `obs-2026-0024.yaml` | `statement` | "shrinking the ek by one byte and repairing the six TLS length fields" |
| `exp-2026-0019.yaml` | `design` | "coefficient overflow planted at byte offsets corresponding to decoded coefficients 0/255" |
| `rpr-2026-0005.yaml` | `reproduced_on.result` | reproduces the 4-row matrix uncritically |
| `vrf-2026-0006.yaml` | matrix | same 4 rows |

Note `obs-2026-0024.yaml` asserts `divergences_from_go_cohort: none` — a claim
that is only true because both harnesses carry the *same* bug, not because
either was independently checked.

---

## 2. Correct t̂ size and coefficient offsets — verified against primary sources

### 2.1 Primary sources consulted

| Source | Where | What it establishes |
|---|---|---|
| FIPS 203 §7.2, step 1 | `localdocs/refs/fips203.pdf` p.45; extracted text `.scratch/formal-203-r2/fips_full.txt:2028-2031` | *"If ek is not an array of bytes of length 384𝑘 + 32 … then input checking failed."* |
| FIPS 203 §7.2, Eq 7.1 | same, `fips_full.txt:2032-2035` | `test ← ByteEncode₁₂(ByteDecode₁₂(ek[0 : 384𝑘]))`; the checked slice is **`ek[0:384k]`** |
| FIPS 203 Table 2 | `fips_full.txt:2134-2137` | ML-KEM-768: n=256, q=3329, **k=3**, η₁=η₂=2 |
| FIPS 203 Table 3 | `fips_full.txt:2141-2145` | ML-KEM-768 encapsulation key = **1184 bytes** |
| FIPS 203 Alg 5 (ByteEncode_d) | `fips_full.txt:1300-1311` | output `B ∈ 𝔹^{32d}` → **384 B per polynomial** at d=12 |
| FIPS 203 Alg 6 (ByteDecode_d) | `fips_full.txt:1316-1326` | `F[i] ← Σⱼ b[i·d+j]·2ʲ mod m`; at d=12, m=q=3329 |
| FIPS 203 Alg 3 (BitsToBytes) | `fips_full.txt:1221-1229` | `B[⌊i/8⌋] += b[i]·2^{i mod 8}` — little-endian bit packing |
| FIPS 203 K-PKE.KeyGen line 19 | `fips_full.txt:1684` | `ekPKE ← ByteEncode₁₂ᵏ(t̂) ‖ ρ` — "run ByteEncode₁₂ **k times**, then append" |
| aws-lc-rs v1.18.0 `kem.rs` | fetched | `ML_KEM_768_PUBLIC_KEY_LENGTH = 1184`; `EncapsulationKey::new` length gate |
| Go stdlib `mlkem` `go_fips_mlkem768.go:57-61` | `.scratch/audit_fnd0001_src/` | `EncapsulationKeySize768 = k*encodingSize12 + 32` with `k = 3` |
| `formal/Formal/LengthCheck.lean:71-75` | repo | kernel-checked `canonicalLength .k3 = 1184` = `384*3+32` |

The `ek[0:384k]` slice in Eq 7.1 is decisive against the brief's `ek[1152..2304)`.
**VERIFIED.**

### 2.2 The arithmetic

```
q               = 3329
k (ML-KEM-768)  = 3
bytes/poly      = 32·d = 32·12 = 384          (Alg 5 output 𝔹^{32d})
|t̂|             = k · 384 = 3 · 384 = 1152   (= 384k, the Eq 7.1 slice length)
|ρ|             = 32
len(ek)         = 384k + 32 = 1184           (§7.2 type check; Table 3)
t̂ occupies      ek[0 : 1152]
ρ  occupies     ek[1152 : 1184]
```

**The constant the harness should carry is `1152`, not `384`.** `384` is
per-polynomial. 384 also happens to be `k=1`, which is not an approved ML-KEM
parameter set — so the wrong constant is not even a valid parameterisation.
**VERIFIED** (execution, `.scratch/fips203_layout_check.py` §B).

### 2.3 Coefficient index → byte offset

Alg 3 + Alg 5 + Alg 6 fix the layout completely:

- coefficient `i` occupies **bits `[12i, 12i+12)`** of the t̂ body
- even `i`: `value = b0 | ((b1 & 0x0F) << 8)`, triplet `t = i/2`, `b0 = 3t`, `b1 = b2 = 3t+1`
- odd  `i`: `value = (b1 >> 4) | (b2 << 4)`, `b0 = b1 = 3t`, `b2 = 3t+2`

Computed table (**VERIFIED by execution**, §C of the script):

| coeff | bits | triplet `t` | `b0` | `b1` | `b2` | note |
|---|---|---|---|---|---|---|
| 0 | 0..12 | 0 | 0 | 1 | 1 | already correct in harness |
| 254 | 3048..3060 | 127 | 381 | 382 | 382 | shares triplet with 255 |
| **255** | **3060..3072** | **127** | **381** | **382** | **383** | **the real target** |
| 256 | 3072..3084 | 128 | 384 | 385 | 385 | start of poly 1 |
| 509 | 6108..6120 | 254 | 763 | 765 | 765 | **what the harness actually hit** |
| 767 | 9204..9216 | 383 | 1150 | 1152 | 1152 | last coeff; `b2` = 1152 = first ρ byte |

Global index `i = 384·p + j` for poly `p` and local `j`; absolute offsets are
identical across polys because every poly is exactly 384 bytes with no padding.

**Correct constants to replace `polyLo`/`tailHi`:**

```go
polyLo = 381  // triplet 127 = (coeff254, coeff255); was 762
tailHi = 383  // coeff255 = (b[382]>>4) | b[383]<<4; was 764
```

Verified by execution that `b[382] = (b[382]&0x0F)|0xF0; b[383] = 0xFF` yields
coeff254 = 0 and coeff255 = 4095 exactly (§F of the script), with no collateral
change to any other lane.

### 2.4 A note on poly-1 targets

If the intent was a *different* polynomial than poly 0, `polyLo`/`tailHi` for
global coeff 509 are `763`/`765` (not `762`/`764` — see the table). The harness's
`762`/`764` correspond to triplet 254 whose **low** half is coeff508 and whose
high half is coeff509. `|= 0xF0` on `ek[763]` + `= 0xFF` on `ek[764]` sets only
the high half → coeff509. This is exactly what my independent decoder measured.
**VERIFIED.**

---

## 3. Precise stimulus specification

### 3.1 Structural constraint discovered first — this changes the plan

`rustls/src/crypto/aws_lc_rs/pq/hybrid.rs` at tag `v/0.23.43`, which I fetched
verbatim:

```rust
fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
    let (post_quantum_share, classical_share) = self
        .layout
        .split_received_client_share(client_share)
        .ok_or(INVALID_KEY_SHARE)?;
    ...
}

fn split<'a>(&self, share: &'a [u8], post_quantum_share_len: usize)
    -> Option<(&'a [u8], &'a [u8])>
{
    if share.len() != self.classical_share_len + post_quantum_share_len {
        return None;
    }
    ...
}
```

with `classical_share_len = X25519_LEN = 32`, `post_quantum_client_share_len =
MLKEM768_ENCAP_LEN = 1184`. The PQ part is obtained by
`share.split_at(post_quantum_share_len)` — a hard slice, not a parse.

**Therefore: if the share reaches `MlKem::start_and_complete` at all, its PQ
portion is *exactly* 1184 bytes. A 1183-byte ek can never arrive there.** The
§7.2(a) length gate in `aws_lc_rs::kem::EncapsulationKey::new` is unreachable dead
code on this path. **VERIFIED** (from the pinned source).

This is stronger than the audit's phrasing ("impossible without another vector"):
it is unreachable for *any* share length, because `Layout::split` fixes both
component lengths and rejects any total that is not their sum. No amount of
editing the mutator can route a short ek past it.

**Consequence for the plan:** the wire row cannot test §7.2(a). `truncate_last_byte`
must be **deleted from the wire matrix and replaced by a library-parse row**, not
re-pointed at `ekSize-1`. Re-pointing it at `d + ekSize - 1` would produce a
1215-byte share that is rejected by `Layout::split` — the same non-§7.2 mechanism,
now with a correctly-computed offset. It would look fixed and still prove nothing.

### 3.2 MODULUS half — wire stimuli (correct offsets)

Keep `wire_coeff0_eq_q` and `wire_coeff0_eq_4095` unchanged (already correct,
confirmed by execution §A and the audit). Fix and extend the rest:

| Stimulus name | Bytes written | Effect | Expected rejection point |
|---|---|---|---|
| `wire_coeff255_eq_4095` **(fixed)** | `d+382 = (d+382)&0x0F \| 0xF0`; `d+383 = 0xFF` | global coeff **255** := 4095 ≥ q | `mlk_kem_enc_derand` → `mlk_kem_check_pk` → `MLK_ERR_INVALID_PK` |
| `wire_coeff509_eq_4095` **(rename of today's row)** | `d+763 \|= 0xF0`; `d+764 = 0xFF` | global coeff **509** := 4095 | same — this is what the old row actually did; keep it, correctly named |
| `wire_coeff767_eq_4095` **(new)** | `d+1151 = (d+1151)&0x0F \| 0xF0`; `d+1152 = 0xFF` | global coeff **767**, the **last** lane of the last poly | same |
| `wire_coeff0_eq_3328` **(new, ACCEPTED control)** | `d+0 = 0x00`; `d+1 = (d+1)&0xF0 \| 0x0D` | coeff0 := 3328 = q−1, the **largest legal** value | **no rejection — handshake must succeed** |
| `wire_rho_byte_set` **(new, ACCEPTED control)** | `d+1183 = 0xFF` (or any ρ byte) | mutates ρ, which Eq 7.1 never inspects | **no rejection — handshake must succeed** |

Rationale for the two ACCEPTED controls, which the current matrix entirely lacks:

- `coeff0_eq_3328` is the true boundary probe. It proves the check is a bound
  comparison at exactly `q = 3329` and not a bit-pattern heuristic. Without it,
  every stimulus you plant is rejected and you have no evidence the check
  discriminates at the boundary. The Go harness gestures at this
  (`go_loopback/main.go:190-193`, `pre[0]=0x00; pre[1]=…|0x0D` for 3328) but only
  as a bit-flip companion, never as a clean accepted row.
- `rho_byte_set` is the strongest available statement about the **scope** of
  §7.2's modulus half: `ByteEncode₁₂(ByteDecode₁₂(ek[0:1152]))` must not examine
  `ek[1152:1184]`. A successful handshake after a ρ mutation *positively*
  demonstrates the check's boundary; the current 5-row matrix only ever
  demonstrates rejection. The Go cohort already has this at library-parse
  (`seed_byte_set` → `accepted`, `go_loopback_report.tsv:5`) — **VERIFIED** — but
  the rustls cohort never got it.

Expected alerts: all three MODULUS rejects → `illegal_parameter` +
`PeerMisbehaved(InvalidKeyShare)`; both ACCEPTED controls → `success`.

### 3.3 LENGTH half — library-parse stimuli (new family)

Port the Go harness's `library-parse` family into the Rust cohort. Design below.

**Stimuli** (all on a canonically generated `ML_KEM_768` ek, then edited):

| Stimulus | Input to `EncapsulationKey::new` | §7.2 clause violated | Expected `Err` |
|---|---|---|---|
| `lp_canonical` | 1184 B, untouched | none | `Ok`; `encapsulate()` → `Ok` |
| `lp_truncate_1183` | 1183 B | §7.2 step 1 (`384k+32`) | `Err(KeyRejected::TooSmall)` |
| `lp_append_1185` | 1185 B | §7.2 step 1 | `Err(KeyRejected::TooLarge)` |
| `lp_ek512_800` | 800 B of a real ML-KEM-512 ek | §7.2 step 1, cross-param | `Err(KeyRejected::TooSmall)` |
| `lp_ek1024_1568` | 1568 B of a real ML-KEM-1024 ek | §7.2 step 1, cross-param | `Err(KeyRejected::TooLarge)` |
| `lp_coeff0_3329` | 1184 B, coeff0 := 3329 | §7.2 step 2 (Eq 7.1) | `Ok` then `encapsulate()` → `Err` |
| `lp_coeff255_4095` | 1184 B, coeff255 := 4095 (correct offsets) | §7.2 step 2 | `Ok` then `encapsulate()` → `Err` |
| `lp_coeff0_3328` | 1184 B, coeff0 := 3328 | none | `Ok`; `encapsulate()` → `Ok` |
| `lp_rho_byte_set` | 1184 B, `ek[1183] = 0xFF` | none | `Ok`; `encapsulate()` → `Ok` |

The cross-param rows are the ones `formal/Formal/LengthCheck.lean` already proves
about (`cross_param_set_rejection`, `not_canonicalLength_wrong_k_2to4`), so they tie
the experiment to an existing kernel-checked result at zero extra cost. **VERIFIED**
that those theorems exist and are stated as described.

### 3.4 Plumbing for the library-parse family

`rustls_loopback` currently has no library-parse path; the Rust server only does
one handshake. Two options:

- **(a) Recommended — mutation spec passed from Go, crypto stays in Rust.**
  Go owns the byte offsets (single source of truth, and the file that has the bug);
  Rust owns the crypto. Add env vars alongside the existing
  `RUSTLS_LOOPBACK_PORT` / `_MODE` / `_VARIANT_NUM`:
  - `RUSTLS_LOOPBACK_MUTATE=382=F0,383=FF` — byte-offset/value pairs applied to a
    freshly generated ek before parsing
  - `RUSTLS_LOOPBACK_RESIZE=1183` — truncate/extend to an exact length before parsing
  Rust replies `RESULT|{"ok":..,"error":..,"class":"too_small"|"too_large"|"encap_failed"|"ok",..}`.
  This sidesteps duplicating the layout constants in a second language, which is
  how the current defect escaped notice in the first place.

- **(b) Self-contained Rust cell** that generates its own key and applies its own
  edits. Simpler to wire, but it duplicates `polyLo`/`tailHi` into `main.rs` and
  creates a second place for the same class of bug. Not recommended.

The Rust server should run this cell **before** binding the listener (or in a
second binary), and exit, so the Go harness can treat it exactly like
`runWireCell`. The Go harness needs `awslc_rs` added as a direct dependency — it is
already a transitive dep of `rustls`, but the direct dep list is currently only
`rustls`, `rustls-pki-types`, `aws-lc-rs`, `rcgen`, `log`, `env_logger`
(`rustls_server/Cargo.toml:12-18`). **VERIFIED** — `aws-lc-rs` is already declared.

---

## 4. Distinguishing the two rejection mechanisms

### 4.1 At the wire layer they are provably indistinguishable — VERIFIED

Both arms map to the *same* constant. From the pinned sources:

```rust
// pq/mod.rs
pub(crate) const INVALID_KEY_SHARE: Error =
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

// pq/hybrid.rs  — share-length failure
.ok_or(INVALID_KEY_SHARE)?;

// pq/mlkem.rs   — length failure inside EncapsulationKey::new, AND modulus
                // failure inside encapsulate(); BOTH .map_err(|_| INVALID_KEY_SHARE)
```

`MlKem::start_and_complete` at `v/0.23.43`:

```rust
let encaps_key = kem::EncapsulationKey::new(self.alg, client_share)
    .map_err(|_| INVALID_KEY_SHARE)?;
let (ciphertext, shared_secret) = encaps_key
    .encapsulate()
    .map_err(|_| INVALID_KEY_SHARE)?;
```

The `|_|` discards the `KeyRejected` / `Unspecified` distinction. And
`server/tls13.rs` `emit_server_hello` wraps the whole thing in one
`send_fatal_alert(AlertDescription::IllegalParameter, err)`. So there is exactly
one wire-visible outcome. **VERIFIED.**

I also read all of `server/tls13.rs` looking for a log statement between
`start_and_complete` and `send_fatal_alert` that would leak the cause. **There is
none** — the two calls are adjacent with no intervening `debug!`/`trace!`. So
raising rustls's log level will **not** separate them. That closes off the
"just turn on debug logging" option; **VERIFIED**.

(The `logging` feature is already enabled in `Cargo.toml:13`, and `main.rs:45-47`
sets `default_filter_or("warn")` — but per the above, there is nothing at that site
to log. Raising it is harmless but useless for this purpose.)

### 4.2 At the library-parse layer they are cleanly distinguishable — VERIFIED

This is the answer to "consider whether a distinct error signature distinguishes
them". Yes — and it is a *type-level* distinction, not a string match:

| Failure | Layer | Rust type | Caller-visible signal |
|---|---|---|---|
| §7.2(a) length | `EncapsulationKey::new` | `Result<_, KeyRejected>` | `KeyRejected::TooSmall` / `TooLarge` |
| §7.2(b) modulus | `.encapsulate()` | `Result<_, Unspecified>` | `Unspecified` from `encapsulate()` |

From aws-lc-rs v1.18.0 `kem.rs`:

```rust
pub fn new(alg: &'static Algorithm<Id>, bytes: &[u8]) -> Result<Self, KeyRejected> {
    match bytes.len().cmp(&alg.encapsulate_key_size()) {
        Ordering::Less    => Err(KeyRejected::too_small()),
        Ordering::Greater => Err(KeyRejected::too_large()),
        Ordering::Equal   => Ok(()),
    }?;
    let pubkey = LcPtr::new(unsafe {
        EVP_PKEY_kem_new_raw_public_key(alg.id.nid(), bytes.as_ptr(), bytes.len())
    })?;
    Ok(EncapsulationKey { algorithm: alg, evp_pkey: pubkey })
}
```

`KeyRejected` carries `TooSmall` / `TooLarge` as distinct variants; `encapsulate()`
returns `Unspecified`. The `aws-lc-rs` test suite already asserts exactly this
distinction in `test_kem_wrong_sizes`. **VERIFIED.**

Note the contrast with Go, which needed **string matching** to make the same
distinction — `go_loopback/main.go:99-109` `classifyLibErr` greps the error text
for `"length"` vs `"encoding"`. Go collapses to `errors.New` with no typed
variants; aws-lc-rs keeps them. That is a real observation about the two stacks'
error surfaces, not a harness artifact, and it is worth recording.

### 4.3 Consequence for the finding's text

`fnd-2026-0005.yaml:61-66` says the collapse is because "the BoringSSL-derived
code does not distinguish length-class from modulus-class at the rustls API
surface". That is **correct but now precisely stated**: the collapse happens in
`pq/mlkem.rs` at `map_err(|_| INVALID_KEY_SHARE)`, not in BoringSSL and not in
rustls' public API. BoringSSL *does* distinguish (too_small/too_large vs
encaps failure) — rustls discards it one layer up. The corrected sentence belongs
in the finding's `limitations`.

---

## 5. Re-run feasibility and effort

### 5.1 Is run 33267918229 still live? — VERIFIED

```
$ gh run view 33267918229 --repo dp1x/frontier --json ...
{"conclusion":"success","createdAt":"2026-08-29T18:18:50Z","databaseId":33267918229,
 "headBranch":"main","status":"completed","workflowName":"rustls-loopback"}
```

Readable, completed, successful. Its committed artifacts
(`interop/protocol-placement/rustls_loopback/reports/`) are byte-identical to what
the harness would produce today — I diffed the TSV against the console log and they
agree row-for-row.

Note `headBranch: main`, **not** `mission/msn-2026-0005-ci` as `exp-2026-0019`
implies; and `git branch -a --list "*msn-2026-0005*"` returns nothing locally, so
the `push:` trigger at `rustls-loopback.yml:12-14` is currently dead. Only
`workflow_dispatch` and the weekly cron (`cron: "0 6 * * 1"`, line 16) can fire.

### 5.2 Can it be re-run? — YES

`gh workflow run rustls-loopback.yml --repo dp1x/frontier` (the command already
recorded in `rpr-2026-0005.yaml:30`). Triggers and permissions are unchanged
(`workflow_dispatch` at line 10; `permissions: contents: read` at line 19 — no
secrets, so no PR-exposure concern from `Agents.md`).

### 5.3 What it needs

Already fully specified in `.github/workflows/rustls-loopback.yml:28-58`:

1. `apt-get install cmake nasm pkg-config` — for the aws-lc-sys C build
2. `dtolnay/rust-toolchain@stable`
3. `cargo build --release` — **this is the long pole** (aws-lc-sys compiles BoringSSL-derived C)
4. `actions/setup-go@v5` with `go-version: "1.26.4"`
5. `go run .` with `RUSTLS_SERVER_BIN` pointed at the built binary

Nothing needs to change in the workflow for the harness fixes. The only workflow
change worth considering is pinning `ubuntu-24.04` instead of `ubuntu-latest`,
given `rev-2026-0018`'s forward-risk note that `ubuntu-latest` moves to 26.04 in
November 2026 and every workflow here is unpinned.

### 5.4 Effort estimate — INFERRED

| Item | Estimate | Basis |
|---|---|---|
| Fix 2 constants + fix `cut` + delete 1 wire row | ~15 min | 4 lines; offsets verified above |
| Add library-parse family (Go + Rust, option (a)) | 2-4 h | 1 new env-var contract, 1 Rust cell, 1 Go runner, 9 rows |
| Add the 2 ACCEPTED wire controls + rho library row | ~30 min | reuses existing `applyEdit` shape |
| Fix the 9 propagated artifact cells (§1.7) | 1-2 h | mechanical, but needs care not to overstate |
| One GHA run + artifact review | ~15 min | `exp-2026-0019` records ~2 min build; budget 5-10 min wall |
| **Total** | **~1 session (4-6 h)** | single implementation agent, one CI round-trip |

This is **medium** class per `Agents.md` compute routing → GitHub Actions, **not**
local. A local `cargo build --release` of aws-lc-sys is exactly the heavy build
tree the constitution forbids persisting (`rustls_server/target/`); the workflow
already rebuilds it from scratch.

### 5.5 Pin drift

`Cargo.toml:15` pins `rustls = "=0.23.43"` exactly; `Cargo.lock` resolves
aws-lc-rs 1.18.0 / aws-lc-sys 0.44.0. The audit reports rustls 0.23.44 and
0.23.45 released since, with `pq/hybrid.rs` blob-SHA identical between 0.23.43 and
0.23.45 and the property holding at 0.23.45 (`2976d90f`).

**Recommendation:** bump to `=0.23.45` in the *same* change, so the corrected
matrix is produced at a non-stale pin. That costs nothing and removes a stale-pin
finding from `rev-2026-0018`'s list. I did **not** re-verify the 0.23.45 blob
identity this session — **INFERRED from the audit**; treat as needing one
`git ls-tree` before the bump is claimed.

---

## 6. What I could not determine

1. **Whether the C layer adds a check beyond the length compare.**
   I read `aws-lc-rs/src/kem.rs` at tag `v1.18.0` and confirmed `EncapsulationKey::new`
   does length-then-`EVP_PKEY_kem_new_raw_public_key`. I did **not** fetch
   `crypto/fipsmodule/evp/p_kem.c` or `crypto/fipsmodule/ml_kem/mlkem/kem.c` at
   `aws-lc-sys 0.44.0`. The audit read those at `main`, not at the pinned tag, and
   says so. **COULD-NOT-DETERMINE** whether `mlk_kem_check_pk` is byte-identical at
   0.44.0.

2. **Whether a modulus-overflow 1184-byte ek is accepted by
   `EncapsulationKey::new`.** My library-parse design (§3.3) *assumes* it is —
   `new()` succeeds and `.encapsulate()` is what fails. That follows from the Rust
   source doing only a length check, plus aws-lc #2891 as relayed by the audit.
   I did not verify #2891 myself this session. **INFERRED.** The experiment is
   designed to *test* this assumption rather than rely on it, which is why
   `lp_coeff0_3329` expects `Ok`-then-`Err` and would fail loudly if wrong.

3. **Whether rustls 0.23.45's `pq/hybrid.rs` is blob-identical to 0.23.43.**
   Audit claim, not re-verified here. **INFERRED.**

4. **Whether a §7.2(a) length stimulus is reachable through *any* rustls
   configuration** — e.g. a non-PQ-first hybrid group, a future group with a
   variable-length classical half, or QUIC. I proved unreachability for
   `X25519MLKEM768` at `v/0.23.43` from `Layout::split`. I did not survey other
   groups or the `Hybrid` impl's other call sites. **COULD-NOT-DETERMINE.**

5. **Actual GHA wall-clock cost of a re-run.** `exp-2026-0019.compute_decision`
   says "~2 min on GHA"; I did not fetch job timings. **INFERRED.**

6. **Whether the Go harness's wire `truncate_last_byte` row can be salvaged.**
   Its committed result is `no-alert-seen:EOF` / `UNMET`
   (`go_loopback_report.tsv:13`), so it is inconclusive today. Whether fixing its
   offset to `d + ekSize - 1` would produce `illegal_parameter` is untested.
   **COULD-NOT-DETERMINE** — though by the Go `crypto/tls` structure it likely
   would, since Go's `key_schedule.go` splits the hybrid share with its own length
   logic rather than a fixed `Layout::split` equivalent. That last point is
   **INFERRED** from `go_loopback/main.go:623-624`'s CITE line; I did not read
   Go's `crypto/tls` hybrid split at the pinned Go version.

7. **The disposition of `rpr-2026-0005.yaml` (`status: reproduced`) and
   `vrf-2026-0006.yaml`.** A reproducer whose matrix contains a mislabeled row and
   a non-§7.2 row arguably cannot stand as `reproduced` for the claim it names.
   That is a synthesizer's call under `Agents.md`, not mine. **Flagged, not decided.**

---

## Appendix — reproducibility of this analysis

Two scratch scripts, both gitignored (`.gitignore:29`), both re-runnable:

- `.scratch/fips203_layout_check.py` — independent `BitsToBytes`/`BytesToBits`/
  `ByteEncode₁₂`/`ByteDecode₁₂` transcribed from FIPS 203 Algorithms 3/4/5/6, with
  five self-tests that run before any conclusion (including `decode(encode(f)) == f`
  and `ByteDecode₁₂(4095) == 766 == 4095 mod 3329`). Prints the layout, the
  coefficient→offset table, the mutation-target diff, and an assertion that the
  corrected offsets produce coeff255 = 4095.
- `.scratch/truncation_check.py` — isolates the `cut` arithmetic in §1.3.

Primary sources fetched this session, all at pinned tags:
`rustls/rustls` tag `v/0.23.43` — `pq/hybrid.rs`, `pq/mlkem.rs`, `server/tls13.rs`;
`aws/aws-lc-rs` tag `v1.18.0` — `src/kem.rs`. FIPS 203 text via
`.scratch/formal-203-r2/fips_full.txt`, cross-checked against
`localdocs/refs/fips203.pdf` and `formal/Formal/LengthCheck.lean`.
