<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_fnd_0007.md -->

# Adversarial audit — fnd-2026-0007 (CIRCL v1.6.5 X-Wing + HPKE conformance)

**Auditor role:** adversarial-critic (goal: disprove)
**Date:** 2026-10-03
**Mode:** READ-ONLY. No repo files edited, no commits made. Only scratch report written (`.scratch/audit_fnd_0007.md`).
**Target:** `knowledge/findings/fnd-2026-0007.yaml` (`status: verified_conclusion`, `disclosure: public`)

---

## 1. VERDICT

**CORRECTION NEEDED — do not publish as written. The core technical claim survives; the framing does not.**

I could not disprove the substance: CIRCL v1.6.5 really does implement X-Wing correctly, and really does reproduce the published reference vector corpus byte-for-byte. I verified this independently against primary sources, not against the repo's own records.

What I **did** disprove is the finding's evidence framing and four of its specific factual assertions. Three are outright wrong; one is self-refuting. A `verified_conclusion` that carries three false numbers and a revision label attached to a moving draft is not safe to publish as-is.

| # | Finding's claim | Status | Verdict |
|---|---|---|---|
| 1 | X-Wing KAT hash matches published reference | **VERIFIED (independently)** | Substance holds |
| 2 | "3 of 3 test vectors" as a conformance result | **MISLEADING** | Overstated; see §3 |
| 3 | "HPKE … 127 of 127 supported RFC 9180 test vectors" | **FALSE** | Real figure is **96 of 96**; corpus is 128 total, 32 skipped — see §4 |
| 4 | "16 export-only AEAD test vectors skipped" | **FALSE** | Real figure is **32**; undercounts by 16 |
| 5 | "draft-08 changed ek_KEM to ek_X in the SHA3 input" | **FALSE** | No such change in any revision -05…-11 — see §2 |
| 6 | Pins conformance to "draft-05" | **MISLEADING** | Vectors are identical -05…-11; label should be "≥ -05, current -11" |
| 7 | Reproducer path / cited evidence | **DEFECT** | Cites a non-existent vectors file; local KAT harness admits it never ran the KATs — see §3.4 |

The single most serious defect is #3/#4: **the HPKE conformance number in a `verified_conclusion` is wrong by a wide margin and was never actually measured.** It appears to have been read off a partial log. Combined with #5, this means the artifact's two headline quantitative claims are both unreliable.

---

## 2. Draft-revision mismatch analysis (the specific trap)

**The trap did NOT fire — but not for the reason the framing implies.** The finding treats "draft-05" as a *distinguishing* pin that separates it from the "real" spec. It isn't. The trap was pre-empted upstream.

### 2.1 Current revision

`https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem` resolves to **draft-connolly-cfrg-xwing-kem-11**, published **23 September 2026**, expiring 27 March 2027. **VERIFIED.**

The repo's own scope artifact `spc-2026-0002` locks scope to **draft-10 (2 March 2026)** and calls it "the latest available." That is now two revisions stale. `spc-2026-0002:33` — *"Audit scope locked to draft-10 (March 2026, latest available)."* Scope artifact needs refresh; not fnd-2026-0007's fault but it inherits the staleness.

### 2.2 Combiner — identical across all revisions checked

draft-11 §5.3 **Combiner**, verbatim:

```
def Combiner(ss_M, ss_X, ct_X, pk_X):
  return SHA3-256(concat(
    ss_M,
    ss_X,
    ct_X,
    pk_X,
    XWingLabel
  ))
```

where `XWingLabel` is the 6-byte ASCII string, **in hex `5c2e2f2f5e5c`**. **VERIFIED.**

I fetched and read draft-05 (§5.3), draft-08 (§5.3) and draft-11 (§5.3). **All three are identical**: same input order `(ss_M, ss_X, ct_X, pk_X)`, same trailing label, same SHA3-256. draft-05, -08 and -11 also agree on sizes (§5.1: sk 32 / pk 1216 / ct 1120 / ss 32), on `EncapsulateDerand` (§5.4.1), on `Decapsulate` (§5.5), and on the HPKE `DeriveKeyPair` (§5.6).

So **draft-05's combiner still matches the current revision. The X-Wing core has not drifted.** The finding's technical pin is sound. **VERIFIED.**

### 2.3 CIRCL's implementation matches all three

`https://raw.githubusercontent.com/cloudflare/circl/v1.6.5/kem/xwing/xwing.go`, `combiner()` — writes `ssm`, `ssx`, `ctx`, `pkx`, then the 6-byte literal:

```go
h.Write(ssm[:]); h.Write(ssx[:]); h.Write(ctx[:]); h.Write(pkx[:])
//   \./
//   /^\   -- h.Write([]byte(`\.//^\`))    [= 5c2e2f2f5e5c]
h.Read(out[:])
```

Byte-identical to draft-11 §5.3. CIRCL is conformant to **-05, -08 and -11 alike** in the combiner. **VERIFIED.**

### 2.4 The `ek_KEM → ek_X` claim is fabricated

`fnd-2026-0007` `limitations:` states:

> *"CIRCL implements X-Wing draft-05 (per its package docstring), not draft-08 (which changed ek_KEM to ek_X in the SHA3 input)."*

Repeated at `exp-2026-0022.yaml:57-59` and `rev-2026-0007.yaml:45`:

> *"the combiner changed between draft-05 and draft-08 (ek_KEM to ek_X) — this single-byte-string swap … would produce a different ss"*

**This is false.** No revision -05 through -11 uses `ek_KEM` in the combiner. Draft-04's change log (`draft-05` §E.1, mirrored in -08 §G.4 and -11 §G.4) reads:

> *"Move label at the end. As everything fits within a single block of SHA3-256, this does not make any difference."*

The pre-05 change was to the **label**, not to a key component — and the draft itself states it is byte-neutral. The name `ek_KEM` never appears in any combiner. I read the full combiner in draft-05, -08 and -11 and searched the change logs. **VERIFIED FALSE.**

**Consequence:** the finding's central *epistemic caveat* — that draft-05 conformance does not imply draft-08 conformance because the combiner changed — is built on a non-existent change. The caveat is not merely unnecessary, it is **misleading**: it tells a reader that CIRCL v1.6.5 might be stale relative to the current spec, when in fact the X-Wing KEM has been bit-stable since -05 and CIRCL is current. The `follow_up` item *"Verify X-Wing draft-08 KAT conformance separately once draft-08 vectors are available"* and *"Conformance to draft-08 is NOT separately verified"* should be struck, not carried forward. Draft-08 vectors were available (published 3 May 2025) and are byte-identical to -05's — so "once vectors are available" was already satisfiable at the time of writing.

### 2.5 Doc-comment provenance note (minor, not a defect)

`spc-2026-0002:20-21` cites CIRCL's comment as *"Implements the final version"* with draft suffix `"-05"`. The actual v1.6.5 comment reads:

```go
//	https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem
//
// Implements the final version (-05).
```

"the final version (-05)" — the repo's parenthetical quote in `spc-2026-0002` is a **misquote**. The `-05` is real, so the finding's reliance on it is fine; but `spc-2026-0002` should be corrected. `fnd-2026-0007` itself says "per its package docstring," which is accurate.

---

## 3. KAT provenance: draft vectors vs self-generated

### 3.1 Not self-generated — the vectors ARE the draft's, byte-for-byte

I fetched **draft-05** (`https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-05.txt`) and **draft-11** (datatracker) and compared their Appendix C test vectors against the repo's own `.scratch/xwing/reports/kat_log.txt`.

**All three sources carry byte-identical vectors.** Anchors, identical in draft-05 Appendix C, draft-11 Appendix C, and `kat_log.txt`:

```
seed   7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
pk     e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b1...
eseed  3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2...
ct     b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a2...
ss     d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384
ss     f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150
ss     953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f
```

`kat_log.txt` (the Go test output) reproduces the draft's vectors exactly, line for line, including the draft's own 74-column hex wrapping. **The "circular self-generated vector compared against a self-recorded hash" attack fails.** These are the draft's vectors. **VERIFIED — substance of claim #1 holds.**

Note draft-08 Appendix C also carries the identical three vectors (verified by fetching `draft-connolly-cfrg-xwing-kem-08.txt`).

### 3.2 The hash is real and traceable — but it is *not* in the draft

`1bcd0057d861d6b866239936cadcaeee1ec0164dedc181c386e9e54fe46156fe` **does not appear in any X-Wing draft.** It is a **commit-time constant inside CIRCL's own test**, `kem/xwing/xwing_test.go`:

```go
// shake128 of spec/test-vectors.txt from X-Wing spec at
// https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem
want := "1bcd0057d861d6b866239936cadcaeee1ec0164dedc181c386e9e54fe46156fe"
if got != want {
    t.Fatalf("%s ≠ %s", got, want)
}
```

**VERIFIED.** The test computes SHAKE-128 over its own formatted output and compares to this constant. The constant is a *digest of the draft's Appendix C vectors* — so it is a legitimate published reference hash, exactly as `fnd-2026-0007` describes. Two nuances the artifact should state:

- The hash is **not a draft-published constant**. It is CIRCL's assertion about the draft's vectors. To call it "the published draft-05 reference hash" is one inferential step stronger than the evidence.
- It is **unattributed to a specific draft revision** by its own comment (it links the *unversioned* draft URL). Since -05/-08/-11 vectors are identical, this is immaterial to the result — but it means the hash pins *the vectors*, not *a revision*. Which is precisely why pinning the finding to "draft-05" is an over-claim.

`web_search` for the hash failed (HTTP 426, CLI version too old), so I could not corroborate the hash via a third independent source. Provenance is nevertheless fully established from CIRCL source + three draft texts. **VERIFIED** from primary sources.

### 3.3 "3 of 3 test vectors" is a category error

`fnd-2026-0007` states the hash "matches … (3 of 3 test vectors pass)". But CIRCL's `TestVectors` does **not** assert three independent conformance checks. It runs one loop body three times, printing vectors, checking only `Encapsulate/Decapsulate` self-consistency, then compares **one** hash over the **concatenation of all three** to **one** constant.

So the real conformance assertion is **1 hash comparison over a 3-vector corpus**, not "3 of 3". Stated correctly: *"CIRCL reproduces the draft's 3-vector reference corpus exactly (single SHAKE-128 digest match against the reference constant published in CIRCL's test)."* The current phrasing inflates one assertion into three. **VERIFIED false as stated.**

### 3.4 Evidence-integrity defects in the repo's own scratch chain

These are process defects that undermine confidence in the numbers even where the numbers happen to be right.

**(a) The cited local KAT harness never ran the KATs.** `.scratch/xwing/test_xwing_kat.go` — the file that introduces `1bcd0057…` into the repo — is a stub. Its `katVectors` slice contains **one** entry with fabricated placeholder fields (`seed: "f3c1d2f1…"`, `pk` = that seed plus a count-up run, `ct: "00"`, `ss: "00"`). Its body discards every value (`_ = kat`, `_ = pass`, `_ = fail`) and prints:

```go
fmt.Printf("\nSkipping KAT cross-check: draft-05 KAT vectors not available locally.\n")
...
fmt.Printf("This hash was published in the X-Wing draft-05 spec\n")
fmt.Printf("Source: https://github.com/cloudflare/circl/blob/v1.6.5/kem/xwing/xwing_test.go\n")
```

Note the last two lines: it asserts the hash was *"published in the X-Wing draft-05 spec"* and cites **CIRCL's test file** as the source. Both are wrong (§3.2): the hash is not in the draft, and it is in CIRCL's test file — the file it claims the draft published it in. The real evidence is `go test`, whose output in `kat_log.txt` does **not** print the hash at all. So the hash assertion in the artifact is supported only by upstream source code, never by the local log. **VERIFIED defect.**

**(b) A cited vectors file does not exist.** `exp-2026-0021.yaml:62` command:

```
go run ./harness/circl_harness.go --mode=canonical --vectors=vectors/draft-08.json --out=...
```

`.scratch/xwing/vectors/` is **empty**. And `.scratch/xwing/harness/circl_harness.go` declares no `--vectors` flag (`main()` at line 267 parses only `-mode`, `-n`, `-out`). **The experiment's stated canonical command cannot have run as written.** **VERIFIED defect.**

**(c) The reproducer in the finding is wrong.** `fnd-2026-0007` `reproducer:` says `go build ./harness && go run ./harness --mode=canonical …`. But `harness/` is `package main` with two files (`circl_harness.go`, `debug.go`) and there are **two `func main()`** definitions — this cannot build as-is. Meanwhile a stray built binary `harness.exe` sits in `.scratch/xwing/`. The reproducer was not validated end-to-end. **VERIFIED defect.**

**(d) Deleted evidence.** `obs-2026-0029.yaml:19` cites `.scratch/xwing/harness/test_rfc.go` as the RFC 9180 Appendix A.1.1 key-schedule check and notes it as *"now deleted."* The key-schedule claim in the finding ("matches RFC 9180 §5.1 byte-for-byte") therefore rests on an artifact that no longer exists. **VERIFIED defect.**

**(e) `verify_reproducibility.py` is not a reproduction.** `.scratch/xwing/verify_reproducibility.py:12-16` defines `expected_canonical_ss/pk/ct` as literals *copied from the previous run's JSON*, then loads that same JSON and compares. Comment at line 10: *"Expected canonical X-Wing + HPKE values from the previous run (committed to the previous JSON; reproducible)."* This is a tautology — it re-reads committed outputs and checks them against themselves. It never re-runs the harness. `vrf-2026-0008` cites this as its "deterministic verification." **VERIFIED defect.**

**(f) `debug_hpke.py` contains a bug that was never fixed.** `.scratch/xwing/py_xwing/debug_hpke.py:66` builds `keySchCtx` as `b"\x00" + pskIDHash + infoHash`. RFC 9180 §5.1 requires `key_schedule_context = mode || psk_id_hash || info_hash` where **`mode` is a single byte: `0x01` for Base** (PSK/Auth/AuthPSK use `0x02`/`0x03`/`0x04`). The `0x00` is wrong. `rev-2026-0007.yaml:41` claims the schedule was checked *"byte-for-byte"* against RFC 9180 §5.1 — with `mode = 0x00`, every `key`, `base_nonce` and `exporter_secret` would differ from the RFC. The file was left unfixed. **VERIFIED defect.**

**(g) The mutation matrix's stated design was not executed.** `exp-2026-0021.yaml:36-43` designs mutations M1–M9 including *"M5: ss_X and ss_KEM swapped (argument-order)"*, *"M6: concat-order"*, *"M7: label-mixup"*. `circl_harness.go:188-217` implements **28 single-bit-flips of `eseed` only** — no M1–M4, no M5/M6/M7, no HPKE `info`/`aad` flips (M8/M9). The harness's own `Notes` (line 261) still carries the **superseded, wrong** expectation: *"Mutations at clamped X25519 bits (M0_0, M31_5, M31_6, M31_7, M32_0) are expected to produce the same ss."* — which `obs-2026-0028` had already corrected. **VERIFIED defect.**

The *substantive* mutation conclusion is fine — clamping at `eseed[32]` bit 0 and `eseed[63]` bit 7 follows directly from `x25519.KeyGen`'s RFC 7748 §5 clamping applied to `eseed[32:64]` (`kem/xwing/xwing.go`, `EncapsulateTo`). But it is a restatement of the implementation, not independent evidence of spec conformance, and it does not exercise the combiner at all.

---

## 4. HPKE / RFC 9180 claim — assessed separately

This is the weakest part of the finding, and it is **wrong**.

### 4.1 The finding's claim

> *"HPKE key schedule matches RFC 9180 §5.1 byte-for-byte and CIRCL passes 127 of 127 supported RFC 9180 test vectors."*
> *"the 16 export-only AEAD test vectors are skipped because CIRCL v1.6.5 does not implement the Export-Only AEAD"*

### 4.2 Ground truth (measured, not read off a log)

I downloaded CIRCL's own bundled corpus — `hpke/testdata/vectors_rfc9180_5f503c5.json.gz` at tag **v1.6.5** (1,692,035 bytes) — decompressed and counted:

```
TOTAL vectors in corpus:          128
KEM  IDs present:                  16, 18, 32, 33
KDF  IDs present:                  1, 3
AEAD IDs present:                  1, 2, 3, 65535
AEAD == 0xffff (export-only):      32
skipped indices:                   12–15, 28–31, 44–47, 60–63,
                                   76–79, 92–95, 108–111, 124–127
VALID (non-skipped) vectors:       96
```

- `128 - 32 = 96`. So the correct statement is **"96 of 96 supported vectors pass (32 export-only vectors skipped)."**
- The finding says **127 of 127** — impossible: 127 exceeds the total corpus size of 128 minus the 32 skipped, and no count of 127 arises from this corpus under any skip policy.
- The finding says **16** skipped — the corpus has **32**, exactly two consecutive groups of four per KEM variant (4 KEMs × 2 KDFs × 4 AEAD-configs × 4 modes = 128; the export-only block is 32).

`obs-2026-0029.yaml:30` lists the skipped set as *"v12-v15, v28-v31, v44-v47, v60-v63, v76-v79, v92-v95, v108-v111, v124-v127"* — **that enumeration is exactly right and matches the corpus I measured.** So the observation layer had the correct data; the synthesis into `fnd-2026-0007` corrupted it into 127/16. **VERIFIED — both figures false.**

### 4.3 What is genuinely true here

- **KEM_XWING = 0x647a is real.** `hpke/algs.go:43` → `KEM_XWING KEM = 0x647a`, wired at `algs.go:285-286` (`kemXwing.Scheme = xwing.Scheme()`, name `HPKE_KEM_XWING`). Matches draft-11 §7 (*"25722 = 25519 + 203 = 0x647a"*). **VERIFIED.**
- **The Export-Only AEAD genuinely is unimplemented.** `hpke/vectors_test.go:40-42` skips on `!aead.IsValid()`; the finding's quoted docstring (*"BUG(cjpatton): This package does not implement the 'Export-Only' mode of the HPKE context"*) is consistent with the skip behaviour. The *reason* for skipping is correct. **VERIFIED.**
- **RFC 9180 vectors really are the official ones.** `vectors_test.go:26-28` loads `testdata/vectors_rfc9180_5f503c5.json.gz` from `https://github.com/cfrg/draft-irtf-cfrg-hpke`. This answers the brief's question directly: **yes, the official RFC 9180 vectors are used.**
- **X-Wing is not exercised by any RFC 9180 vector.** The corpus KEM IDs are 16/18/32/33 (DHKEM P-256/P-384/X25519/X448). **No X-Wing vector exists.** So this test says nothing about X-Wing-in-HPKE.

### 4.4 The overclaim

The RFC 9180 corpus exercises **DHKEM only**. `fnd-2026-0007` bundles it under a finding titled *"X-Wing (draft-05) **and HPKE (RFC 9180)** is byte-exact conformant"*, and `obs-2026-0029.yaml:38` states:

> *"The CIRCL X-Wing (KEM_XWING = 0x647A) + HPKE Base mode … is byte-exact RFC 9180 conformant, verified via test-vector pass."*

**That inference is invalid.** The 96 passing vectors contain no X-Wing. The only X-Wing+HPKE evidence is `obs-2026-0027`'s single self-roundtrip (`circl_harness.go:100-149`: NewSender → Setup → Seal → NewReceiver → Setup → Open, asserting only that Open returns the plaintext). That proves **internal consistency of one library with itself**, not RFC 9180 conformance and not interoperability. The supporting key-schedule script had `mode = 0x00` instead of `0x01` (§3.4f) and was deleted (§3.4d).

**The X-Wing+HPKE interop question is therefore still entirely open** — which is the one thing the finding's own `follow_up` already flags, but the summary sentence implies otherwise.

---

## 5. Novelty / has anything changed since v1.6.5

- **CIRCL v1.6.5 is the latest release.** `api.github.com/repos/cloudflare/circl/releases/latest` → `tag_name: v1.6.5`, `published_at: 2026-08-05T17:04:08Z`. **VERIFIED.** No successor release. The pin is current.
- **The v1.6.5 changelog contains no X-Wing or HPKE-conformance fix.** All 56 entries are in ascon, dilithium, ecc, ed448, frodo, kyber, oprf, tss, zk, etc. Only two touch HPKE, both robustness (`Fix HPKE/KEM exact-length key unmarshaling` #627; `hpke: don't panic when unmarshalling opener/sealer from empty buffer` #656) — neither alters the key schedule. **VERIFIED.**
- **No upstream X-Wing KAT mismatch issue found.** `web_search` was unavailable this session (HTTP 426), so this is **COULD-NOT-DETERMINE** rather than a clean negative. Circumstantial support for "no drift": the draft still lists CIRCL in Appendix A implementations (draft-11 §A.1.2.2.1 → CIRCL PR #471) while annotating *other* libraries as lagging (*"xwing-kem.rs … implements the older `-00` version"*, draft-11 §A.1.2.1.2). The authors do not flag CIRCL as stale. **INFERRED (weak).**

---

## 6. Safe-to-disclose, or correction needed?

**CORRECTION NEEDED.** Not safe to publish as `verified_conclusion` with `disclosure: public` in its current form.

No security disclosure risk is implicated — nothing here suggests a vulnerability in CIRCL; if anything the audit **strengthens** confidence that CIRCL's X-Wing is correct. The problem is accuracy of the artifact, which is the repo's own constitutional requirement ("Never fabricate: no invented … versions, results"). Three numbers and one draft-delta claim do not survive checking.

**Substance that survives and should be retained:**
- CIRCL v1.6.5 reproduces the X-Wing reference vector corpus byte-for-byte (independent check against draft-05, -08, -11 Appendix C).
- CIRCL v1.6.5's combiner matches draft-11 §5.3 exactly — X-Wing has been bit-stable since -05, so CIRCL is **current**, not stale.
- Export-Only AEAD is genuinely unimplemented; the skip is legitimate (at 32 vectors, not 16).
- KEM_XWING = 0x647a matches draft §7.
- RFC 9180 official vectors are used (96/96 pass).
- Determinism, clamping positions and entropy results are sound as reported.

**Required corrections:**

1. **`limitations:`** — delete "not draft-08 (which changed ek_KEM to ek_X in the SHA3 input)" and "Conformance to draft-08 is NOT separately verified." Strike the `follow_up` item *"Verify X-Wing draft-08 KAT conformance separately once draft-08 vectors are available"*. Replace with: combiner verified identical across -05/-08/**-11**; CIRCL v1.6.5 is conformant to the current revision.
2. **Re-label the pin.** "draft-05" is not a meaningful discriminator. Say: conformant to the X-Wing construction as of draft-**11** (2026-09-23), whose combiner and vectors are unchanged since -05.
3. **HPKE numbers.** Replace "127 of 127 … 16 export-only … skipped" with **"96 of 96 supported vectors pass; 32 export-only-AEAD vectors skipped (corpus of 128; KEM IDs 16/18/32/33)."**
4. **Scope the HPKE claim.** Amend the "X-Wing + HPKE Base mode is byte-exact RFC 9180 conformant, verified via test-vector pass" — the RFC 9180 corpus contains **no X-Wing vectors**. Downgrade X-Wing+HPKE to "single-implementation self-roundtrip only; conformance/interop not established."
5. **Fix "3 of 3 test vectors."** It is one digest match over a 3-vector corpus, not 3 independent vector passes.
6. **Fix hash attribution.** `1bcd0057…` is a constant in CIRCL's `xwing_test.go`, not a constant published in any draft. Cite it as such.
7. **Do not let this finding's evidence rest on scratch.** Repair or retire: `test_xwing_kat.go` (never ran), `vectors/draft-08.json` (absent), the `--vectors` flag (nonexistent), the two-`main()` `harness` build (unbuildable), `verify_reproducibility.py` (tautological), `test_rfc.go` (deleted), `debug_hpke.py` (`mode=0x00` bug), and the 7 designed mutations M1–M9 (7 of 9 never implemented). Per `Agents.md`, scratch is disposable — **committed artifacts must not cite scratch paths as their evidence base.**
8. **Refresh `spc-2026-0002`.** Scope is pinned to draft-10; current is -11. Also correct its misquote of CIRCL's doc comment (*"Implements the final version (-05)"*, not *"Implements the final version"* with a separate `-05` suffix).

**Process observation (conservative, for `knowledge/process-findings/` if desired):** the numbers `127` and `16` did not survive one pass of reading the source corpus, while the *correct* enumeration was already sitting in `obs-2026-0029` at the observation layer. The failure was introduced during synthesis, not during execution. `obs-2026-0029` additionally **contradicts itself** — its summary is "the previously-recorded obs-2026-0029 was based on a misread" while the artifact *is* `obs-2026-0029`. A synthesis step that re-derives quantitative claims from prose instead of copying them from the observation layer is the weakest link here.

---

## Appendix — claim ledger

| Claim | Source | Status |
|---|---|---|
| Current X-Wing revision is draft-11, 2026-09-23 | datatracker | **VERIFIED** |
| draft-11 §5.3 combiner `(ss_M,ss_X,ct_X,pk_X)` + label `5c2e2f2f5e5c` | draft-11 | **VERIFIED** |
| draft-05 / -08 / -11 combiners identical | all three texts read | **VERIFIED** |
| CIRCL `combiner()` matches all three | `kem/xwing/xwing.go` @v1.6.5 | **VERIFIED** |
| CIRCL doc comment: "Implements the final version (-05)" | `kem/xwing/xwing.go` @v1.6.5 | **VERIFIED** |
| `ek_KEM → ek_X` change ever existed | absent from -05/-08/-11 change logs | **VERIFIED FALSE** |
| KAT vectors are the draft's, not self-generated | draft-05 App. C ≡ draft-11 App. C ≡ `kat_log.txt` | **VERIFIED** |
| `1bcd0057…` present in any X-Wing draft | not in -05/-08/-11 | **VERIFIED ABSENT** |
| `1bcd0057…` is CIRCL's test constant | `kem/xwing/xwing_test.go` @v1.6.5 | **VERIFIED** |
| "3 of 3 test vectors" = 3 assertions | `xwing_test.go` (one loop, one hash) | **VERIFIED FALSE** |
| RFC 9180 corpus size = 128 | decompressed @v1.6.5 | **VERIFIED** |
| Export-only (AEAD 0xffff) vectors = 32 | decompressed @v1.6.5 | **VERIFIED** |
| Supported (non-skipped) vectors = 96 | 128 − 32 | **VERIFIED** |
| Finding's "127 of 127" / "16 skipped" | contradicted by corpus | **VERIFIED FALSE** |
| RFC 9180 vectors contain no X-Wing | KEM IDs 16/18/32/33 only | **VERIFIED** |
| `KEM_XWING = 0x647a` | `hpke/algs.go:43` @v1.6.5 | **VERIFIED** |
| v1.6.5 is latest CIRCL release | api.github.com releases/latest | **VERIFIED** |
| No X-Wing fix in v1.6.5 changelog | 56-entry changelog read | **VERIFIED** |
| Upstream X-Wing KAT-mismatch issue | `web_search` HTTP 426 | **COULD-NOT-DETERMINE** |
| CIRCL not flagged stale by draft authors | draft-11 App. A annotations | **INFERRED (weak)** |
| `debug_hpke.py` uses `mode=0x00` not `0x01` | file read; RFC 9180 §5.1 | **VERIFIED** |
| `vectors/draft-08.json` absent; `--vectors` flag nonexistent | dir listing + harness `main()` | **VERIFIED** |
| `verify_reproducibility.py` is self-comparing | file read | **VERIFIED** |
