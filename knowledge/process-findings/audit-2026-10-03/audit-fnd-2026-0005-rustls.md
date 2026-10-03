<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_fnd_0005.md -->

# Adversarial audit — fnd-2026-0005 (rustls 0.23.43 + aws-lc-rs 1.18, X25519MLKEM768 §7.2)

**Auditor role:** adversarial-critic (goal: disprove)
**Date:** 2026-10-03
**Target:** `knowledge/findings/fnd-2026-0005.yaml` (`status: verified_conclusion`, `disclosure: public`)
**Mode:** READ-ONLY. No repo files edited, no commits. All work in `.scratch/` (gitignored, confirmed via `git check-ignore -v`).

---

## 1. VERDICT

**PARTIALLY SUPPORTED — the security property is real; the finding's evidentiary support is overstated and internally mislabeled. Correction needed before any disclosure.**

Three separable judgments:

| Claim | Verdict |
|---|---|
| **A.** rustls/aws-lc rejects modulus-invalid client ek at the handshake boundary with `illegal_parameter` | **VERIFIED** — correct at the pinned versions, traced to the leaf |
| **B.** All 4 stimuli are distinct, correctly-named §7.2 violations | **REFUTED** — 2 of 4 labels are wrong; `truncate_last_byte` is not a §7.2 stimulus at all |
| **C.** "§7.2 check enforced" (both halves) | **OVERCLAIM** — only the MODULUS half is exercised; the LENGTH half is never tested, and was never reachable in this harness |

I could not disprove the core positive claim. I **did** disprove parts of the evidence that supports it. Per the repo's own constitution ("Model consensus is never evidence", "Never make an output sound more impressive by overstating evidence"), the finding as written must not ship as `verified_conclusion` with its current stimulus names.

The sibling-finding failure mode named in my brief ("read a wrapper and stop one layer above the real check") is **not** reproduced here — I traced to the mlkem-native leaf. But a different instance of the same *class* is present: the harness's own comments assert what its code does, and two of those assertions are false.

---

## 2. CLAIMED vs ACTUAL (file:line)

### 2A. Leaf trace — the check IS enforced (VERIFIED)

Server-side path, all at rustls `v/0.23.43` = commit `fcf61cdbba30913cfd5b40aefa83989c6233812d` (tag verified via `api.github.com/repos/rustls/rustls/git/ref/tags/v/0.23.43`; release tag is `v/0.23.43`, **not** `v0.23.43` — the artifact's cited URL `releases/tag/v0.23.43` 404s).

1. `rustls/src/crypto/aws_lc_rs/pq/mod.rs:66` — `const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);`
2. `rustls/src/crypto/aws_lc_rs/pq/mod.rs:16-26` — `X25519MLKEM768` is a `hybrid::Hybrid` with `post_quantum_client_share_len: MLKEM768_ENCAP_LEN` (= 1184), `classical_share_len: X25519_LEN` (= 32), `post_quantum_first: true`.
3. `rustls/src/server/tls13.rs` `emit_server_hello()` — `kxgroup.start_and_complete(&share.payload.0).map_err(|err| cx.common.send_fatal_alert(AlertDescription::IllegalParameter, err))`. **This is the spec-mandated alert mapping** (draft-ietf-tls-ecdhe-mlkem-05 §4.2: "the server MUST perform the encapsulation key check described in Section 7.2 of [NIST-FIPS-203] … and abort with an illegal_parameter alert if it fails").
4. `rustls/src/crypto/aws_lc_rs/pq/hybrid.rs:35-67` — `Hybrid::start_and_complete` → `split_received_client_share(client_share).ok_or(INVALID_KEY_SHARE)?` → `self.post_quantum.start_and_complete(post_quantum_share)`. The **length** gate is `Layout::split()`: `if share.len() != self.classical_share_len + post_quantum_share_len { return None }`.
5. `rustls/src/crypto/aws_lc_rs/pq/mlkem.rs:34-44` — `MlKem::start_and_complete` → `kem::EncapsulationKey::new(self.alg, client_share).map_err(|_| INVALID_KEY_SHARE)?` then `.encapsulate().map_err(|_| INVALID_KEY_SHARE)?`.
6. **LEAF 1 (Rust):** `aws-lc-rs/src/kem.rs` `EncapsulationKey::new` — `match bytes.len().cmp(&alg.encapsulate_key_size()) { Less => Err(KeyRejected::too_small()), Greater => Err(KeyRejected::too_large()), Equal => Ok(()) }`, then `EVP_PKEY_kem_new_raw_public_key(alg.id.nid(), bytes.as_ptr(), bytes.len())`. `ML_KEM_768.encapsulate_key_size == 1184`.
7. **LEAF 2 (C):** `crypto/fipsmodule/evp/p_kem.c` `EVP_PKEY_kem_new_raw_public_key` — `if (kem->public_key_len != len) { OPENSSL_PUT_ERROR(EVP, EVP_R_INVALID_BUFFER_SIZE); goto err; }`. Redundant second length gate.
8. **LEAF 3 (where the check actually happens):** `crypto/fipsmodule/ml_kem/mlkem/kem.c` `mlk_kem_enc_derand()` carries the explicit annotation `/* Specification: Implements @[FIPS203, Section 7.2, Modulus check] */` followed by `ret = mlk_kem_check_pk(pk, context); if (ret != 0) goto cleanup;`.
9. `mlk_kem_check_pk()` — `mlk_polyvec_frombytes(p, pk); mlk_polyvec_reduce(p); mlk_polyvec_tobytes(p_reencoded, p); ret = mlk_ct_memcmp(pk, p_reencoded, MLKEM_POLYVECBYTES) ? MLK_ERR_INVALID_PK : 0;`

That last function is a faithful implementation of FIPS 203 §7.2 step 2 (verified against the FIPS 203 PDF, p.45 §7.2): `test ← ByteEncode₁₂(ByteDecode₁₂(ek[0:384k]))`; "If `test ≠ ek[0:384k]`, then input checking failed." `frombytes → reduce → tobytes → constant-time compare` over `MLKEM_POLYVECBYTES` (= 384k = 1152) is exactly the round-trip test.

**Conclusion: claim A is correct.** rustls+aws-lc performs the FIPS 203 §7.2 check on the client ek and maps failure to `illegal_parameter` at the handshake boundary. This is an INFERRED-from-source conclusion, not independently re-executed; the GHA run is the execution evidence and I did not re-run it.

### 2B. Stimuli audit — 2 of 4 labels are FALSE (REFUTED)

Harness: `interop/protocol-placement/rustls_loopback/main.go`. I re-implemented FIPS 203 `ByteDecode12` and self-tested it against hand-computed values before trusting any output (an earlier draft of my checker had a bug — `bit` was not advanced in the inner loop — which the self-test caught; the numbers below are from the corrected, self-tested version).

ML-KEM-768 ek layout: `ek[0:1152]` = encoded t̂ (3 polys × 256 coeffs × 12 bits), `ek[1152:1184]` = 32-byte rho. X25519MLKEM768 share = ek (1184) ‖ X25519 (32) = 1216, PQ first.

| Variant | Claimed | Actual | Verdict |
|---|---|---|---|
| `wire_coeff0_eq_q` | coeff0 = 3329 | coeff0 = **3329** ✓ (self-test: bytes `01 0D` → 0x01 \| (0x0D<<8) = 3329) | **VERIFIED** |
| `wire_coeff0_eq_4095` | coeff0 = 4095, distinct from previous | coeff0 = **4095** ✓, distinct from 3329 ✓ | **VERIFIED** |
| `wire_coeff255_eq_4095` | coeff255 = 4095 | writes `ek[763]`,`ek[764]` (`main.go:233-234`). Those bytes are triplet 254 = **coeff508,509**. The coefficient actually set to 4095 is **global index 509** (poly 1, coeff 253). **coeff255 was never touched** — it lives at `ek[381..383]` and was verified byte-identical to baseline. | **REFUTED (label false)** |
| `truncate_last_byte` | "ek shrunk to 1183 B" = §7.2 length/type check | `cut = d + shareSize - 1` (`main.go:237`). `shareSize` = 1216, so the removed byte is **share index 1215 = offset 31 inside the 32-byte X25519 tail**. The **ek stays exactly 1184 bytes**. | **REFUTED** |

Per `main.go:64`: `// ek layout is 384 B encoded t-hat (modulus-checked) then 32 B rho seed` — this comment is **wrong**. 384 is `ByteEncode` of ONE polynomial of 256 coefficients (384 bytes/poly); for k=3 the t̂ body is 1152 bytes. The comment's arithmetic error is what produced `polyLo = 762` / `tailHi = 764`: those are calibrated to a 768-byte t̂ (768/2 − 3), not the real 1152. The same wrong constants are duplicated in `interop/protocol-placement/go_loopback/main.go:114,119-120,136,328-330`, so **the mislabeled stimulus is inherited from the Go cohort**, not introduced by this experiment.

The wrong comment is materially misleading about scope: a 384-byte-t̂ model would put `rho` at `ek[384:416]`, meaning a `coeff255` write at bytes 762/764 would land in the **rho seed**, which §7.2 does **not** modulus-check. That is exactly the kind of "cross-param-set body / rho-tail" pattern the finding's own limitations section flags as untested — except here it is silently present *under a wrong name*, and it happens to land back inside t̂ at index 509 only because the real t̂ is longer than the assumed one. The stimulus does fail the modulus half (4095 ≥ 3329), so the *observed* outcome is correct; only its identity is misreported.

### 2C. `truncate_last_byte` is not a §7.2 stimulus (REFUTED — most material finding)

The audit brief asked specifically whether `truncate-by-1` is "really a §7.2 *type* check (length == 384k+32)". **It is not.**

- §7.2 step 1 (Type check) applies to `ek`: "If `ek` is not an array of bytes of length 384k+32 … then input checking failed." For ML-KEM-768 that is 1184 bytes.
- The harness removed a byte from the **X25519 half**, leaving `ek` at exactly 1184 bytes and the total share at 1215.
- Therefore the §7.2 type check was **never violated**. The handshake was rejected earlier, by rustls's own hybrid layout check — `Layout::split()` returning `None` (`hybrid.rs`, `share.len() != 32 + 1184`), mapped to the same `INVALID_KEY_SHARE` → `illegal_parameter`.

Both paths yield byte-identical observable behavior (`PeerMisbehaved(InvalidKeyShare)` + `illegal_parameter`), which is precisely why the harness could not distinguish them and why the finding's own limitation text ("does not distinguish length-class from modulus-class") is correct **as a rustls-API observation** but was then mis-transcribed into the artifact as evidence that a length-class §7.2 failure was tested. It was not.

---

## 3. Does §7.2's LENGTH half get tested, or only MODULUS? (the critical question)

**Only MODULUS. The LENGTH half is untested — and it was structurally untestable by this harness.**

| §7.2 half | Tested? | Evidence |
|---|---|---|
| (a) Type check, `len(ek) == 384k+32` = 1184 | **NO** | No variant alters ek length. `truncate_last_byte` shrinks the *share* to 1215; ek remains 1184. |
| (b) Modulus check, `ByteEncode₁₂(ByteDecode₁₂(ek[0:384k])) == ek[0:384k]` | **YES** | All 3 coefficient variants plant a coefficient ≥ q in t̂ → round-trip mismatch → `mlk_kem_check_pk` returns `MLK_ERR_INVALID_PK`. |

So the empirical matrix is 3 real §7.2-modulus stimuli (one mislabeled) + 1 non-§7.2 share-length stimulus. The artifact's result matrix presents all four as "want=abort:illegal_parameter" with a single `MET` expectation, which silently collapses two distinct rejection mechanisms into one indistinguishable outcome.

**Is the length half nonetheless enforced in the code?** Yes — but by *accident of layering*, not by design of this experiment, and I want to be precise about which layer does what:

- `Layout::split()` (rustls) enforces `share.len() == 1216`, i.e. the **hybrid share** length. It never computes 384k+32.
- `aws-lc-rs EncapsulationKey::new` enforces `bytes.len() == 1184` = 384k+32 — the genuine §7.2(a) check. Reachable **only** because `split()` already guaranteed the length.
- `EVP_PKEY_kem_new_raw_public_key` re-checks `public_key_len != len` (redundant).

Because `split()` runs first and returns the *same* `INVALID_KEY_SHARE` error, **the aws-lc-rs §7.2(a) length check is unreachable dead code on this path.** Any experiment that wants to demonstrate §7.2(a) enforcement must construct a share where the ek is short while the total is right — impossible without another vector (e.g. a longer X25519 half) or a direct library-parse test. The finding's follow-up list already gestures at this ("Audit which implementations perform the s7.2 check at parse-time vs encapsulate-time"); this audit confirms the answer for this cohort: **parse-time length check is unreachable, encapsulate-time modulus check is what fires.**

Verdict on claim C: **OVERCLAIM.** "§7.2 check enforced" implies both halves. Half (b) is verified. Half (a) is enforced in source but not demonstrated, and on this code path cannot fire. The artifact's summary and statement both say "s7.2 encapsulation-key check" / "enforces the s7.2 check" without qualifying the half — that is the overclaim.

---

## 4. NOVELTY

**Checked. Result: not novel; do not disclose as new.**

- `GET api.github.com/advisories?ecosystem=rust&affects=aws-lc-rs` → `[]`. No RustEcosystem advisory against aws-lc-rs.
- `search/issues repo:aws/aws-lc "ML-KEM encapsulation key check"` → 16 hits. Material ones:
  - **aws-lc #2872** (merged 2026-04-06) — "Add encap/decapKeyCheck support in ACVP". Explicitly adds NIST ACVP `encapsulationKeyCheck` vectors against `crypto_kem_check_pk` / `ml_kem_*_check_pk`, i.e. **§7.2 is already an ACVP-validated test target in this project since April 2026**.
  - **aws-lc #2891** (merged 2026-01-20) — Wycheproof ML-KEM vectors. Notable admission in its own text: "**Missing encaps key import checks**: we successfully import ML-KEM encapsulation keys with modulus overflow. **This is allowed by FIPS 203**, but is not ideal … we will resolve this in an upcoming PR." This confirms (a) aws-lc deliberately does **not** check at import time — the check is deferred to `encaps` — and (b) the maintainers already know and document this placement.
  - **aws-lc #2709** (merged 2026-09-17) — exposes `ml_kem_*_check_pk/check_sk` via `EVP_PKEY_check`; its body quotes `mlkem/kem.c#L52-L74` for `crypto_kem_check_pk`, confirming the leaf I traced.
  - **aws-lc #3277 / #3483** — HPKE ML-KEM; #3277 states "The encapsulation key is validated on encap via `ml_kem_*_check_pk` … `mlk_kem_enc_derand` in the backend already performs the same modulus check." Independent corroboration of the exact placement.
- `search/issues repo:rustls/rustls X25519MLKEM768 key share` → 8 hits, **none** about ek validation. Closest is **rustls #2495** (closed, `state_reason: not_planned`) — a HelloRetryRequest/FIPS ergonomics complaint, unrelated to §7.2.
- Drift since the pins: rustls **0.23.44** (2026-09-07) and **0.23.45** (2026-09-14) released; aws-lc-rs **1.18.1** (2026-09-01) released. I re-checked the leaf at rustls `v/0.23.45` = `2976d90fd1c2db6b518700dd101b714069cfcb17`: `pq/hybrid.rs` blob SHA is **identical** (`8e30d782edcc88dac9625cabd63657298999b716`) to 0.23.43, and `emit_server_hello` still maps `start_and_complete` failure to `send_fatal_alert(IllegalParameter, …)`. **The property still holds at 0.23.45**; the finding is stale-pinned but not invalidated.

**Conclusion:** the substantive observation (BoringSSL-derived ML-KEM enforces the §7.2 modulus check at encapsulate time) is **already public in aws-lc's own issue tracker since at least January 2026** and is ACVP-covered since April 2026. The finding's own `follow_up` proposes "File an interoperability note (not a CVE)". Per `Agents.md` ("NOVELTY check required before any disclosure"), that note would be non-novel and is **not recommended**. Keep it as an internal conformance record.

---

## 5. SAFE TO DISCLOSE, OR CORRECTION NEEDED?

**CORRECTION NEEDED.** Do not disclose `fnd-2026-0005` as written. Specifically:

**Must fix before `verified_conclusion` stands:**
1. **Re-label the stimuli.** `wire_coeff255_eq_4095` → the byte writes at `main.go:233-234` target coefficient index **509**, not 255. Either fix the constants (`polyLo`/`tailHi` must be 381/382 for coeff255) or rename the variant. Note the same defect exists in `go_loopback/main.go:119-120,136,328-330`, so `obs-2026-0011` / the Go cohort needs the same correction.
2. **Fix the layout comment.** `main.go:64` (`384 B encoded t-hat`) → 1152 B for k=3, rho at `ek[1152:1184]`. Same in `go_loopback/main.go:114`.
3. **Stop presenting `truncate_last_byte` as a §7.2 stimulus.** It exercises rustls's `Layout::split()` share-length check, not FIPS 203 §7.2(a). The console log's own detail string — `"ek shrunk to 1183 B, all six length fields repaired (-1)"` (`reports/rustls_loopback_console.log:18`) — is **factually false**; ek stayed 1184 B and the share went to 1215 B. The finding propagated this string into `limitations` ("1 length truncate") without checking it.
4. **Qualify the §7.2 claim to the MODULUS half.** State that the LENGTH half is enforced in source (`aws-lc-rs` `EncapsulationKey::new`, 1184) but is unreachable on this path and untested.
5. **Update the pin.** rustls 0.23.43 → current 0.23.45 (property unchanged, blob-identical `hybrid.rs`); aws-lc-rs 1.18.0 → 1.18.1 available.
6. **Add the novelty result** to the artifact: aws-lc #2891 / #2872 already document and ACVP-test this; non-novel.

**What survives unchanged and is safe to state:**
- rustls 0.23.43 + aws-lc-rs 1.18 **does** enforce the FIPS 203 §7.2 **modulus** check on the client ML-KEM-768 ek, at encapsulate time, on the server handshake path, and maps failure to `illegal_parameter` + `PeerMisbehaved(InvalidKeyShare)`. Traced to `mlkem/kem.c` `mlk_kem_check_pk`. VERIFIED by source; consistent with the GHA run.
- The control/4-variant 5-row matrix is a faithful record of what the harness observed. The harness itself is not buggy in outcome — only in its self-description.

**One more caution for the record:** the finding's positive result is *evidence that rustls is correct*. A finding whose evidentiary base is partly mislabeled, published as public verification of a major stack's FIPS behavior, is exactly the kind of artifact a downstream reader will cite without reading the harness. That is the failure mode, not the conclusion. The conclusion survives; the citations do not.

---

## Appendix — method and verification notes

- **Pins verified from lockfile, not from prose.** `rustls_server/Cargo.lock:116-131,622-626` → aws-lc-rs `1.18.0`, aws-lc-sys `0.44.0`, rustls `0.23.43` (checksums match crates.io: `ce2b2dcc…` = aws-lc-rs 1.18.0, `0283386c…` = rustls 0.23.43). `Cargo.toml:15` declares `rustls = "=0.23.43"` (exact) and `aws-lc-rs = "1.14"` (caret — hence "resolved from ^1.14" in the artifact is accurate).
- **404s reported, not guessed:** `api.github.com/repos/rustls/rustls/releases/tags/v0.23.43` → **404**; `raw.githubusercontent.com/rustls/rustls/v/0.23.43/...` → **404** (tag is `v/0.23.43`); `crypto/fipsmodule/ml_kem/ml_kem.cc` → **404** (file is `.c`). Correct paths were then resolved via the git trees API, not guessed.
- **My own checker was self-tested before use.** A first implementation of `ByteDecode12` failed a self-test (coefficient 255 read as 0 instead of 240) because `bit` was computed outside the inner loop; corrected and re-validated against two hand-computed cases before any conclusion was drawn. Results in §2B come from the corrected version.
- **aws-lc C sources were read at `main`, not at the pinned `aws-lc-sys 0.44.0` tag.** The mlkem-native leaf (`mlk_kem_check_pk`, the `FIPS203 Section 7.2` annotation) is identical in substance, and #2709 quotes the same file/line range, but the exact pinned C tree was not fetched. Treat the leaf as high-confidence, not byte-verified at 0.44.0.
- **Not re-executed.** GHA run 33267918229 was read via its committed artifacts (TSV + console log); I did not re-run the workflow. Execution claims are INFERRED from those artifacts, whose internal consistency I did confirm.
