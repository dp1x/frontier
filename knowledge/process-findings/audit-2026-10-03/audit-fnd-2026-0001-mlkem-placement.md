<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_fnd_0001.md -->

# Adversarial audit — `fnd-2026-0001` (ML-KEM §7.2 check-placement taxonomy)

**Role:** adversarial-critic (contract: `roles/README.md` — "Explicit goal: disprove the current best interpretation before it is promoted. Must attempt concrete disproof, not stylistic critique.")
**Target:** `knowledge/findings/fnd-2026-0001.yaml` — `status: verified`, `epistemic_status: verified_conclusion`, `disclosure: public`
**Date:** 2026-10-03 · **Mode:** READ-ONLY (no repo file edited, no commit)

---

## 1. VERDICT

**PARTIALLY-CONFIRMED** — all six claimed check *placements* survive direct source reading at the pinned versions with no bypass found, but three of the finding's supporting generalizations are overstated or imprecise and must be corrected before public disclosure (the "OQS fixed-size structs enforce length statically by typing" claim is false as written; `.NET 10` is a servicing version `10.0.11`, not `10.0.0`; and the PQClean leg is unverified on two of three shipped backends).

I attempted concrete disproof and failed to break any placement claim. That is a negative result and is recorded as such.

---

## 2. Per-implementation: claimed vs actual check location

Pins verified live against `api.github.com` on 2026-10-03. Every `file:line` below was read by me at the pinned commit unless marked otherwise.

| # | Impl (pin) | Claimed | **Actual check location (read)** | Verdict |
|---|---|---|---|---|
| 1 | **PQClean clean** @ `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` | absent entirely | **Absent — CONFIRMED.** `crypto_kem/ml-kem-768/clean/kem.c:110` `crypto_kem_enc` → `:115` straight to `crypto_kem_enc_derand` → `indcpa_enc`; no check. `indcpa.c:39` `unpack_pk` → `polyvec_frombytes` → **`poly.c:1055-1059` `poly_frombytes` masks with `& 0xFFF`** (accepts 0..4095), **no `>= 3329` test**. `verify.c` holds only constant-time `verify`/`cmov`/`cmov_int16` — no modulus check. `api.h:15` returns `int` but only ever 0. | **CONFIRMED** |
| 2 | **PQClean avx2** (same pin) | (not separately claimed) | **Absent — CONFIRMED.** `avx2/indcpa.c` `PQCLEAN_MLKEM768_AVX2_indcpa_enc` identical structure; `unpack_pk` → `polyvec_frombytes`, no check. | **CONFIRMED** (extends the claim) |
| 3 | **liboqs 0.16.0** @ `5a1a854b0dc9f2141bdc771c555ee60c37950183` | Encaps-time | **Encaps-time — CONFIRMED, one layer deeper than the finding states.** liboqs's own `src/kem/ml_kem/kem_ml_kem_768.c` wrapper contains **no check**; it calls `PQCP_MLKEM_NATIVE_MLKEM768_{C,X86_64,AARCH64}_enc{,_derand}`. The check lives in mlkem-native `mlkem/src/kem.c` `mlk_kem_enc_derand`: `/* Specification: Implements @[FIPS203, Section 7.2, Modulus check] */ ret = mlk_kem_check_pk(pk, context); if (ret != 0) goto cleanup;` — **unconditional, first statement after allocation**. `mlk_kem_check_pk` does `frombytes → reduce → tobytes → ct_memcmp(pk, reencoded)`. | **CONFIRMED** (see §4.1 — attribution nit) |
| 4 | **mlkem-native v1.2.0** @ `0ba906cb14b1c241476134d7403a811b382ca498` | Encaps-time | **Encaps-time — CONFIRMED.** Critically, `mlkem/src/kem.c` is **shared by all backends** (tree listing shows a single `mlkem/src/`, with only `src/native/*` per-arch). So the C, x86_64 and aarch64 legs all inherit the check. Repo evidence agrees: `oqs_ref_invar_report.tsv` META `backend=ref|mlkem_native=0ba906c`. | **CONFIRMED** |
| 5 | **OpenSSL 3.5.7** @ tag `openssl-3.5.7` → commit `8cf17aaeb4599f8af87fefd810b5b5fee90fe69e` | import-time | **Import-time — CONFIRMED at the level encapsulation actually runs.** The check is `crypto/ml_kem/ml_kem.c:1055-1070` **`scalar_decode_12`**: `int outOfRange1 = (*c++ = …) >= kPrime; int outOfRange2 = …; if (outOfRange1 | outOfRange2) return 0;` Reached via `parse_pubkey` `ml_kem.c:1597` `if (!vector_decode_12(key->t, in, vinfo->rank))` → `ERR_raise_data(… PROV_R_INVALID_KEY …)`. **Bypass hunted and NOT found:** `encap()` `ml_kem.c:1758` performs no decode; its only gate is `ossl_ml_kem_encap_seed` `ml_kem.c:2223` `if (key == NULL \|\| !ossl_ml_kem_have_pubkey(key)) return 0;`. `have_pubkey` is set only via `parse_pubkey`/`genkey`. Provider layer also gates: `providers/implementations/kem/ml_kem_kem.c:79` and `:156` both check `ossl_ml_kem_have_pubkey(key)`. | **CONFIRMED** |
| 6 | **Go 1.26.4** @ `a9ce111d580581fb925ae88f125c69b7d93504ea` | import-time | **Import-time — CONFIRMED.** `src/crypto/mlkem/mlkem.go:106` `NewEncapsulationKey768` → `crypto/internal/fips140/mlkem/mlkem768.go:374` → `parseEK` `:384`; length check `:385`; modulus check `:395` via `polyByteDecode` → `field.go:164-182`, which calls `fieldCheckReduced` per coefficient and returns `errors.New("mlkem: invalid polynomial encoding")`. **Raw-bytes bypass hunted and NOT found:** the exported constructor `NewEncapsulationKey768` is the *only* way to build an `EncapsulationKey768`, and it funnels to `parseEK`. `Encapsulate` `:335` deliberately does not re-check — but by then the key object already exists, so it is unreachable-by-construction, not an omission. Source itself documents this: `:345-346` "the modulus check … is performed by polyByteDecode in parseEK". | **CONFIRMED** |
| 7 | **RustCrypto ml-kem 0.3.2** @ `440768245bba59784b504269cb3087a6c21af45c` | import-time | **Import-time — CONFIRMED.** `ml-kem/src/encapsulation_key.rs:33` `new()` → `pke.rs:168` `EncryptionKey::from_bytes` → `pke.rs:202` **`if &ret.to_bytes() == enc { Ok(ret) } else { Err(InvalidKey) }`** — byte-exact round-trip, i.e. precisely FIPS 203 §7.2. `encapsulate_deterministic` `:45-49` performs no check (key already validated). The finding's "fallible slice constructor" characterization is **accurate**. | **CONFIRMED** |
| 8 | **.NET 10 MLKem** | import-time | **Import-time — CONFIRMED behaviourally; version pin needs correction.** No managed `MLKem.cs` exists in `System.Security.Cryptography` at v10 (only `MLKemOpenSsl*.cs`, `MLKemImplementation.OpenSsl.cs`); the managed type lives outside that directory and I **could not locate it** — see §3. Import goes through the platform. Repo evidence: `dotnet_windows_report.tsv` META `runtime=10.0.11\|backing=CNG` (implied by harness `RuntimeInformation.IsOSPlatform(Windows)`), and `Program.cs:58` calls `MLKem.ImportEncapsulationKey` **before** `Encapsulate`, so observed rejection is import-time. | **CONFIRMED behaviourally / CAND-NOT-DETERMINE mechanism** |

### 7. The "C KEM ABI leaves the type check to callers" claim

**PARTIALLY REFUTED — one of the two sub-claims is false.**

- **PQClean half — VERIFIED, and it is a type-system fact, not an ABI accident.** `api.h:15`:
  `int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);`
  The parameter is an **unqualified pointer with no length parameter**. FIPS 203 §7.2 step 1 (type check: "array of bytes of length 384k+32") is therefore *inexpressible* at this signature. Repo evidence agrees: `pqclean_x64_report.tsv` shows `fail-type` → `inexpressible-at-api` (9 vectors). **The finding's phrasing "a runtime type check is inexpressible there" is correct.**

- **OQS half — REFUTED as written.** The finding says: *"OQS's fixed-size structs enforce length statically by typing."* `src/kem/kem.h` declares
  `OQS_STATUS (*encaps)(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);`
  — again an **unqualified pointer**, with length carried **out-of-band** as the struct field `length_public_key` and as compile-time macros. Nothing in the type system enforces anything; a caller who ignores those macros gets a silent out-of-bounds read. So OQS is **not** a counterexample of static typing — it is a *second instance of the same raw-pointer shape* as PQClean, merely with the length published as an advisory field. The finding's own later sentence ("offer no runtime rejection signal for wrong-length buffers") is correct and contradicts the earlier one.
  **Consequence for the taxonomy:** the claim is not "two dominant C KEM API shapes differ" but **"both dominant C KEM shapes are the same shape."** The reported `inexpressible-at-api` verdict for OQS (9 vectors, `oqs_runner_report.tsv`) already encodes this correctly — the *prose* is what is wrong.

---

## 3. Claims I could NOT verify (CAND-NOT-DETERMINE)

1. **.NET managed `MLKem` import implementation.** The managed `MLKem.cs` is **not** at `src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/` at v10.0.11 (directory listing shows only `MLKemOpenSsl*.cs`, `MLKemImplementation.OpenSsl.cs`; **no `MLKem.cs`**). Probes for `MLKemBase.cs` and `System.Security.Cryptography.Pq` both returned **404**. Unauthenticated `search/code` returns **401 "Requires authentication"**, so I could not tree-search. I read `MLKemOpenSsl.OpenSsl.cs` (OpenSSL-backed path only) and it contains no modulus check — it delegates to `Interop.Crypto.EvpKemEncapsulate`. **The Windows CNG path that the experiment actually exercised is not verifiable from the repo at this ref.** The *placement* claim survives on executed evidence, not on source I read.
2. **Windows CNG (`bcrypt.dll`) ML-KEM import semantics.** Closed-source; not inspectable. The 82 `crypto-class:Unknown error (0xc1000001)` rejections in `dotnet_windows_report.tsv` are consistent with import-time rejection but do not by themselves prove where the check lives.
3. **PQClean `aarch64` backend.** Not read. `META.yml` pins it to `neon-ntt@70cdc9601b8fce9b6c0cef4faf168b6c4c4ddc4c`; the finding's architecture-invariance claim covers executed legs only, which its own `limitations` field already concedes.
4. **FIPS-provider runtime behaviour, DER/SPKI-vs-raw matrix, liboqs non-mlkem-native backends (cuPQC, ICICLE).** Not read; already listed in the finding's `limitations`.
5. **Whether `scalar_decode_12`'s early-`return 0` on first out-of-range coefficient leaks a secret-dependent timing signal.** Out of scope for a placement audit; noted only because it is a *different* question the finding does not raise.
6. **FIPS 203 §7.2 / SP 800-227 §3.2–3.3 quoted text.** The finding cites `localdocs/refs/fips203.pdf` and `csrc.nist.gov/pubs/sp/800/227/final`. I did **not** open the local PDF or re-verify the normative language; the placement analysis above is independent of it.

---

## 4. Disclosure-readiness defects (must fix before sending to maintainers)

### 4.1 Attribution error — the same mistake as `fnd-2026-0009`
The statement credits liboqs with "enforced inside Encaps … via mlkem-native v1.2.0 `mlk_kem_check_pk`". Technically true but it **understates the layer**, and this is precisely the `fnd-2026-0009` failure mode recurring in milder form (reading the wrapper, not the callee): liboqs's `kem_ml_kem_768.c` has *no* validation; a maintainer replying "that's not our code" would be **correct**. The credit belongs to **pq-code-package/mlkem-native**, and liboqs is a consumer. Any disclosure should name mlkem-native as the implementing project and liboqs as the integrating one. This is the single most likely cause of the disclosure landing badly.

### 4.2 Self-contradictory OQS claim
Quoted in §2. Fix the "enforce length statically by typing" sentence.

### 4.3 Stale/imprecise version pins
- **`.NET 10`** — the finding's `statement` says ".NET 10 MLKem on its default Windows CNG backing" without a version, while `dotnet_windows_report.tsv` META records **`runtime=10.0.11`**. v10.0.11 is a current servicing tag (verified: `v10.0.0` → `60629d14`, `v10.0.12` → `4271d88e`; 10.0.12 now exists, so **10.0.11 is one servicing behind**). Not *wrong*, but unpinned in the text while every other leg is pinned — an asymmetry a maintainer will notice.
- **PQClean `0586a824`** — commit dated 2026-08-04, and that tree is the **retirement** commit (README diff: "Deprecation Notice" → "Retirement Notice"). Accurate as a pin; correct that the target is archived and points readers at mlkem-native, or the disclosure reads as aimed at dead code.

### 4.4 Claims resting on tests that did not run — **none found**
I checked every "rejects"/"accepts" claim against its report:
- `oqs_runner_report.tsv`: 200 rows, 82 `rejected`, 108 `accepted`, 9 `inexpressible-at-api`, `total=199 matched=199`. The **82/82** claim is **exactly borne out**.
- `pqclean_x64_report.tsv`: all 82 `fail-modulus` → `accepted`; split 24/27/31 across k=2/3/4; 9 `inexpressible-at-api`; `surprises=0`. "Accepts every length-valid input" **borne out**.
- `go_runner_report.tsv`: 58 `invalid polynomial encoding` + 5 `invalid encapsulation key length` — matches `field.go:174/177` and `mlkem768.go:386` **string-for-string**. Source and log agree.
- `rust_runner_report.tsv`: 91 `rejected` / 107 `accepted`.
- `dotnet_windows_report.tsv`: 82 `crypto-class` + 9 `arg-class` + 108 accepted.
- META provenance lines all carry runtime/version and are internally consistent; `openssl_report.tsv` META `OpenSSL 3.5.7 9 Jun 2026` matches tag date 2026-06-09.
- Harness `Program.cs` (mtime 2026-08-25 19:43) is **later** than `dotnet_windows_report.tsv` (mtime 2026-08-25 02:25). **The committed report was NOT produced by the committed harness** — it predates it by ~17 h. Given commit `c49e667` ("byte-clean v1 harness restore … apply adversarial review R1+O1 to ByteEncode.lean"), the current harness is the *corrected* v2 and the Windows report is a v1 artifact. This does not overturn the placement claim (both versions call `ImportEncapsulationKey` first), but **the report must be regenerated before disclosure** or its provenance cannot be stated honestly.
- **No unrun test was found to be the sole support for a "rejects" claim.** The `82` and the byte-exact Go error strings are the load-bearing evidence and both check out.

---

## 5. What I could not break

- No import-time implementation has an encapsulation path that skips its check. OpenSSL, Go and RustCrypto were each probed specifically for the bypass and none exists; each is guarded by a key-object invariant (`have_pubkey` / `parseEK` / `from_bytes`).
- PQClean genuinely has no check at either layer, in either backend I read, and `poly_frombytes` masks rather than validates.
- mlkem-native's check is unconditional and backend-shared, so liboqs cannot silently lose it on a non-C backend.

## 6. Recommended disposition

**Do not send as-is.** The finding's core taxonomy is sound and survived adversarial attack; three prose defects (§4.1 layer mis-attribution, §4.2 self-contradiction, §4.3 unpinned .NET) are cheap to fix and would otherwise damage credibility with exactly the maintainers it aims at. Regenerate `dotnet_windows_report.tsv` with the committed harness (§4.4) before any disclosure. Consider splitting the mlkem-native/liboqs credit as its own finding so the credit lands on the project that wrote the code.
