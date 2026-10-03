<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_fnd_0002.md -->

# Adversarial audit — `fnd-2026-0002`

**Target:** `knowledge/findings/fnd-2026-0002.yaml` — "OpenSSL 3.5.7 cross-API variance — `d2i_PUBKEY` (SPKI import) accepts 6 malformed ML-KEM encapsulation keys that `EVP_PKEY_new_raw_public_key_ex` (raw import) and .NET correctly reject, and proceeds to a successful encap."
**Status under audit:** `verified_conclusion`, `disclosure: public`
**Auditor role:** adversarial-critic (mandate: disprove)
**Date:** 2026-10-03
**Mode:** READ-ONLY. No repo file was edited. All probes written under `.scratch/audit_tmp/`.

---

## 1. VERDICT

**THE CENTRAL CLAIM IS REFUTED. `fnd-2026-0002` must be corrected before any disclosure.**

The empirical observation is real and reproducible, but its *interpretation* is wrong. The artifact concludes that OpenSSL's ML-KEM SPKI decoder "does not validate the relationship between the algorithm OID and the key-body length/canonical form" and describes a "`permissive BIT STRING length-trust`" loophole in the keymgmt. That is false.

**What actually happens is documented, universal `d2i_*` behaviour, identical for Ed25519, X25519, ML-DSA and ML-KEM:** `d2i_PUBKEY()` decodes *one* DER object. It leaves `*pp` pointing at the first byte after that object. Bytes past that point belong to the caller, not to OpenSSL. The harness (`build_spki_der`, `openssl_invar_runner.c:66-76`) copies a **canonical, fully-consistent 822-byte ML-KEM-512 SPKI prefix** and then appends the extra body bytes *past* the end of the declared DER object. The "malformed key" was never inside the DER object at all. There is no length-mismatch to detect, because the DER is well-formed.

The 6 divergent vectors are an **artifact of the harness**, not a property of OpenSSL's decoder. Every downstream artifact (obs-2026-0020, obs-2026-0022, rev-2026-0002, rpr-2026-0002, vrf-2026-0002) inherits this error, and each independently "reproduced" the same harness construction rather than testing it. This is precisely the fnd-2026-0009 failure mode repeated: **the logged evidence does not contradict the source, because the evidence and the source were both produced by the same wrong stimulus.**

A secondary but important finding: the artifact's FIPS 203 framing is also wrong. The s7.2 coefficient check **is present on the `d2i_PUBKEY` path** and rejects non-canonical keys correctly (measured below). So "the SPKI decode path does not validate canonical form" is contradicted by direct measurement.

**Disclosure recommendation: MUST BE CORRECTED. Do not file as drafted.**

---

## 2. CLAIMED vs ACTUAL, per attack point

### Attack point 0 — Was the empirical claim ever executed, or inferred?

**ACTUAL: it WAS executed. The "not executed" premise in the audit brief is wrong, and I must report that rather than repeat it.**

- `crypto/mlkem-input-checks/reports/openssl_invar_report.tsv` exists on disk (110,685 bytes, mtime 2026-08-26) and contains `META|runtime_libcrypto=OpenSSL 3.5.7 9 Jun 2026` and exactly 6 `import-accepted-UNEXPECTED` rows, each followed by `encap-accepted`.
- `msn-2026-0002.yaml:84-87` says dimension B is "complete: … B REFUTED (6 divergent vectors)". Only dimension **C (FIPS provider)** was blocked, and `blocked_reason` says so explicitly ("Dimension C … is permanently blocked"). The mission's terminal state `blocked-by-missing-evidence` is about the FIPS cell, **not** about the OpenSSL DER/SPKI-vs-raw matrix. Dimension B was run.
- **I re-ran the repo's own harness** (`openssl_invar_runner.c`, unmodified, compiled against local OpenSSL 3.6.3, MSYS2 GCC 16.1.0) over the committed 199-vector `stimuli.tsv`. Result: **the same 6 `UNEXPECTED` rows**, byte-identical family/param/source labels. Output at `.scratch/audit_tmp/h_out.tsv`.

So the empirical leg is sound and reproducible. **The defect is entirely in the interpretation, not the evidence.** This is the opposite failure from fnd-2026-0009's O3 (evidence contradicting source, unreconciled) — here source and evidence agree with each other and are both describing a harness artifact. Marked **VERIFIED**.

---

### Attack point 1 — Is `d2i_PUBKEY` really lenient? Trace to the leaf.

**CLAIMED** (`fnd-2026-0002.yaml:38-45, 96-99`): "The keymgmt trusts the parser-reported publen and the BIT STRING length header, and does not re-validate the relationship between the algorithm OID and the actual body length." Title: "`d2i_PUBKEY` SPKI decode path silently truncates mismatched bodies via BIT STRING length header." Mechanism steps 2-3 assert the ASN.1 parser is "permissive" and that `ASN1_R_SEQUENCE_LENGTH_MISMATCH` is "bypassed".

**ACTUAL.** The keymgmt's check is strict and never relaxes. Full leaf trace, all line numbers verified against pinned tag `openssl-3.5.7` (tag object `6ca677c395a4ae4472a12c5857c122ec33b36f66`, fetched via `raw.githubusercontent.com`):

1. `crypto/x509/x_pubkey.c:128` — `x509_pubkey_ex_d2i_ex()`, the EXTERN_FUNCS `d2i` callback for `X509_PUBKEY`.
2. `crypto/x509/x_pubkey.c:158` — `publen = *in - in_saved;`. **This is correct and it is the whole story:** `publen` is the number of bytes the DER parser actually consumed, i.e. the length of one complete DER object. It is *not* the caller's buffer length.
3. `crypto/x509/x_pubkey.c:189` — `size_t slen = publen;` — the decoder is handed exactly the consumed extent.
4. `providers/implementations/encode_decode/decode_der2key.c:288` — `key = ctx->desc->d2i_PUBKEY(&derp, der_len, ctx);`
5. `providers/implementations/encode_decode/decode_der2key.c:601` — `ml_kem_d2i_PUBKEY()` → `ossl_ml_kem_d2i_PUBKEY()`.
6. **`providers/implementations/encode_decode/ml_kem_codecs.c:248`** — the leaf:
   ```c
   if (publen != ML_COMMON_SPKI_OVERHEAD + (ossl_ssize_t)v->pubkey_bytes
       || memcmp(pubenc, vspki->asn1_prefix, ML_COMMON_SPKI_OVERHEAD) != 0)
       return NULL;
   ```
   This is an **exact** equality against the OID's own `pubkey_bytes`. There is no tolerance, no over-shoot allowance, and no "trust" of any length header. It receives `publen` = consumed-extent = 822/1206/1590, which is exactly `22 + 800/1184/1568`, so it passes — correctly, because the object it was handed genuinely *is* a canonical ML-KEM key.
7. `providers/implementations/encode_decode/ml_kem_codecs.c:257` → `crypto/ml_kem/ml_kem.c:2097` `ossl_ml_kem_parse_public_key()`, gated at `crypto/ml_kem/ml_kem.c:2110` (`len != vinfo->pubkey_bytes`), then `crypto/ml_kem/ml_kem.c:1593` `parse_pubkey()` → `crypto/ml_kem/ml_kem.c:1598` `vector_decode_12()` → `crypto/ml_kem/ml_kem.c:1240` → **`crypto/ml_kem/ml_kem.c:1055-1069` `scalar_decode_12()`**, which is the **FIPS 203 §7.2 modulus check**:
   ```c
   int outOfRange1 = (*c++ = b1 | ((b2 & 0x0f) << 8)) >= kPrime;
   int outOfRange2 = (*c++ = (b2 >> 4) | (b3 << 4)) >= kPrime;
   if (outOfRange1 | outOfRange2)
       return 0;
   ```
   **This check is on the `d2i_PUBKEY` path.** The artifact's premise that the SPKI path skips canonical-form validation is contradicted.

**Where the artifact's mechanism goes wrong.** Its step 3 says `ASN1_R_SEQUENCE_LENGTH_MISMATCH` was "bypassed". Check `crypto/asn1/tasn_dec.c:470-473`:
```c
if (!seq_nolen && len) {
    ERR_raise(ERR_LIB_ASN1, ASN1_R_SEQUENCE_LENGTH_MISMATCH);
```
`len` here is the SEQUENCE's *own declared* content length minus what its children consumed. In the harness's input the SEQUENCE declares 818 content bytes and its children consume exactly 818 (13-byte AlgorithmIdentifier + 4-byte BIT STRING header + 1 unused-bits byte + 800 body). `len == 0`. **There is no mismatch to detect** — the DER is internally consistent. The check is not bypassed; it is never armed, because nothing is inconsistent. Marked **REFUTED**.

**The harness's construction, byte-exact** (`openssl_invar_runner.c:66-76`):
```c
static int build_spki_der(const unsigned char *test_ek, int ek_len,
                          const char *alg, unsigned char *out_der, int *out_len) {
    ...
    memcpy(out_der, pref, 22);
    memcpy(out_der + 22, test_ek, ek_len);
    *out_len = 22 + ek_len;
```
`pref` is the **canonical** prefix — 22 bytes whose SEQUENCE length and BIT STRING length both encode the canonical body size. `openssl_invar_runner.c:60-62` hard-codes exactly OpenSSL's own `ml_kem_512_spkifmt` / `ml_kem_768_spkifmt` / `ml_kem_1024_spkifmt` (`ml_kem_codecs.c:24-44, 64-84, 124-144`) — I verified byte equality. So the harness writes 22 + 800 canonical bytes and then simply keeps going, appending 801, 1185, 1569, 1184, 1568-byte bodies past a DER object that is fixed at 822/1206/1590 bytes.

**Audit byte-math of the three prefixes (computed, matches OpenSSL exactly):**

| param set | SEQ.content | algor TLV | BS.content | BS.TLV | overhead | body | OVERHEAD+BODY |
|---|---|---|---|---|---|---|---|
| 512 | 818 | 13 | 801 | 805 | 22 | 800 | **822** |
| 768 | 1202 | 13 | 1185 | 1189 | 22 | 1184 | **1206** |
| 1024 | 1586 | 13 | 1569 | 1573 | 22 | 1568 | **1590** |

Note the trap the artifact fell into, twice. `BS.content = 801 = 800 body + 1 unused-bits byte`. obs-2026-0020 called this "the over-shoot"; obs-2026-0022 then "corrected" it from 1 byte to 33 bytes. **Both are wrong** — 801 is the *canonical* BIT STRING content length, and the harness's 801-byte body contains only **1** byte of true over-shoot, not 33. obs-2026-0022's magnitude "correction" is fabricated: `stimuli.tsv` `len-plus-1|ML-KEM-512` has a 1602-hex-char field = **801 bytes**, i.e. 800 canonical + 1. The claim that "the harness uses test_ek of length 833 (body + 33)" is false; I measured it directly. rev-2026-0002 and rpr-2026-0002 both propagate the 33-byte figure. Marked **REFUTED**.

---

### Attack point 2 — "6 malformed keys": is 6 verified? Reproducible or asserted?

**ACTUAL: the count 6 is VERIFIED and reproducible. The label "malformed keys" is REFUTED.**

- Count: **6**, confirmed in the committed GHA report and re-confirmed by my independent re-run of the unmodified harness on OpenSSL 3.6.3. Reproducible, deterministic (fixed seeds). **VERIFIED.**
- Mutations, measured from `stimuli.tsv` (hex field length ÷ 2 = body bytes):

| family | params | body bytes | canonical | true trailing bytes past the DER object |
|---|---|---|---|---|
| `len-plus-1` | ML-KEM-512 | 801 | 800 | **1** |
| `len-plus-1` | ML-KEM-768 | 1185 | 1184 | **1** |
| `len-plus-1` | ML-KEM-1024 | 1569 | 1568 | **1** |
| `cross-set-1024-as-768` | ML-KEM-768 | 1568 | 1184 | **384** |
| `cross-set-1024-as-512` | ML-KEM-512 | 1568 | 800 | **768** |
| `cross-set-768-as-512` | ML-KEM-512 | 1184 | 800 | **384** |

- There are **no coefficient mutations here at all** — no `coefficient == q`, no `== 4095`, no truncation. The audit brief asked about those; they are **absent** from these 6 vectors. (Coefficient-range vectors exist elsewhere in the 199-vector manifest and are handled identically on both paths — see attack point 3, Q3.) Marked **VERIFIED (count) / REFUTED (characterisation)**.

**The decisive test — are these keys malformed?** I wrote `.scratch/audit_tmp/audit_equivalence.c`, which imports each harness-style SPKI and separately raw-imports the *first N canonical bytes*, then compares the resulting public keys byte-for-byte:

```
cross-set-1024-as-512              DER-consumed=822/1590   DER-ek == first-800-of-body?  YES  (800 vs 800 bytes)
cross-set-1024-as-768              DER-consumed=1206/1590  DER-ek == first-1184-of-body? YES  (1184 vs 1184 bytes)
cross-set-768-as-512               DER-consumed=822/1206   DER-ek == first-800-of-body?  YES  (800 vs 800 bytes)
len-plus-1 ML-KEM-512              DER-consumed=822/823    DER-ek == first-800-of-body?  YES  (800 vs 800 bytes)

Does i2d_PUBKEY round-trip back to a canonical 822-byte SPKI?
  re-encoded SPKI = 822 bytes (canonical ML-KEM-512 = 822); equals canonical prefix? YES
```

**The key OpenSSL returns is bit-for-bit identical to the canonical key built from the truncated body, and re-encodes to a canonical 822-byte SPKI.** Nothing malformed was ever imported. OpenSSL parsed a complete, correct key and left the caller's extra bytes where the caller put them. **REFUTED.**

---

### Attack point 3 — Does it really "proceed to a successful encap"? Does the `enc` shim re-validate?

**ACTUAL: yes, encapsulation succeeds — and it succeeds because the key is a valid canonical key. There is no missing re-validation.**

- `encap-accepted` is present in the report for all 6 vectors. **VERIFIED** (as an observation).
- The reason is attack point 2: the key handle holds a canonical ML-KEM encapsulation key. `EVP_PKEY_encapsulate` operating on a valid key is expected to succeed. The `enc` shim has nothing to re-validate, because nothing wrong survived import.
- Source confirmation: `crypto/ml_kem/ml_kem.c:1593-1618` `parse_pubkey()` runs the §7.2 check and pre-computes `pkhash` and the matrix expansion **at import time** (`:1610-1611`). Encapsulation consumes the already-validated state. There is no window in which an unvalidated key reaches `enc`.
- **My control test Q3** (`.scratch/audit_tmp/audit_fnd0002.c`) puts a genuine §7.2 violation — coefficient #0 set to `q = 3329` — into a **canonically framed 822-byte SPKI** and tests both paths:
  ```
  ek with coefficient #0 = q (3329), len 800     raw=REJECT  (Provider routines:invalid key)
  ek with coefficient #0 = q (3329), len 800     d2i=REJECT  (digital envelope routines:decode error)
  ```
  **Both paths reject.** The `d2i_PUBKEY` path enforces §7.2. The artifact's statement that "the SPKI decode path does not validate … canonical form" is directly contradicted. **REFUTED.**

- **The critical counter-test (Q2).** I built a *genuinely* over-length SPKI — outer SEQUENCE length **and** BIT STRING length both patched to declare the over-length body, so there are zero trailing bytes and the DER is self-consistent about being too big:
  ```
  framed over-length SPKI (lengths agree)   d2i=REJECT  consumed=0/823  (asn1 encoding routines:too long)
  framed over-length SPKI (lengths agree)   d2i=REJECT  consumed=0/824  (asn1 encoding routines:too long)
  framed over-length SPKI (lengths agree)   d2i=REJECT  consumed=0/825  (asn1 encoding routines:too long)
  ```
  **OpenSSL rejects it.** When the over-length body is actually *inside* the DER object — which is the only place it could be a decoder defect — `asn1_check_tlen` (`crypto/asn1/tasn_dec.c:1212-1215`, `ASN1_R_TOO_LONG`) and the keymgmt's exact `publen` check both fire. The "loophole" closes as soon as the stimulus is well-formed. **REFUTED.**

- **Universality test (`.scratch/audit_tmp/audit_universal.c`).** Does ML-KEM behave differently from every other algorithm? No — a canonical SPKI followed by extra bytes is accepted identically everywhere:
  ```
  Ed25519 SPKI + trailing bytes     extra=1    ACCEPT consumed=44/45    TRAILING=1
  X25519 SPKI + trailing bytes      extra=1    ACCEPT consumed=44/45    TRAILING=1
  ML-DSA-44 SPKI + trailing bytes   extra=1    ACCEPT consumed=1334/1335 TRAILING=1
  ML-KEM-512 SPKI + trailing bytes  extra=1    ACCEPT consumed=822/823  TRAILING=1
  ML-KEM-512 SPKI + trailing bytes  extra=768  ACCEPT consumed=822/1590 TRAILING=768
  ```
  **ML-KEM is not special.** A finding whose behaviour is indistinguishable from Ed25519 and X25519 is not an ML-KEM input-validation gap. **REFUTED.**
  (`RSA:3072` and `EC` keygen failed in my probe — reported as such, not guessed.)

- **The contract that makes this correct.** `doc/man3/d2i_X509.pod`, pinned at `openssl-3.5.7`, DESCRIPTION section:
  > "d2i_TYPE() attempts to decode *len* bytes at *\*ppin*. When there is no error, a pointer to a TYPE object is returned and ***\**ppin* is incremented to the byte following the parsed data**."

  OpenSSL tells the caller exactly how many bytes it consumed so the caller can decide what to do with the rest. My probes measured precisely that: 822 of 823, 822 of 1590, 1206 of 1590. `d2i_PUBKEY` is behaving exactly as documented. The artifact never consulted this contract — that is the single missing step that would have caught this. **VERIFIED.**

---

### Attack point 4 — Version pinning and novelty.

**Version pinning.** The finding targets 3.5.7. `openssl-3.5.7` tag resolves to annotated-tag object `6ca677c395a4ae4472a12c5857c122ec33b36f66`; all source citations above were fetched at that tag. My local probes ran on **OpenSSL 3.6.3** (MSYS2), which rpr-2026-0002 also used. Both versions behave identically — consistent with rpr-2026-0002's cross-version note. **VERIFIED.**

**Has upstream changed?** No relevant change exists, and none is needed — because there is no defect. Reviewed every `ml_kem`-titled PR on openssl/openssl (11 total via `q=repo:openssl/openssl+ml_kem+in:title+type:pr`): #33023 (AVX2 NTT, perf), #32558 / #32109 (ppc64le multibuffer SHAKE, perf), #31822 (`ml_kem: Add a check for shared_secret`, closed 2026-07-20), #31525 (revert of #31432), #31432 (`return an error on catastrophic failure in decap`), #30243 (fromdata propquery), #30037 (docs), #29062 (init refactoring), #27627 (error-code choice in `s3_lib.c`), #26082 (evp_test). None touches SPKI length or canonical-form validation.

**Novelty result: the premise of novelty does not survive, because the behaviour is pre-existing, generic, and documented.**

Critically, there is a **directly analogous open upstream issue that is NOT ML-KEM-specific and reaches the same root shape**: **openssl/openssl#32368** — *"asn_pack.c:58 ASN1_item_unpack drops the decode cursor: openssl ocsp verifies non-DER OCSP responses with trailing garbage"* (opened 2026-08-14 by qifan-sailboat, Palo Alto Networks; **open**; labels `branch: master`, `help wanted`, `triaged: feature`). Same OpenSSL version (3.5.7), same class (accepted artifact with an unconsumed tail where canonical DER was required), and it argues the same cursor-vs-buffer distinction from the other direction. It reaches the *generic helper* `crypto/asn1/asn_pack.c:52-61`, whereas `d2i_PUBKEY`'s cursor is correctly propagated by `x_pubkey.c:158` — so this is not the same bug, but it is the same **family**, it is **already known to the project**, and filing an ML-KEM-specialised variant of it as novel would be a mis-framing.

Also relevant and **open**: **#25781** "Malformed hybrid ML-KEM key shares are not handled correctly" (tomato42, 2024-10-23) — the genuine ML-KEM malformed-key-handling issue in this codebase, at the TLS layer, with an existing reproducer. And **#29840** "ml-kem: validate explicit public key against seed on import" (open) — a real but *different* gap (seed/pubkey consistency, not SPKI framing).

**Queries run (all against `api.github.com`, `search_type: lexical`):**
- `repo:openssl/openssl+ML-KEM+SPKI+in:title,body` → `total_count: 0`
- `repo:openssl/openssl+ML-KEM+encapsulation+key+validation` → `total_count: 0`
- `repo:openssl/openssl+d2i_PUBKEY+in:title` → `total_count: 11` (none on point)
- `repo:openssl/openssl+SPKI+ML-KEM+in:title` → `total_count: 0`
- `repo:openssl/openssl+ml_kem+in:title+type:pr` → `total_count: 11` (all enumerated above)
- `repo:openssl/openssl+d2i_PUBKEY+trailing+data` → `total_count: 1` (#28610, unrelated Windows build failure)
- `repo:openssl/openssl+trailing+garbage+ASN.1+OR+"extra bytes"+OR+slen+in:title` → `total_count: 1` (**#32368**, on point)
- `web_search` tool: **UNAVAILABLE** — returned HTTP 426 (Grok CLI 1.0.5 outdated). Reported, not worked around. All novelty evidence above is from the GitHub API directly; general web/ mailing-list coverage is therefore **incomplete**.

---

### Attack point 5 — Reconcile source vs logged evidence.

**The evidence and the source AGREE. That is the problem, not a defence.**

The GHA log rows (`openssl_invar_report.tsv`) say: SPKI cell accepted, raw cell rejected, encap accepted. The OpenSSL 3.5.7 source says: `ossl_ml_kem_d2i_PUBKEY` enforces an exact length match and `scalar_decode_12` enforces §7.2. Both are true simultaneously, because the harness never put the malformed length *into* the DER object. So there is no contradiction to reconcile — and no reviewer noticed, because every layer of review (obs-2026-0020, obs-2026-0022, rev-2026-0002, rpr-2026-0002, vrf-2026-0002) re-derived and re-ran **the same harness construction** instead of testing the stimulus's framing assumption.

Specific inherited errors:
- **obs-2026-0020** `stdout` block asserts `byte-count of spki_prefix_512 literal: 23 (declared size: 22, overflow: 1)` and `discrepancy: 1 byte in BIT STRING content-length vs actual content`. Both wrong — the literal has exactly 22 initialisers, and `BS.content = 801` is correct because 801 = 800 + 1 unused-bits byte. (The narrative text of the same artifact retracts this; the machine-readable `stdout` block still carries it.)
- **obs-2026-0020 / fnd-2026-0002** claim `asn1_check_tlen` "advances the cursor by exactly the declared number of bytes, then `asn1_d2i_ex_primitive` … advances by exactly *plen* more bytes". Wrong: `crypto/asn1/a_bitstr.c:120` is `if (len-- > 1)` — the BIT STRING body is `plen - 1`, minus the unused-bits byte. (`crypto/asn1/tasn_dec.c:1204` `asn1_check_tlen` is also misdescribed as a cursor-advancing function; it reads the header and sets `*olen`.)
- **obs-2026-0022 / rev-2026-0002 / rpr-2026-0002** 33-byte magnitude: **false**, measured 1 byte.
- **rev-2026-0002** cites `crypto/asn1/tasn_dec.c:411-414` for SEQUENCE_LENGTH_MISMATCH (actual: **471**) and `ml_kem_codecs.c:213-218` for the `publen` check (actual: **248**). vrf-2026-0002 cites `tasn_dec.c:283-308`, `x_pubkey.c:175-196`, `ml_kem_codecs.c:213-225` — all shifted. The `x_pubkey.c:175-196` window and the `213-225` window exist but do not contain the cited code. These citation errors are the direct signature of reviews that reasoned from memory rather than from the fetched file, and are exactly what a pinned line-number re-check catches.

---

## 3. Novelty — summary

**Result: no novel ML-KEM SPKI/DER validation issue exists upstream, because the claimed defect does not exist.**

| Item | Number | URL | Relevance |
|---|---|---|---|
| OpenSSL issue — `ASN1_item_unpack` drops decode cursor, OCSP accepts trailing garbage | **#32368** | https://github.com/openssl/openssl/issues/32368 | **Same defect family, generic, already known and open.** Tested on 3.5.7. Establishes that the "accepted artifact with unconsumed tail" shape is a known, discussed OpenSSL topic — not a novel ML-KEM discovery. |
| OpenSSL issue — malformed hybrid ML-KEM key shares | #25781 | https://github.com/openssl/openssl/issues/25781 | Genuine ML-KEM malformed-key issue, but at the TLS key-share layer, not SPKI import. |
| OpenSSL PR — validate explicit public key against seed on import | #29840 | https://github.com/openssl/openssl/pull/29840 | Open. Different gap (seed↔pubkey consistency). |
| ML-KEM import/encaps/decaps PRs surveyed | #33023, #32558, #32109, #31822, #31525, #31432, #30243, #30037, #29062, #27627, #26082 | github.com/openssl/openssl/pulls/… | **None** touches SPKI framing or canonical-form validation. |

**Explicitly searched and absent:** an openssl/openssl issue or PR specifically for "ML-KEM SPKI / DER / encapsulation-key validation" — `total_count: 0` on three independent query formulations.

**Coverage limits, stated honestly:** `web_search` failed with HTTP 426 (Grok CLI outdated), so openssl.org mailing lists, the OpenSSL security-policy page and general web sources were **not** searched. The novelty sweep is GitHub-API-only. This is adequate to establish that **no GitHub-tracked issue/PR covers the claim**, and inadequate to make a claim about private correspondence.

---

## 4. Safe to disclose, or must be corrected?

**MUST BE CORRECTED. Do not disclose fnd-2026-0002 as written.**

Reasons, in order of severity:

1. **The central claim is false.** "`d2i_PUBKEY` SPKI decode path silently truncates mismatched bodies via BIT STRING length header" is not what OpenSSL does. A correct, canonically-framed over-length SPKI is **rejected** (`asn1 encoding routines:too long`). The finding would, if filed, invite a maintainer to spend time on a non-bug and to conclude that the reporter's reproducer is broken.
2. **It would misrepresent the §7.2 posture.** It claims the SPKI path skips canonical-form validation. Both paths demonstrably enforce it (`scalar_decode_12`, `crypto/ml_kem/ml_kem.c:1055-1069`). Publishing that claim could wrongly reassure someone auditing their own ML-KEM handling.
3. **It would ask for a fix that would break correct behaviour.** Its recommended remediation (fnd-2026-0002 `follow_up` step 3) — make `d2i_PUBKEY` "enforce no over-shoot tolerance" — asks OpenSSL to reject callers that pass a buffer containing one DER object followed by more data. That is a documented, universal `d2i_*` usage pattern, used by Ed25519, X25519 and ML-DSA identically. Implementing it for ML-KEM alone would make ML-KEM *inconsistent with every other algorithm in the library*.
4. **The `.scratch/upstream-openssl/ISSUE.md` draft (246–297 lines) is built on the false premise** and would need to be withdrawn, not amended.

**What survives, and is worth preserving as a negative result:**

- **VERIFIED:** `d2i_PUBKEY` leaves unconsumed trailing bytes in the caller's buffer; the caller must check `*pp`. Measured: 822/823, 822/1590, 1206/1590.
- **VERIFIED:** `EVP_PKEY_new_raw_public_key_ex` rejects on any `len != pubkey_bytes`; the raw API has no "extra bytes" concept. So raw-vs-DER *harness matrices* will always show this asymmetry unless the harness checks the consumed length. That is a real, reusable **harness-design lesson** and is the durable content of this mission.
- **VERIFIED:** both paths enforce FIPS 203 §7.2, including via `d2i_PUBKEY`.
- **VERIFIED:** behaviour is identical on OpenSSL 3.5.7 and 3.6.3, and identical to Ed25519/X25519/ML-DSA.
- **Open question, genuinely unresolved:** OpenSSL **#32368** is a real, open, non-ML-KEM instance of the same family (accepted artifact with an unconsumed tail). Whether `d2i_PUBKEY` callers elsewhere in the tree are similarly unchecked is a legitimate follow-up mission — but it must be framed as a **cursor-consumption audit**, not as the ML-KEM SPKI bug claimed here.

**Recommended status change:** `verified_conclusion` → `rejected` (mirroring the fnd-2026-0009 precedent and the AGENTS.md requirement to preserve negative results). The artifacts that inherit the error — obs-2026-0020, obs-2026-0022, rev-2026-0002, rpr-2026-0002, vrf-2026-0002, hyp-2026-0002 dimension B — need the same correction, and `hyp-2026-0002`'s DIMENSION B "REFUTED" verdict must be re-marked, since the invariance it claims to have broken was never violated by the target under test.

---

## 5. Evidence index

**Target pinned version:** OpenSSL tag `openssl-3.5.7` → annotated tag object `6ca677c395a4ae4472a12c5857c122ec33b36f66`. All `file:line` citations below verified by line-number query against files fetched from `raw.githubusercontent.com` at that tag.

**OpenSSL source cited:**
- `crypto/x509/x_pubkey.c:128, 158, 189, 221` — `x509_pubkey_ex_d2i_ex`; `publen = *in - in_saved`; `slen = publen`; `if (slen != 0)`
- `providers/implementations/encode_decode/decode_der2key.c:288, 601` — SPKI dispatch; `ml_kem_d2i_PUBKEY`
- `providers/implementations/encode_decode/ml_kem_codecs.c:24-44, 64-84, 124-144, 235, 248, 257` — canonical SPKI prefixes; `ossl_ml_kem_d2i_PUBKEY`; **exact** `publen` check; `parse_public_key` call
- `crypto/ml_kem/ml_kem.c:1055-1069 (§7.2 modulus check), 1240, 1593-1618, 2097, 2110` — validation chain
- `crypto/asn1/tasn_dec.c:362 (SEQUENCE branch), 470-473 (SEQUENCE_LENGTH_MISMATCH), 1212-1215 (TOO_LONG)` — decoder
- `crypto/asn1/a_bitstr.c:120` — BIT STRING body is `plen - 1` (unused-bits byte)
- `doc/man3/d2i_X509.pod`, DESCRIPTION — "**\**ppin* is incremented to the byte following the parsed data**"

**Repo evidence examined:**
- `crypto/mlkem-input-checks/reports/openssl_invar_report.tsv` — 6 UNEXPECTED rows + encap-accepted; `META|runtime_libcrypto=OpenSSL 3.5.7 9 Jun 2026`
- `crypto/mlkem-input-checks/stimuli/stimuli.tsv` — 199 vectors; the 6 divergent bodies measured at 801/1185/1569/1568/1568/1184 bytes
- `crypto/mlkem-input-checks/harnesses/openssl_invar_runner.c:60-62 (canonical prefixes), 66-76 (build_spki_der — appends verbatim, no re-framing), 190-196 (d2i_PUBKEY)` — **the root cause**
- `missions/completed/msn-2026-0002.yaml:84-87, blocked_reason` — dimension B complete; only dimension C (FIPS) blocked
- `knowledge/notes/msn-2026-0002.md` — session narrative; confirms the 33-byte figure originated here

**Audit probes written (READ-ONLY, `.scratch/audit_tmp/`):**
- `audit_fnd0002.c` → Q1 harness reproduction (accepts, encap OK); **Q2 properly-framed over-length SPKI REJECTS**; **Q3 coefficient=q REJECTS on both raw and d2i paths**
- `audit_equivalence.c` → DER-decoded key is byte-identical to the canonical truncated key; re-encodes to canonical 822 bytes
- `audit_universal.c` → same trailing-byte acceptance for Ed25519, X25519, ML-DSA-44, ML-KEM-512
- `h_repro.c` + `h_out.tsv` → the repo's own unmodified harness, re-run over the committed 199-vector manifest on OpenSSL 3.6.3: reproduces exactly the same 6 UNEXPECTED rows

**Marking summary:**
| Claim | Verdict |
|---|---|
| The empirical matrix was executed | **VERIFIED** (audit brief's "not executed" premise is incorrect; only the FIPS cell was blocked) |
| Count = 6, reproducible | **VERIFIED** |
| Specific mutations are coefficient-level | **REFUTED** — no coefficient mutations; length-level only |
| "1-byte over-shoot" (fnd-2026-0002 body) | **VERIFIED** for len-plus-1; **REFUTED** for cross-set (384/768, not 800) |
| "33-byte over-shoot" (obs-2026-0022, rev, rpr) | **REFUTED** — measured 1 byte |
| SEQUENCE_LENGTH_MISMATCH "bypassed" | **REFUTED** — never armed; DER is self-consistent |
| keymgmt "trusts the BIT STRING length header" | **REFUTED** — `ml_kem_codecs.c:248` is an exact equality |
| SPKI path skips canonical-form validation | **REFUTED** — `scalar_decode_12` enforces §7.2; measured on both paths |
| Accepted DER leads to successful encap | **VERIFIED** as observation — but the key is canonical, so success is correct |
| Behaviour is ML-KEM-specific | **REFUTED** — identical in Ed25519 / X25519 / ML-DSA |
| Properly-framed over-length SPKI accepted | **REFUTED** — rejected with `too long` |
| Cited file:line values | **PARTLY REFUTED** — 4 of 6 cited ranges do not contain the claimed code |
| Novel ML-KEM SPKI/DER validation issue upstream | **REFUTED** — 0 hits on 3 formulations; generic family already tracked as #32368 |
