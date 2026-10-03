<!-- Preserved from .scratch/ (gitignored, not durable).
     Supports knowledge/reports/rpt-2026-0017.yaml.
     Original filename: xwing_hpke_test_spec.md -->

# X-Wing inside HPKE — factual status and test specification

**Role:** test-archaeologist + experiment-designer
**Date:** 2026-10-03
**Mode:** READ-ONLY over `knowledge/`, `missions/`, `src/`. No repo files edited, no commits made. Scratch computations run ad hoc; this file is the only artifact written.
**Supersedes as a source of fact on one point:** the audit claim that `.scratch/xwing/py_xwing/debug_hpke.py:66` uses the wrong mode byte. **That claim is itself false — see §4. The script is correct.**

---

## 1. Factual status of X-Wing-in-HPKE, with quotes

### 1.1 X-Wing explicitly targets HPKE

`draft-connolly-cfrg-xwing-kem-11` (23 September 2026, expires 27 March 2027) is the current revision. <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/> and <https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.txt>

§1.2, Design goals — VERIFIED:

> "We aim for X-Wing to be usable for most applications, including specifically HPKE [RFC9180]."

§1.4 — VERIFIED:

> "In particular, X-Wing is not, borrowing the language of [RFC9180], an _authenticated_ KEM."

§5.6, *Use in HPKE* — the operative text. VERIFIED, verbatim:

> "X-Wing satisfies the HPKE KEM interface as follows.
>
> The SerializePublicKey, SerializePrivateKey, and DeserializePrivateKey are the identity functions, as X-Wing keys are fixed-length byte strings, see Section 5.1.
>
> DeriveKeyPair() is given by
>
> ```
> def DeriveKeyPair(ikm):
>   # Extract 32-byte seed from variable-length ikm using SHAKE.
>   sk = SHAKE256(ikm, 32*8)
>   return GenerateKeyPairDerand(sk)
> ```
>
> where the HPKE private key and public key are the X-Wing decapsulation key and encapsulation key respectively.
>
> Encap() is Encapsulate() from Section 5.4, where an ML-KEM encapsulation key check failure causes an HPKE EncapError.
>
> Decap() is Decapsulate() from Section 5.5.
>
> X-Wing is not an authenticated KEM: it does not support AuthEncap() and AuthDecap(), see Section 1.4.
>
> Nsecret, Nenc, Npk, and Nsk are defined in Section 7."

§7, IANA Considerations — VERIFIED:

> "Value: 25722 = 25519 + 203 = 0x647a (please) … Nsecret: 32 / Nenc: 1120 / Npk: 1216 / Nsk: 32 / Auth: no"

**Answers to the two questions asked.**

- *Does X-Wing define `DeriveKeyPair`/`Encap`/`Decap` compatible with HPKE's KEM interface?* **Yes, explicitly and normatively**, §5.6. VERIFIED.
- *Is X-Wing intended to be used as an HPKE KEM?* **Yes, by explicit design goal.** VERIFIED.

Two consequences that constrain any test:

1. **Auth mode is out of scope for X-Wing.** `Auth: no` (§7) and "it does not support AuthEncap() and AuthDecap()" (§5.6). Only `mode_base` and `mode_psk` are meaningful. RFC 9180 §7.1.5 makes the same statement for future KEMs: "If a KEM algorithm does not provide them, only the Base and PSK modes of HPKE are supported."
2. **`DeriveKeyPair` has a specified X-Wing-specific twist.** RFC 9180 §7.1.3 specifies `DeriveKeyPair` only for the DHKEM variants defined in RFC 9180. X-Wing overrides it with SHAKE256(ikm, 32). Any harness must use the draft's version, not the DHKEM version.

### 1.2 What the X-Wing draft does NOT specify

**Appendix C carries exactly three KEM vectors and no HPKE vectors.** VERIFIED, from the machine-readable corpus (`spec/test-vectors.json`, 15,177 bytes, 3 entries) and from Appendix C's printed text. The schema is `seed, eseed, ss, sk, pk, ct` — six KEM fields. The strings `hpke` and `9180` appear **zero** times in that file.

Appendix C is also self-flagged as provisional. VERIFIED — the section heading in the TOC renders as:

> "Appendix C. Test vectors # TODO: replace with test vectors that re-use ML-KEM, X25519 values"

So the draft's own test corpus is acknowledged incomplete, and HPKE vectors are not part of the gap it names.

---

## 2. Do authoritative X-Wing-in-HPKE vectors exist? — CONFIRMED ABSENT

**No authoritative X-Wing-in-HPKE test vectors were found.** This is a confirmed absence within the sources searched, not an inference from silence.

### 2.1 Queries actually run

| # | Source | Query / endpoint | Result |
|---|---|---|---|
| 1 | datatracker | `draft-connolly-cfrg-xwing-kem/` document page + full `-11` text | §5.6 specifies the HPKE binding; **Appendix C = 3 KEM vectors, zero HPKE** |
| 2 | datatracker | full text scan of `-11` for HPKE vectors | Only `hpke` mentions are §1.2, §1.5.1, §5.6, §6, §7, reference `[RFC9180]` |
| 3 | Draft source repo | `api.github.com/repos/dconnolly/draft-connolly-cfrg-xwing-kem/git/trees/main?recursive=1` | 28 paths; only `spec/test-vectors.{json,txt}` + `spec/xwing_test.py`; **no HPKE vectors file** |
| 4 | Draft vector corpus | `raw.../spec/test-vectors.json` | 3 entries, 6 KEM fields, `hpke`→False, `9180`→False |
| 5 | CIRCL corpus | `raw.../circl/v1.6.5/hpke/testdata/vectors_rfc9180_5f503c5.json.gz` | `kem_ids = [16, 18, 32, 33]` — DHKEM only. **`0x647a` absent.** |
| 6 | CIRCL tree | `api.github.com/repos/cloudflare/circl/contents/hpke?ref=v1.6.5` | 18 entries; single `testdata/`, holding only the RFC 9180 corpus |
| 7 | RustCrypto | `RustCrypto/KEMs` tree → `x-wing/tests/{kats.rs,test-vectors.json}` | Same 3 KATs, same 6 fields, `hpke`→False, `9180`→False |
| 8 | X-Wing-KEM-Team C impl | `X-Wing-KEM-Team/xwing` tree, 223 paths | Benchmark CSVs + AVX2 sources; `test_vectors.h` is KAT-only |
| 9 | rugo, orion | `rugo/xwing-kem.rs` (10 paths), `orion-rs/orion` | Single `src/xwing.rs`; no HPKE vector file |
| 10 | GitHub repo search | `api.github.com/search/repositories?q=xwing+kem&sort=stars` | 13 repos; none publishes X-Wing HPKE vectors |
| 11 | GitHub code search | `search/code?q=X-Wing+hpke+test+vectors` | **HTTP 401 — requires authentication. Not run.** |
| 12 | General web search | `web_search` tool | **HTTP 426, CLI 1.0.5 outdated. Unavailable all session.** |

### 2.2 Why this absence is expected, not an anomaly

RFC 9180's own corpus is DHKEM-only *by construction* — §7.1's KEM table contains exactly five entries (0x0010/0x0011/0x0012/0x0020/0x0021) and X-Wing did not exist when it was written. X-Wing §7 registers `0x647a` with the IANA "HPKE KEM Identifiers" registry but is only *requesting* it ("please"); it is not yet assigned. So:

- RFC 9180's corpus **cannot** contain X-Wing vectors — the codepoint was unassigned.
- The X-Wing draft defines the HPKE binding but publishes no HPKE vectors — a real gap in the draft, not a search failure.

**VERIFIED. The gap is authoritative and reproducible: as of 2026-10-03, X-Wing is specified for HPKE use and there are no published HPKE test vectors for it from any source.**

---

## 3. CIRCL's actual X-Wing + HPKE surface

**CIRCL v1.6.5 can and does use X-Wing as an HPKE KEM.** This refutes the hypothesis that the claim is "untestable with the current cohort." VERIFIED from source at tag `v1.6.5`.

### 3.1 The codepoint is registered and selected

`hpke/algs.go`:

```go
// KEM_XWING is a hybrid KEM using X25519 and ML-KEM-768.
KEM_XWING KEM = 0x647a
```

`0x647a` = 25722, matching X-Wing §7 exactly.

`hpke/algs.go`, `func (k KEM) IsValid()`:

```go
case KEM_P256_HKDF_SHA256,
	KEM_P384_HKDF_SHA384,
	KEM_P521_HKDF_SHA512,
	KEM_X25519_HKDF_SHA256,
	KEM_X448_HKDF_SHA512,
	KEM_X25519_KYBER768_DRAFT00,
	KEM_XWING:
	return true
```

`hpke/algs.go`, `func (k KEM) Scheme()`:

```go
	case KEM_XWING:
		return kemXwing
```

and the package-level wiring:

```go
var (
	dhkemp256hkdfsha256, dhkemp384hkdfsha384, dhkemp521hkdfsha512 shortKEM
	dhkemx25519hkdfsha256, dhkemx448hkdfsha512                    xKEM
	hybridkemX25519Kyber768                                       hybridKEM
	kemXwing                                                      genericNoAuthKEM
)

func init() {
	…
	kemXwing.Scheme = xwing.Scheme()
	kemXwing.name = "HPKE_KEM_XWING"
}
```

### 3.2 The adapter implements the HPKE `DeriveKeyPair` twist correctly

`hpke/genericnoauthkem.go` — the whole file, and it is short because the point is the comment:

```go
// Shim to use generic KEM (kem.Scheme) as HPKE KEM.

// genericNoAuthKEM wraps a generic KEM (kem.Scheme) to be used as a HPKE KEM.
type genericNoAuthKEM struct {
	kem.Scheme
	name string
}

func (h genericNoAuthKEM) Name() string { return h.name }

// HPKE requires DeriveKeyPair() to take any seed larger than the private key
// size, whereas typical KEMs expect a specific seed size. We'll just use
// SHAKE256 to hash it to the right size as in X-Wing.
func (h genericNoAuthKEM) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	seed2 := make([]byte, h.Scheme.SeedSize())
	hh := sha3.NewShake256()
	_, _ = hh.Write(seed)
	_, _ = hh.Read(seed2)
	return h.Scheme.DeriveKeyPair(seed2)
}
```

This is byte-for-byte X-Wing §5.6's `DeriveKeyPair`: `sk = SHAKE256(ikm, 32*8)` then `GenerateKeyPairDerand(sk)`. VERIFIED match to the draft.

`xwing.Scheme()` (`kem/xwing/scheme.go`) supplies the rest of the interface CIRCL's generic HPKE needs: `EncapsulateDeterministically`, `Decapsulate`, `UnmarshalBinaryPublicKey`, `UnmarshalBinaryPrivateKey`, `PublicKeySize`/`PrivateKeySize`/`SeedSize`/`SharedKeySize`/`CiphertextSize`. All present. VERIFIED.

### 3.3 Auth mode is correctly refused

`hpke/hpke.go` declares X-Wing's adapter as `genericNoAuthKEM`, which does not implement `kem.AuthScheme`. `Sender.SetupAuth` therefore returns `ErrInvalidAuthKEM` ("hpke: KEM does not support Auth mode") rather than silently producing a wrong answer. VERIFIED — this matches X-Wing §5.6 and §7 (`Auth: no`) exactly.

### 3.4 The one real limitation

`genericNoAuthKEM` **embeds** `kem.Scheme` rather than implementing a private-key-only interface. `kem.Scheme.DeriveKeyPair` takes exactly `SeedSize` bytes (32 for X-Wing), while RFC 9180 §7.1.3 says `ikm` "SHOULD have at least `Nsk` bytes" and may be longer. The shim's SHAKE256 pre-hash absorbs that, but only because it re-hashes *everything* down to 32 bytes. VERIFIED — this is a deliberate, documented workaround, and it matches the draft. Not a defect.

**Conclusion for §3: CIRCL v1.6.5 exposes X-Wing through a `kem.Scheme` that HPKE accepts, with a correct `DeriveKeyPair`, correct sizes, and a correctly-absent Auth mode. The X-Wing-in-HPKE claim is testable today. VERIFIED.**

---

## 4. The Base-mode key schedule byte — the audit is WRONG

### 4.1 The correct value

**`key_schedule_context` for `mode_base` begins with `0x00`.**

RFC 9180 §5, Table 1, "HPKE Modes". VERIFIED verbatim:

```
| Mode            | Value |
| --------------- | ----- |
| mode_base       | 0x00  |
| mode_psk        | 0x01  |
| mode_auth       | 0x02  |
| mode_auth_psk   | 0x03  |
```

RFC 9180 §5.1 `KeySchedule<ROLE>` — the `mode` parameter is one byte and is concatenated first:

```
key_schedule_context = concat(mode, psk_id_hash, info_hash)
```

### 4.2 Three independent confirmations

**(a) RFC 9180's own worked example.** Appendix A.1.1, "Base Setup Information", `DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`. VERIFIED verbatim from the RFC text:

```
mode: 0
…
key_schedule_context: 00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449
```

The `mode:` field literally reads `0`, and the context's first byte is `00`. VERIFIED.

**(b) The machine-readable corpus.** I decompressed CIRCL's bundled `vectors_rfc9180_5f503c5.json.gz` (v1.6.5, 1,692,035 bytes gz, sha256 `99195f41e2e113ae99c7d85b34dff8d9f9e151a9ead397ababc0d925265a2310`). Grouping by declared `mode`:

| mode | first byte of `key_schedule_context` across all vectors |
|---|---|
| 0 | `0` |
| 1 | `0` |
| 2 | `0` |
| 3 | `0` |

VERIFIED. Mode 0 (Base) vectors all begin `00`.

**(c) Full independent recomputation.** I reimplemented RFC 9180 §5.1 from the RFC text (no CIRCL code involved) and recomputed `key_schedule_context`, `secret`, `key`, `base_nonce`, and `exporter_secret` for every non-export-only vector:

```
RFC 9180 supported vectors independently reproduced: 96   mismatched: 0
```

**96 of 96 reproduced, 0 mismatched.** VERIFIED. The corpus totals 128, with 32 export-only (AEAD `0xffff`) vectors at indices `12–15, 28–31, 44–47, 60–63, 76–79, 92–95, 108–111, 124–127`, leaving 96 supported. This independently confirms the audit's `96 / 32 / 128` figures and independently confirms the mode byte, since 96/96 could not reproduce under any other value.

### 4.3 Verdict on `.scratch/xwing/py_xwing/debug_hpke.py`

`.scratch/xwing/py_xwing/debug_hpke.py:66`:

```python
keySchCtx = b"\x00" + pskIDHash + infoHash
```

**This is CORRECT.** `0x00` *is* `mode_base`. The audit's assertion —

> "`debug_hpke.py:66` uses `keySchCtx = 0x00` where RFC 9180 §5.1 requires mode `0x01` for Base mode"

— is **false**, and reverses the RFC. `0x01` is `mode_psk`; using it in Base mode would be the bug. The script is left unfixed in a state that is, on this point, right.

**What this actually invalidates: nothing about `debug_hpke.py`.** It invalidates one clause of the audit — `rev-2026-0018`'s fnd-2026-0007 verdict line "(f)" and the `evidence_integrity_concern` bullet in `fnd-2026-0007.yaml` that repeats it. Those must be struck, not merely softened, because they assert a spec violation that did not occur.

I am not able to certify the *rest* of `debug_hpke.py` from source reading alone: I did not execute it, and the `exporter_secret` it prints depends on `hpke_out.exporter_secret` from a JSON file whose provenance is the harness at `.scratch/xwing/harness/` (which has two `func main()` and cannot build). **COULD-NOT-DETERMINE** whether `debug_hpke.py`'s output was ever correct even though its mode byte is right.

### 4.4 A real and separate defect, in the *other* Python HPKE reference

`.scratch/msn-2026-0009/hpke_ref.py` is wrong, and differently wrong. VERIFIED by reading it and measuring it:

```python
SUITE_ID_XWING_HPKE_SHA256_AES128GCM = bytes([
    ord('K'), ord('E'), ord('M'), 0x64, 0x7A,
    ord('K'), ord('D'), ord('F'), 0x00, 0x02,
    ord('A'), ord('E'), ord('A'), ord('D'), 0x00, 0x01,
])
…
key_sched_ctx = enc + SUITE_ID_XWING_HPKE_SHA256_AES128GCM + b"" + info
```

Five defects, all confirmed:

1. **`suite_id` is 16 bytes of nonsense.** RFC 9180 §5.1: `suite_id = concat("HPKE", I2OSP(kem_id,2), I2OSP(kdf_id,2), I2OSP(aead_id,2))` = `b'HPKE' + 0x647A + 0x0001 + 0x0001` = 10 bytes. The script builds `"KEM"`+`"KDF"`+`"AEAD"` ASCII sections with no such definition.
2. **KDF codepoint is `0x0002` = HKDF-SHA384, not `0x0001` = HKDF-SHA256** — while the module docstring and function body use SHA-256 throughout.
3. **`key_schedule_context` structure is wrong.** It builds `enc || suite_id || psk_id_hash || info`. RFC 9180 requires `mode || psk_id_hash || info_hash` — 65 bytes for Base mode. The script omits the mode byte entirely, omits `info_hash`, uses a zero-length `psk_id_hash` instead of a labeled extract, and prepends `enc`. Measured: **1,166 bytes vs. the RFC's 65.**
4. **`exporter_secret` is double-derived.** It applies `hkdf_extract` to the `exp` expansion. RFC 9180 §5.1 assigns `exporter_secret` directly from `LabeledExpand(secret, "exp", ...)` with no further extract.
5. **`hkdf_expand_label` misapplies RFC 9380 framing.** It emits `bytes([len(lab)])` — a single-byte length prefix — around `"HPKE-v1" || label`. RFC 9180 §4's `LabeledExpand` has no such length prefix; the only length prefix in `labeled_info` is the leading `I2OSP(L, 2)`.

`.scratch/msn-2026-0009/oracle_src/oracle.go` carries the **same five defects** in Go (verified at `oracle.go:226–248`, and the HkdfLabel construction at `oracle.go:287–301`).

**This means `full_audit_summary.json`'s `hpke_base_setup` block — `n_key_agree: 10, n_base_nonce_agree: 10, n_exporter_secret_agree: 10, n_ciphertext_agree: 10, n_total: 10` — is a tautology.** Two implementations of the *same wrong* construction agreeing 10/10 says nothing about RFC 9180 conformance. It is not independent evidence of anything. It must be struck. (The `xwing_combiner` and `mutation_matrix` blocks in that file concern the X-Wing KEM proper and are not affected by this.)

**No committed artifact cites `full_audit_summary.json`** — I checked `fnd-2026-0007`, `rev-2026-0007`, `rev-2026-0018`, `exp-2026-0021`, `exp-2026-0022`. The damage is contained to `.scratch`. Good.

---

## 5. Recommended smallest honest test

### 5.1 Recommendation: **option (b)**, run against **option (a)'s library as the second oracle**

Of the two options:

- **(a) cross-implementation byte-comparison against an independent X-Wing-in-HPKE implementation** — there is no such implementation to compare against. Every X-Wing library in Appendix A implements the KEM; none publishes an HPKE context, and CIRCL is the only one with HPKE wiring. Running (a) means *writing* a second implementation, which converts a conformance test into a differential test between my code and CIRCL's. It can only prove CIRCL matches something I wrote, and my code is exactly what the test is meant to check.
- **(b) KAT vectors from the draft's Appendix C applied through HPKE Base mode** — this is a genuine end-to-end test with an authoritative oracle for the KEM half, and the HPKE half is fully determined by RFC 9180 §5.1, which is unambiguous and already validated 96/96 above. It requires no new implementation and no new trust.

**Choose (b).** Then add a thin (a): compare CIRCL's own HPKE Base-mode output against the RFC-9180 recomputation script used in §4.2(c), which is a *reference from the RFC*, not a second library. That gives both a vector anchor and a second oracle, at minimal cost.

### 5.2 The harness

**Do not extend `.scratch/xwing/harness/`.** It cannot build (two `func main()`), its `--vectors` flag does not exist, and `verify_reproducibility.py` is tautological. Start clean in an env-scrubbed scratch tree.

**Inputs.** The three Appendix C vectors, transcribed from `spec/test-vectors.json` (`seed`, `eseed`, `sk`, `pk`, `ct`, `ss` — 32/64/32/1216/1120/32 bytes). Do **not** reuse `.scratch/xwing/reports/canonical.json`; its `seed` is `00…1f`, which is the harness's own invention, not a draft vector.

**Suite.** `KEM_XWING (0x647a) / KDF_HKDF_SHA256 (0x0001) / AEAD_AES128GCM (0x0001)` → `suite_id = b'HPKE' + 647A + 0001 + 0001` = `48504b45647a00010001`. Base mode only. Per §1.1, do not attempt Auth or AuthPSK — X-Wing does not support them and CIRCL correctly refuses.

**Procedure, per vector:**

1. `xwing.Scheme().UnmarshalBinaryPrivateKey(sk)` / `UnmarshalBinaryPublicKey(pk)`. Assert the round-trip: `Decapsulate(ct, sk) == ss`. This is the KEM anchor and must hold before anything else.
2. Recipient key derivation, HPKE-style: `xwing.DeriveKeyPairPacked(SHAKE256(ikm, 32))` where `ikm` is a fixed test input. Assert `pk' == pk`. **This is the one genuinely X-Wing-specific HPKE behaviour** (§5.6's SHAKE256 twist), and it is currently untested anywhere in the corpus. Pick `ikm` ≥ 32 bytes so the test would catch a regression to the DHKEM §7.1.3 form.
3. Sender, Base mode, deterministic: `sender.Setup(bytes.NewReader(eseed))`. Assert `len(enc) == 1120` and **`enc == ct` from the vector** — the draft's `eseed` is exactly the 64-byte HPKE encapsulation seed, and CIRCL's `EncapsulateTo` splits it `seed[0:32]` → ML-KEM, `eseed[32:64]` → X25519, identically to `EncapsulateDerand`. This is the load-bearing assertion: it proves HPKE's `Encap` and the draft's `EncapsulateDerand` agree byte-for-byte.
4. Recipient, Base mode: `receiver.Setup(enc)`. Assert `Open(sealOut, aad) == pt`.
5. Key-schedule cross-check against the §4.2(c) reference. Feed the vector's `ss` into the RFC 9180 recomputation with `mode=0x00`, `suite_id` as above, the test `info`; compare `key`, `base_nonce`, `exporter_secret`, and one `Seal` ciphertext byte-for-byte against CIRCL's context values.
6. `Context.Export` at two different exporter contexts, compared against the reference.

**Two oracles, one artifact.** The Go side emits `{enc, ss, key, base_nonce, exporter_secret, ct, export0, export1}` per vector as JSON. The Python RFC-9180 reference emits the same keys from `ss` alone. Compare with `diff`. Both sides must agree **and** agree with the Appendix C `ss`/`ct`.

**Make the oracle the RFC, not the library.** The reference implementation must be transcribed from RFC 9180 §5.1 text, and validated by construction: run it against the 96 supported DHKEM vectors first and require 96/96 before trusting a single X-Wing line of its output. This is the discipline that would have caught `hpke_ref.py`.

**Route to CI, not local.** Per `Agents.md` compute routing, this is a `medium` workload — two toolchains, one small JSON diff. GitHub Actions. If it turns out to be a single-file Go test with no second toolchain, it drops to `lightweight` and may run in an env-scrubbed local scratch. Record the decision in the experiment artifact either way.

**Claims the result supports, and no further:**

> "CIRCL v1.6.5's HPKE Base-mode implementation agrees byte-for-byte with the X-Wing draft's Appendix C vectors and with an independent transcription of RFC 9180 §5.1, for KEM `0x647a` / KDF `0x0001` / AEAD `0x0001`."

That is a real conformance statement with two independent oracles. It is **not** a statement about interoperability with other implementations, because none exist to interoperate with. It is **not** coverage of PSK mode, which is a separate claim I am not testing.

### 5.3 The claim that should be published regardless

Even if no harness is ever built, one finding here is independently valuable and costs nothing:

> **X-Wing §5.6 defines an HPKE KEM binding for which no HPKE test vectors exist in any published source as of 2026-10-03.** The X-Wing draft's own Appendix C is explicitly marked incomplete ("# TODO: replace with test vectors that re-use ML-KEM, X25519 values") and contains three KEM vectors and no HPKE vectors. RFC 9180's corpus cannot supply them — `0x647a` was unassigned when RFC 9180 was published and is only *requested* (not assigned) by X-Wing §7.

That is a clean, verified, useful gap. It is the honest shape of the "X-Wing + HPKE is byte-exact RFC 9180 conformant, verified via test-vector pass" claim's successor.

---

## 6. What I could not determine

1. **GitHub code search.** `search/code?q=X-Wing+hpke+test+vectors` returned **HTTP 401 — Requires authentication**. Unauthenticated code search is unavailable. A private vector set inside a repo I did not enumerate would not have been found by my repo-name search either. My absence claim covers the sources in §2.1 and does not extend to arbitrary private code.
2. **General web search.** The `web_search` tool failed with **HTTP 426** on every attempt (CLI 1.0.5, needs ≥ 1.0.13). No third-party commentary, blog, mailing-list post, or issue discussing X-Wing HPKE vectors was reachable. The CFRG mail archive was not searched. This is the same limitation `rev-2026-0018` recorded.
3. **`mailarchive.ietf.org` discussion.** Not attempted; the audit reported Cloudflare interstitials there. Whether the CFRG working group has discussed the missing HPKE vectors — and whether anyone has committed to producing them — is **unresolved**. This is the single most decision-relevant unknown: if vectors are already planned upstream, building a private harness is wasted work and the right output is a tracking observation instead.
4. **Whether `debug_hpke.py` ever produced correct output.** Its mode byte is correct (§4.3), but I did not execute it, and its input JSON comes from the unbuildable `.scratch/xwing/harness/`. The `exporter_secret` it prints could not be traced to a verified source. Its `info_hash` / `psk_id_hash` / labeled-expand logic reads correctly against RFC 9180 §5.1, but reading is not execution.
5. **IANA registry state for `0x647a`.** X-Wing §7 says "please"; I read the draft but did not query the live IANA "HPKE KEM Identifiers" registry at <https://www.iana.org/assignments/hpke/hpke.xhtml>. Whether `25722` has since been assigned is **unverified**. It does not affect any conclusion above — CIRCL already uses the value and the draft fixes it — but the claim "requested, not assigned" in §5.3 is a draft-text claim, not a registry-state claim.
6. **CIRCL's X-Wing conformance to draft -11 specifically.** `kem/xwing/xwing.go`'s docstring still reads "Implements the final version (-05)". I confirmed the combiner and Appendix C vectors are bit-stable across -05/-08/-11 (consistent with `rev-2026-0018`'s finding, which I did not re-verify line-by-line), but I did not diff `xwing.go` against §5.6's `DeriveKeyPair` beyond the SHAKE256 construction in `genericnoauthkem.go`, which I did verify directly.
7. **Whether the 96 DHKEM vectors passing means anything about X-Wing.** It does not. They share zero code paths with the X-Wing KEM. I note this explicitly because the original finding's error was precisely this kind of inference.

---

## Appendix — claim ledger

| Claim | Source | Status |
|---|---|---|
| X-Wing current revision is -11, 2026-09-23 | datatracker | **VERIFIED** |
| X-Wing §5.6 defines HPKE `DeriveKeyPair`/`Encap`/`Decap` | draft -11 §5.6 | **VERIFIED** |
| `DeriveKeyPair(ikm) = SHAKE256(ikm, 32*8)` then `GenerateKeyPairDerand` | draft -11 §5.6 | **VERIFIED** |
| X-Wing HPKE target is a design goal | draft -11 §1.2 | **VERIFIED** |
| X-Wing `Auth: no`; no `AuthEncap`/`AuthDecap` | draft -11 §1.4, §5.6, §7 | **VERIFIED** |
| KEM codepoint `0x647a` = 25722; Nsecret 32 / Nenc 1120 / Npk 1216 / Nsk 32 | draft -11 §7 | **VERIFIED** |
| Appendix C = 3 KEM vectors, zero HPKE vectors | draft -11 App. C; `spec/test-vectors.json` | **VERIFIED** |
| Appendix C marked incomplete ("# TODO") | draft -11 TOC heading | **VERIFIED** |
| `spec/test-vectors.json`: 3 entries, 6 KEM fields, no `hpke`/`9180` | raw githubusercontent | **VERIFIED** |
| RFC 9180 corpus has zero X-Wing vectors (`kem_ids` 16/18/32/33) | decompressed at v1.6.5 | **VERIFIED** |
| CIRCL bundled corpus = 128 total / 32 export-only / 96 supported | decompressed at v1.6.5 | **VERIFIED** |
| Export-only indices `12–15 … 124–127` | decompressed at v1.6.5 | **VERIFIED** |
| Corrupted gz sha256 `99195f41e2e113ae99c7d85b34dff8d9f9e151a9ead397ababc0d925265a2310` | local download | **VERIFIED** |
| **RFC 9180 `mode_base` = `0x00`** | RFC 9180 §5 Table 1 | **VERIFIED** |
| Appendix A.1.1 Base Setup lists `mode: 0` | RFC 9180 App. A.1.1 | **VERIFIED** |
| All 96 vectors' `key_schedule_context` begin with `mode` byte | corpus scan | **VERIFIED** |
| **96/96 vectors reproduced by independent RFC 9180 reimplementation** | local recomputation | **VERIFIED** |
| `debug_hpke.py:66` uses `0x00` — **CORRECT**, not a bug | file + RFC 9180 §5 | **VERIFIED** |
| Audit claim "`0x01` required for Base mode" is **FALSE** | contradicts RFC 9180 §5 | **VERIFIED FALSE** |
| `hpke_ref.py` builds 1,166-byte context vs RFC's 65 | measured | **VERIFIED** |
| `hpke_ref.py` + `oracle.go` share the same 5 HPKE defects | source read | **VERIFIED** |
| `full_audit_summary.json` `hpke_base_setup` 10/10 is a tautology | both oracles share defects | **VERIFIED** |
| `full_audit_summary.json` not cited by any committed artifact | grep of fnd/rev/exp 0007 | **VERIFIED** |
| CIRCL `KEM_XWING = 0x647a`, in `IsValid()` and `Scheme()` | `hpke/algs.go` @v1.6.5 | **VERIFIED** |
| CIRCL `genericNoAuthKEM.DeriveKeyPair` = SHAKE256(ikm, 32) | `hpke/genericnoauthkem.go` @v1.6.5 | **VERIFIED** |
| CIRCL refuses Auth for X-Wing (`ErrInvalidAuthKEM`) | `hpke/hpke.go` @v1.6.5 | **VERIFIED** |
| Authoritative X-Wing HPKE vectors **do not exist** | 10 sources, §2.1 | **VERIFIED ABSENT** (scoped) |
| GitHub code search | HTTP 401 | **COULD-NOT-DETERMINE** |
| General web search / CFRG mail archive | HTTP 426 / not attempted | **COULD-NOT-DETERMINE** |
| Live IANA registry state for `25722` | not queried | **COULD-NOT-DETERMINE** |
| Whether `debug_hpke.py` ever ran correctly | not executed | **COULD-NOT-DETERMINE** |
