<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: rev-2026-0017_draft.md -->

# REV-2026-0017 (DRAFT) — Adversarial critique of fnd-2026-0014 and obs-2026-0046

Role: adversarial-critic (non-synthesizer). Read-only over the repo; no repo file
was created or edited by this review. Scratch probes were written under `R:\` and
deleted in the same session. Nothing is promoted here.

Targets:
- `knowledge/findings/fnd-2026-0014.yaml` (status `verified_conclusion`)
- new evidence `exp-2026-0034` / `obs-2026-0046` / `cose-cross-impl/probes/`

---

## 1. Verdict

**REFUTES** — the *empirical* behaviour (pycose 1.1.0 emits protected-header maps in
insertion order, not §4.2.1 order) survives every attack I ran and is now the best-supported
claim in the chain, but the finding's `classification.primary: "SPEC_VIOLATION per RFC 9052
§9 / RFC 8949 §4.2.1"` and its quoted normative text are **wrong**, and the RFC 9052 §9 quote
stored in `fnd-2026-0014.normative_basis` **does not exist in RFC 9052**.

---

## 2. Attack log

### H1 — "pycose genuinely has no canonical path"

Tried: static grep of every module in the installed package; runtime sweep of every plausible
entry point.

```
.\.venv\Scripts\python.exe -m pip show pycose cbor2     -> pycose 1.1.0, cbor2 6.1.4
```
Walked `site-packages/pycose/**` via `pkgutil.walk_packages`, case-insensitive search for
`canonical`: **0 hits** (mine). Confirms obs-2026-0046's `absence_of_alternative`.
`inspect.getsource(CoseBase.phdr_encoded.fget)` — I reproduced the exact body; line **136**
verified independently via `Select-String`:
`return cbor2.dumps(self._phdr, default=self._custom_cbor_encoder)`.

Runtime sweep for a canonical path:

| Attempt | Result |
|---|---|
| module-level default injection `cbor2.dumps(..., canonical=True)` | **works** — but only reaches §4.2.3, see H2 |
| `Sign1Message.decode(canonical_msg)` then re-encode | **`TypeError: Bytes cannot be decoded as COSE message`** — pycose 1.1.0's `decode()` cannot ingest a `cbor2`-produced tagged array (`cosemessage.py:65` requires `list`; `cbor2` yields `tuple`). Independently confirmed; obs-2026-0046 recorded the same quirk. |
| subclass overriding `phdr_encoded` | produced `a0` — my override was wrong (map keys are `CoseHeaderAttribute` objects, not labels); a correct override *is* possible. **This is a real escape hatch but it is not public API.** |
| `CoseKey` serialization | not reachable (no `generate_key`, `KeyCurve` import differs in 1.1.0) — **not established** |
| `x5bag` | not exercised — **not established** |
| symbols named `canonical`/`sort` | none |

**SURVIVED, with one correction.** There is no *documented* canonical path. There *is* an
undocumented one: `CoseBase.__init__(phdr_encoded=...)`, and — the part obs-2026-0046 frames
as "mitigation, not exoneration" — it is **not a mitigation at all**, because it is the
mechanism the decoder itself uses (H5 below). It is also easy to trip over: `phdr` and
`phdr_encoded` are mutually exclusive (`ValueError`), and both `phdr` setter and
`phdr_update()` clear the cache, so any later mutation silently reverts to insertion order.

### H2 — "the canonical side of the comparison is right"

**This is where the finding breaks.** I tested the RFC 8949 §4.2.1 worked example directly:

```
.\.venv\Scripts\python.exe R:\critic_probe_6.py
```

RFC 8949 §4.2.1 states the correct order is `10, 100, -1, "z", "aa", [100], [-1], false`.
Measured, mine:

- `cbor_oracle.encode_canonical(...)` → `[10, 100, -1, "z", "aa", "ab", False]` — **matches
  the RFC** (I dropped `False` vs `"ab"` confusion; the RFC list has 8 keys, mine substituted
  the `[100]`/`[-1]` list keys which Frontier's oracle renders). Not §4.2.3.
- `cbor2.dumps(..., canonical=True)` (cbor2 6.1.4) → `[10, -1, False, 100, "z", "aa", "ab"]` —
  this is exactly RFC 8949 §4.2.3 **length-first** order.

So **Frontier's oracle is correct and `cbor2`'s `canonical=True` is the wrong rule.** That
invalidates the natural one-line fix, and obs-2026-0046's
`cbor2_canonical_true_is_4_2_3_not_4_2_1` finding is **confirmed by me** on an independent
vector:

```
map {1000: b"x", "z": b"y"}
  4.2.1        : a21903e84178617a4179
  4.2.3        : a2617a41791903e84178
  cbor2 canon  : a2617a41791903e84178
  pycose fwd   : a21903e84178617a4179   (== 4.2.1)
  pycose rev   : a2617a41791903e84178   (== 4.2.3)
```

**The comparison does not collapse**, but only because `encode_canonical` was used. Note the
earlier artifacts used the *other* oracle in places: `obs-2026-0045` says it compared against
"the `cbor2` canonical=True encoding of the same map" — that comparator implements §4.2.3.
It happens to agree with §4.2.1 on every vector in that observation (all key encodings are
equal length), so its conclusions are unaffected, but **the stated comparator is misdescribed
and must not be cited as a §4.2.1 reference.**

### H3 — "the probe is not confounded"

**SURVIVED — this is the strongest part of the new evidence.**

- I reproduced claim 1 from scratch: pycose emits
  `a40281637a7a7a636d6d6d0704496b69642d627974657363717171f5`; my oracle emits
  `a40281637a7a7a04496b69642d6279746573636d6d6d0763717171f5`. Byte-identical to obs-2026-0046.
- I decoded the orchestrator's hex strings myself. Self-consistent.
- Reversed insertion `[qqq,4,mmm,2]` → `a463717171f504496b69642d6279746573636d6d6d070281637a7a7a`.
  Matches. Forward ≠ reversed ⇒ no sort.
- `zzz`/`mmm`/`qqq` confirmed unregistered against `CoseHeaderAttribute.get_registered_classes()`.
- Int labels `2` and `4` are **not** normalized — decoded key types `['int','str','int','str']`.
- Python 3.11.15; dict insertion order is language-guaranteed since 3.7. Sound.

One methodological caveat: pycose **value-validates** labels before encoding. `{24: b'x'}`
raises `ValueError: KID should be a byte string`; int label `7` is treated as
`CoseAlgorithm` and raises `Unknown COSE attribute with value`. So an int-only vector that
wants label 4 must use a bstr. Reproducer-design constraint, not an ordering result —
obs-2026-0046 flagged this too; I confirm it.

### H4 — "scope creep"

Several over-claims. Listed verbatim in §4 below.

### H5 — "`phdr_encoded` is a red herring / already-known"

**It is already-known, and it is not a red herring — it inverts the finding's impact story.**

`cosebase.py:21-25` (`CoseBase.from_cose_obj`) does `phdr_encoded = cose_obj.pop(0)` and
`cosebase.py:51` does `self._phdr_encoded = phdr_encoded`. So **pycose preserves the received
protected bytes verbatim on decode.** I measured:

```
[D5] received a2031832044179 -> after decode a2031832044179  PRESERVED_VERBATIM: true
     received a2044179031832 -> after decode a2044179031832  PRESERVED_VERBATIM: true
```

And with real cryptography (P-256/ES256, my own probe):

```
[D2] canonical protected bytes a2031832044179, signed by an independent
     conformant signer (raw ecdsa, no pycose encoding path):
     pycose preserved received bytes verbatim: True
     pycose verifies: True
```

So **a conformant message verifies in pycose.** pycose is interoperable as a *verifier*
regardless of the sender's ordering.

Conversely, the signer side does fail:

```
[D1] desc_4_3  pycose protected a2044179031832  (canonical a2031832044179)
      sig over pycose ToBeSigned   verifies: True
      sig over CANONICAL ToBeSigned verifies: False
[D1] asc_3_4   pycose protected a2031832044179  (== canonical)
      sig over pycose ToBeSigned   verifies: True
      sig over CANONICAL ToBeSigned verifies: True
```

Note `alg` had to be placed in the **unprotected** bucket: putting `Es256` in the protected map
makes `encode_canonical` raise `unsupported value: <class Es256>`, because Frontier's oracle
cannot encode a pycose algorithm class. That is an oracle limitation, not a pycose one.

**Conclusion for H5:** the divergence is real on the *signing* path and harmless on the
*verifying* path. Any maintainer report that claims symmetric "mutual unverifiability" is
wrong.

---

## 3. Independent measurements (MINE — not the orchestrator's)

Environment: `C:\Users\Dhane\frontier\.venv\Scripts\python.exe`, Python 3.11.15, pycose 1.1.0,
cbor2 6.1.4. Scripts under `R:\`, deleted after the run.

```
.\.venv\Scripts\python.exe R:\critic_probe_pycose.py   (H2/H3 setup; aborted on a harness bug)
.\.venv\Scripts\python.exe R:\critic_probe_2.py        (H1/H2/H3/H4 sweep)
.\.venv\Scripts\python.exe R:\critic_probe_3.py        (decode preservation, unprotected)
.\.venv\Scripts\python.exe R:\critic_probe_5.py        (real ES256 interop)
.\.venv\Scripts\python.exe R:\critic_probe_6.py        (decode preservation, 4.2.1/4.2.3, D8)
```

| Measurement | pycose 1.1.0 | §4.2.1 (Frontier `encode_canonical`) |
|---|---|---|
| `{2:["zzz"],"mmm":7,4:b"kid-bytes","qqq":True}` | `a40281637a7a7a636d6d6d0704496b69642d627974657363717171f5` | `a40281637a7a7a04496b69642d6279746573636d6d6d0763717171f5` |
| same, reversed | `a463717171f504496b69642d6279746573636d6d6d070281637a7a7a` | (same as above) |
| `{4:b"y",3:50}` | `a2044179031832` | `a2031832044179` |
| `{3:50,4:b"y"}` | `a2031832044179` | `a2031832044179` (agree by luck) |
| `{a,aa,b,ab,z}` | `a56161016261610261620362616204617a05` | `a5616101616203617a056261610262616204` |
| `{1000:b"x","z":b"y"}` | `a21903e84178617a4179` | `a21903e84178617a4179` |
| `{1000:b"x","z":b"y"}` reversed | `a2617a41791903e84178` | `a21903e84178617a4179` |
| `{1000,100,10,256}` | `a41903e84161186441620a41631901004164` | `a40a41631864416219010041641903e84161` |
| unprotected `{4:b"y",3:50}` | `a2044179031832` | `a2031832044179` |
| unprotected `{4:b"y","mmm":7,3:50}` | `a3044179636d6d6d07031832` | `a3031832044179636d6d6d07` |
| `{100,1000,10,1}` (D4) | `a4186441610a416201261903e84164` | `a40141630a4162186441611903e84164` |

Independent of pycose, I searched for an **int-only** map where §4.2.1 and §4.2.3 disagree:
**none exists** — for pure integer keys bytewise-lex on the encoded key is identical to
length-first (verified exhaustively over 3-subsets of `{1,10,24,100,255,256,1000,65535,65536}`).
So every int-only vector in the corpus is blind to the §4.2.1-vs-§4.2.3 question; only the
mixed `{1000,"z"}` vector discriminates, and it favours the finding.

Adapter equivalence (obs-2026-0046 claim 2): **confirmed**, byte-identical bare vs adapter on
all compared cases, including the registered-name `{"KID","Z"}` case.

---

## 4. Weaknesses / over-claims (verbatim-quotable)

1. **The normative quote in `fnd-2026-0014.normative_basis.rfc_9052_section_9` is not in
   RFC 9052.** The artifact quotes §9 as saying *"encoding MUST be done using definite
   lengths, the length of the encoded argument MUST be the minimum possible length, the keys
   in every map MUST be sorted in the bytewise lexicographic order of their deterministic
   encodings."* I fetched RFC 9052 (network available) and searched it. RFC 9052 §9 says:

   > This document limits the restrictions it imposes on how the CBOR Encoder needs to work.
   > The new encoding restrictions are aligned with the Core Deterministic Encoding
   > Requirements specified in Section 4.2.1 of RFC 8949 [STD94]. It has been narrowed down
   > to the following restrictions:
   > * The restriction applies to the encoding of the Sig_structure, the Enc_structure, and the MAC_structure.
   > * Encoding MUST be done using definite lengths, and the length of the (encoded) argument MUST be the minimum possible length. ...
   > * Applications MUST NOT generate messages with the same label used twice as a key in a single map. ...

   The phrase *"the keys in every map MUST be sorted in the bytewise lexicographic order"*
   appears **only** in RFC 8949 §4.2.1, **not** in RFC 9052 §9. And critically:

   > * **The restriction applies to the encoding of the Sig_structure, the Enc_structure, and the MAC_structure.**

   RFC 9052 §9 constrains the encoding of the **structures**, not of the protected-header map
   *as transported*. The protected map travels as an opaque bstr.

2. **"SPEC_VIOLATION per RFC 9052 §9" is the wrong classification.** The narrowing sentence
   means the three §4.2.1 requirements that survive into COSE are the three §4.2.1 bullets
   that are *also* restated — preferred serialization, no indefinite lengths, no duplicate
   keys. Map-key sorting is **not** among them. A conformant reading is that the protected
   map's internal ordering is unconstrained, and this is corroborated by RFC 9052 §3, which
   explains *why* the bucket is wrapped in a bstr:

   > Wrapping the encoding with a byte string allows the protected map to be transported with
   > a greater chance that it will not be altered accidentally in transit. ... This avoids
   > the problem of all parties needing to be able to do a common canonical encoding of the
   > map for input to cryptographic operations.

   That is an explicit design statement that parties are **not** required to agree on a common
   canonical encoding of the protected map. It is the strongest disproof available and it came
   from the RFC, not from a model.

3. **The pycose maintainers have already ruled on this, and against the finding.** PR
   TimothyClaeys/pycose#91 "Avoid re-encoding of protected header" (merged 2022-11-08,
   v1.0.1), authored by a collaborator and closed by the maintainer, states:

   > However, relying on this is brittle, especially since **COSE does not enforce any
   > deterministic encoding for the protected header.**
   > This PR preserves the encoded protected header and avoids re-encoding it.

   `phdr_encoded` — the very mechanism obs-2026-0046 frames as a *workaround* — is the merged
   upstream fix for issue #82. It is shipped. **H5 is answered: the behaviour is already-known
   and already-deliberate.** obs-2026-0046's `novelty remains unchecked` is now false.

4. **"Mutually unverifiable" / "signatures are mutually unverifiable" is false as written.**
   Measured: pycose *verifies* conformantly-ordered messages correctly (D2), because it
   preserves received bytes. Only the *signing* path produces divergent bytes. Any report
   saying both directions fail will be rejected by the maintainer on first inspection.

5. **`obs-2026-0045` misdescribes its own comparator** as "the `cbor2` canonical=True
   encoding". `cbor2`'s `canonical=True` is §4.2.3 length-first, not §4.2.1. Conclusions
   survive (all its vectors are length-ambiguous) but the comparator must not be cited as a
   §4.2.1 reference.

6. **"Widening the scope beyond protected headers" (obs-2026-0046, unprotected bucket) is
   an over-claim.** RFC 9052 §9's narrowing to Sig/Enc/MAC_structure means the unprotected
   bucket — which is not part of any of those structures — is outside §9 entirely. Emitting
   it in insertion order is not a deviation from anything the finding cites. My T10
   measurement stands as an observation; the *widen* claim does not.

7. **`cbor2_canonical_true_is_4_2_3_not_4_2_1` — confirmed and important.** obs-2026-0046 is
   right that "add `canonical=True`" is the wrong fix. But note the corollary that cuts the
   other way: if the library most COSE implementations use expresses `canonical=True` as
   §4.2.3, that is evidence the ecosystem reads "canonical CBOR" as §4.2.3, which weakens any
   maintainer-facing claim that §4.2.1 is mandatory here.

8. **Cohort is still 2; still only pycose 1.1.0; still only COSE_Sign1 protected maps.**
   `Enc0Message`/`Mac0Message` have no `_create_sig_structure` — my attempt raised
   `AttributeError`. Other message classes remain unmeasured. `cose_oracle.encode_canonical`
   cannot encode pycose algorithm classes, so any real-world protected map (which always has
   `alg`) cannot be put through the Frontier oracle at all. **This is a genuine gap: no
   measured vector contains a legal COSE protected header.**

---

## 5. What remains unestablished

- Whether pycose's maintainers would accept an ordering change as a *bug* (their own merged
  PR says the opposite). Not testable by me.
- Behaviour of any pycose version other than 1.1.0. Not testable without other versions.
- COSE_Sign, Encrypt0, Mac0, Encrypt, Mac protected-bucket ordering. **Unmeasured.**
- Whether pycose's *encoder* ordering affects MAC/AEAD correctness (it does not for
  verification, by the same D2 logic, but this was not measured for Enc0/Mac0).
- Whether any third COSE library re-encodes rather than preserves the protected bucket.
  go-cose was only compared at structure-byte level in the original matrix.
- The exact normative intent of RFC 9052 §9's narrowing sentence. My reading is that
  map-key sorting is excluded; I am confident but this is interpretation, not a citation.

## 6. Explicit uncertainty markers

- **UNVERIFIED-BY-ME-BY-NO-NETWORK: nothing.** I had network and fetched RFC 9052, RFC 8949
  §4.2.1/§4.2.3, the RFC 9052 errata page, RFC 9338, and the pycose GitHub API directly.
  All RFC quotes above are from those fetches.
- RFC 8949 §4.2.1 full text: I read §4.2.1 and §4.2.3 from the fetched HTML (lines 633-703 of
  the saved page). I did **not** read the whole of RFC 8949.
- The pycose PR #91 text is quoted from the GitHub API `pulls` endpoint. I did not fetch the
  diff. I did not read issue #82's body beyond what PR #91 quotes.
- **My reading of RFC 9052 §9's narrowing is an interpretation.** A maintainer could argue
  the narrowing is editorial and §4.2.1 applies wholesale. I cannot settle that from the text.
  I weight it heavily because of §3's bstr rationale and the maintainer's own PR, but it is
  interpretation.
- I could not test `CoseKey` serialization or `x5bag` — API shape differs in 1.1.0. Marked
  "not established" rather than assumed absent.
- `go-cose` behaviour on decode was not tested by me; I only read the existing matrix rows.
- The D1/D2/D3 crypto results used `ecdsa` (pycose's own backend) for verification rather than
  a separately-implemented verifier. The independent conformant signer in D2 used `ecdsa`
  directly with a hand-built `Sig_structure`, which is genuinely outside pycose's encoding
  path, but shares the crypto library.

---

## 7. What would still falsify a SUPPORT verdict

Since I am returning REFUTES, the symmetric question: what would falsify *my* verdict?

- A Frontier artifact showing RFC 9052 §9 in a version where the narrowing sentence does not
  restrict scope — i.e. evidence that §4.2.1 map ordering is mandatory for the protected
  bucket. I found no such text and §3 contradicts it.
- Evidence that pycose's merged PR #91 was later reverted, or that the maintainers subsequently
  changed position.
- A measurement showing pycose *fails to verify* a conformantly-ordered message (I measured
  the opposite, twice, with real crypto).
