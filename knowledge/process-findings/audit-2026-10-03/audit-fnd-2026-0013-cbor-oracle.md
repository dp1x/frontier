<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_fnd_0013.md -->

# Adversarial audit — fnd-2026-0013 (CBOR §4.2 cross-impl "byte-exact agreement")

**Auditor:** adversarial-critic (independent of the msn-2026-0017 promotion chain)
**Date:** 2026-10-03
**Target:** `knowledge/findings/fnd-2026-0013.yaml` — `status: verified_conclusion`, `disclosure: public`
**Method:** read-only. Re-ran the repo's own oracle/adapters under `C:\Users\Dhane\frontier\.venv\Scripts\python.exe` (Python 3.11.15, cbor2 **6.1.4**), reconstructed the §4.2.1 and §4.2.3 orderings independently, and checked the recorded verification steps verbatim. No repo files were edited; scratch script at `R:\audit\audit_fnd0013.py`.

---

## 1. VERDICT

**CORRECTION NEEDED. The finding is false as written, and its supporting verification artifacts are falsified.** It is *not* merely misworded.

The operator's high-value suspicion is correct and worse than hypothesized. `fnd-2026-0013` was **promoted on the basis of a step that cannot reproduce.** Running `vrf-2026-0015` step 4 — its own literal command — today returns `DIVERGE`, not the recorded `MATCH`.

The finding's headline claim is byte-exactly true of the *stored* `matrix.tsv` and of the *stored* vectors, so no individual "cell" in the table is arithmetically false. But the claim is an artifact of a stale, never-regenerated vector corpus: **the finding is currently contradicted by the repository's own oracle.** Under the code as committed at HEAD, cbor2 agrees with the Frontier oracle on **108/111** vectors, not 111/111. The three exceptions are the only vectors that discriminate §4.2.1 from §4.2.3.

---

## 2. The §4.2.1-vs-§4.2.3 resolution

This resolves as a **combination of (b) and (c)**, with (a) only narrowly defensible.

### 2.1 Which oracle function and which flag were actually used

| Role | Function / flag | RFC 8949 section it implements |
|---|---|---|
| Runner, canonical rows | `oracle_canonical_hex` → `encode_canonical()` | §4.2.1 — **bytewise lexicographic** |
| Runner, default rows | `oracle_deterministic_hex` → `encode_deterministic()` | §4.2.3 — **length-first** |
| cbor2 adapter, canonical | `cbor2.dumps(obj, canonical=True)` | §4.2.3 in fact |
| ciborium adapter, canonical | `CanonicalValue` sort, `into_writer` | §4.2.3 (docstring cites 4.2.3) |

`runner/run_matrix.py:149`: `expected = oracle_can_hex if mode == "canonical" else oracle_det_hex`. So the paper trail says "canonical ⇒ §4.2.1". `lib_cbor2_adapter.py:117` passes `canonical=True`, which is §4.2.3. **These disagree** — which is exactly the operator's measurement.

### 2.2 The decisive probe — operator's claim CONFIRMED

`{1000: b"x", "z": b"y"}`:

```
§4.2.3 length-first (encode_deterministic) : a2617a41791903e84178
§4.2.1 bytewise-lex (independent build)    : a21903e84178617a4179
Frontier oracle encode_canonical()         : a21903e84178617a4179
cbor2.dumps(canonical=True)                : a2617a41791903e84178
cbor2.dumps(default)                       : a21903e84178617a4179
```

The operator's hex strings reproduce exactly. **VERIFIED.** Note the corollary the finding does not draw: for this map, **cbor2's *default* mode is the §4.2.1-conformant one and cbor2's *canonical* mode is not** — cbor2 sorts by insertion order by default, and insertion order here happened to be §4.2.1 order.

### 2.3 The finding does NOT claim §4.2.1 for cbor2 (kills (b), narrowly)

The finding is *honest* at the sentence level. `fnd-2026-0013` lines 66–72 say plainly: "All three canonical-mode implementations implement RFC 8949 §4.2.3 length-first map key ordering." And `imp-2026-0018` (line 58) says ciborium "aligns with RFC 8949 §4.2.3 … rather than §4.2.1". So **the finding does not falsely assert §4.2.1 conformance for cbor2.** The operator's option (b) does not apply to the prose.

### 2.4 But the ORACLE is mislabelled, and the finding inherits the error — this is the real defect

The oracle's header comment is false:

```
# Two output modes:
#  - encode_deterministic: RFC 8949 §4.2 (deterministic, ...)
#  - encode_canonical: RFC 8949 §4.2.1 (canonical, strictly enforced)
```

`encode_canonical` sorts `key=lambda x: x[0]` (line 279) — bytewise lex, §4.2.1. Fine.

**But until commit `8148462` (2026-09-02), `encode_canonical` sorted `key=lambda x: (len(x[0]), x[0])`** — length-first, §4.2.3 — under a docstring claiming §4.2.1. That is a mislabelled §4.2.3 implementation wearing a §4.2.1 name.

The entire evidence chain was built against that mislabelled state:

- `rpr-2026-0014` (2026-08-31 21:30Z) — oracle still §4.2.3-under-§4.2.1-name
- `vrf-2026-0015` (2026-08-31 22:30Z) — oracle still mislabelled
- `9ae9caa`/`c4b58d5` promotion commit — 2026-08-31 22:39Z; `git show c4b58d5:.../cbor_oracle.py` contains `encoded_keys.sort(key=lambda x: (len(x[0]), x[0]))`
- `8148462` "oracle & instrument repair" — 2026-09-02 03:51, two days *after* promotion; split the sorts; did **not** regenerate the vectors

`fnd-2026-0013.yaml` has `updated_at: "2026-08-31T23:00:00Z"` and has never been touched since (`git log` shows only 9927955 → 793eedb → c4b58d5/9ae9caa). **The finding predates the oracle repair and silently rotted.**

### 2.5 Yes — the test is BLIND, and it is near-blind (c)

The stored vectors were generated when both oracle modes were length-first, so:

```
vectors where oracle_canonical_hex == oracle_deterministic_hex : 111/111
vectors where they DIFFER                                       : 0
```

**All 111 vectors have `oracle_canonical_hex` byte-identical to `oracle_deterministic_hex`.** The canonical and default columns are the *same expected values* for the entire corpus. 108 of 111 vectors additionally have **all map keys of identical encoded length**, so §4.2.1 and §4.2.3 provably coincide. Only **3 vectors discriminate** the two orderings:

- `map_key_sort/map_mixed_lengths` (19 mixed-length keys)
- `map_key_sort/map_rfc_4_2_3_example` (8 mixed-length keys)
- `map_key_sort/map_mixed_types` (6 mixed-length keys)

**Three of 111 vectors (2.7%) carry the entire discriminating power of the axis the finding is named for.** The finding's title asserts "§4.2 cross-impl conformance"; in reality the corpus tests the non-discriminating axes (integer/float/tag/simple-value shortest-form — 95 of 111 vectors) well, and tests map-key ordering on a 3-vector sample.

### 2.6 Classification of the resolution

**Not (a)** — "true-but-misworded" is too generous. **Not (b)** — the prose doesn't claim §4.2.1. It is **(c) plus a labelling defect**: the claim is *true of a stale artifact*, **false of the committed code**, and the test is **blind** on 97.3% of vectors. The honest verdict is **"true-but-misworded against a stale oracle; false against HEAD; blind test."**

---

## 3. Other defects

### 3.1 CRITICAL — vrf-2026-0015 recorded "PASS" for a step that returns DIVERGE

Running the artifact's literal commands:

| Step | Recorded `actual` | Actually produces |
|---|---|---|
| 2 — `encode_canonical(m).hex()` | `a80a012001f401186401617a018120016261610181186401` | `a80a011864012001617a016261610181186401812001f401` |
| 4 — oracle vs cbor2, §4.2.3 example | `MATCH` | **`DIVERGE`** |
| 5 — oracle vs ciborium | `MATCH` | not reproducible — driver gone (see 3.3) |

Both cited hexes *are* valid CBOR and *do* decode correctly (verified with the repo's own `decode()`), so the spot-checks look plausible to a casual reader — but step 2's recorded output is the length-first ordering presented as `encode_canonical`'s output, and step 4's `MATCH` is false against today's oracle.

**The steps were passed against the mislabelled oracle.** They are not merely stale; they are wrong as recorded, and they were the load-bearing evidence for the `verified_conclusion` promotion.

### 3.2 The stored matrix is stale relative to HEAD — confirmed by divergence

`matrix.tsv` rows whose `expected_hex` disagrees with a **fresh** oracle run:

```
map_key_sort/map_mixed_lengths        canonical  (matrix ≠ fresh oracle)
map_key_sort/map_rfc_4_2_3_example    canonical  (matrix ≠ fresh oracle)
map_key_sort/map_mixed_types          canonical  (matrix ≠ fresh oracle)
```

6 rows total (each vector appears in both modes). The matrix was **never re-run after the oracle repair**, and `rpr-2026-0014` step 8's "byte-identical on re-run" claim is therefore untested against HEAD.

### 3.3 The ciborium leg cannot be reproduced at all

```
R:\cbor-cohort                          -> does not exist
R:\cbor-cohort\ciborium\...\cbor-driver.exe -> missing
R:\cbor-cohort\cbor-x\node_modules     -> missing
```

The adapter returns `None` → `ERROR` when the driver is absent (`_driver_available()`). Per AGENTS.md's hard rule on scratch (ramdisk contents are disposable), these were correctly deleted — but the consequence is that **101 of the 222 canonical-mode cells in `matrix.tsv` are unreproducible**, and the `imp-2026-0018` / `rev-2026-0015` citations to `R:/cbor-cohort/ciborium/src/main.rs` are dead pointers. The Rust driver source is not committed anywhere in the repo, so the ciborium canonical result **cannot currently be independently re-derived or even audited** — the sort logic was hand-written by the audit's own agent, in code that no longer exists.

### 3.4 "Independently" is not supported — three independent ways

**(a) Non-independence of the modes.** The canonical column and the default column share one set of expected values (2.5 above). A single artifact establishes both halves of "222/222".

**(b) The finding's own dedup.** The finding states the agreement holds "across 3 independent lineages (Python, Rust, Python cleanroom)". **Two of the three are Python.** The finding's summary does list the languages correctly, but the `statement` block's parenthetical "(Python, Rust, Python cleanroom)" invites reading this as 3-way language diversity. It is 2 languages, 3 implementations.

**(c) The repo's own standard is not applied to itself.** `fnd-2026-0012` established the criterion the operator invoked: byte-exact agreement where the test vectors and the implementation share provenance is *"not independent … self-consistency"*. Here the expected values are the Frontier oracle's **own output** on its **own vectors**. cbor2 matching them is agreement with the oracle, which is the claim — that part is legitimate. But the §4.2.3 example vector is *also* the single vector cited by `vrf-2026-0015` step 6, and by cbor.me: the same hex appears as oracle evidence, as cbor2 evidence, as ciborium evidence, **and** as the external-oracle evidence. One 8-key byte string underwrites all four legs.

**(d) cbor.me: CITED, not RUN.** The finding lists two `https://cbor.me/?bytes=...` URLs under `provenance.sources`; there is no captured output, no timestamp, no hash, and no committed artifact. `vrf-2026-0015` steps 6–7 record them as executed PASS, but nothing in the repo substantiates execution. **COULD-NOT-DETERMINE** whether they were ever actually fetched. Independently: a decoder diagnostic returning "decodes fine" **cannot confirm key ordering**, because decoding is order-independent — the strongest available evidence for the §4.2.1-vs-§4.2.3 question is structurally incapable of settling it. Even the recorded claim is weaker than it reads: the cited URL's hex is the **§4.2.3** ordering, and the finding presents it as validating the **§4.2.1** mode.

### 3.5 Version pinning

- **cbor2 6.1.4** — installed is 6.1.4; PyPI latest is **6.1.5**. The pin is accurate as a pin, one minor behind latest. Not a defect, but `cross_version_tested: false` means nothing is known about 6.1.5.
- **ciborium 0.2.2** — still latest (docs.rs confirms 0.2.2 as current). Pin correct.
- **cbor-x 1.6.6** — cannot re-check; `node_modules` deleted, and cbor-x is default-mode-only so it does not bear on the canonical claim.
- Adapter header `lib_cbor2_adapter.py:33` hardcodes `LIB_VERSION = "6.1.4"` as a literal with no runtime assertion. Verified against installed metadata, so correct today, but it is an unverified constant.

### 3.6 Spec defects that propagate into the finding

`spc-2026-0004.yaml` has **fabricated RFC quotations** presented as normative:

- Lines 78–83 attribute to §4.2.1: *"The canonical encoding is a particular deterministic encoding defined by the following rules. The encoding is well-formed and valid CBOR, but not all well-formed CBOR data has a valid canonical encoding."* — I searched the full RFC 8949 text; **this text does not exist in RFC 8949.** It is RFC 7049's §3.9 material (or invented).
- Line 85–96: "§4.2.1 adds … §4.2.1 §1 explicitly says 'indefinite-length items MUST be made into definite-length items.'" §4.2.1 has no numbered rules; those clauses are §4.2.1 bullets.
- Line 125 rule_ref for `map_key_sort` reads `"RFC 8949 §4.2 rule 2, §4.2.1 rule 2"`, and line 126 defines that axis as *"Sort map keys first by encoded byte length (shorter first), then lexicographically"* — i.e. **the spec defines its own `map_key_sort` audit axis as §4.2.3**, while the finding and its summary claim §4.2 cross-impl conformance. `rev-2026-0015` ATTACK 5 already flagged "§4.2.1 rule numbering is non-canonical" but only asked for a citation fix, not for the substance of the axis definition to be reconciled.
- The spec still cites `#appendix-C` as a source for the 14 integer vectors; `rev-2026-0015` rec 3 correctly notes these are Appendix A Table 6. Note the oracle's own constant is named `RFC_8949_APPENDIX_C_VECTORS` and its docstring says "Source: RFC 8949 Appendix C" — the error is still in the code.

### 3.7 Divergence cells the finding glosses over

I enumerated all 54 non-MATCH rows in `matrix.tsv`. The finding's "52 cells" figure is off by 2 and its arithmetic doesn't close:

- Finding: cbor2 default 14 + 4; ciborium default 4; cbor-x 20 + 5 + 5 + 2 → **52**
- Matrix actual: cbor2 14+4; ciborium **4**; cbor-x 20+5+5+2 → **54**

I could not reconstruct a grouping that yields 52; the finding's list sums to 52 by its own arithmetic while the artifact shows 54. Unreconciled.

Substantively, the gloss is in the right direction (all are documented per-library behavior, not bugs) but understates two classes:

- `lib_cbor2 default` → `map_key_sort/map_rfc_4_2_3_example` = SPEC_VIOLATION. In default mode cbor2 emits insertion order; here that happened to equal §4.2.1 order. **Default-mode behaviour is order-of-insertion-dependent and therefore not reproducible from the encoded output** — so the "4 SPEC_VIOLATION (map_key_sort, insertion order)" line, while true, hides that this is the *same axis* whose canonical-mode result is the finding's headline.
- The `duplicate_key_rejection` axis is **inert**. `gen_duplicate_key_vectors` admits this in a code comment: it feeds `{"a": 1, "a": 2}`, which Python deduplicates to `{"a": 2}` before the oracle ever sees it. Both vectors therefore PASS trivially for every library. **The finding counts 2 of its 111 vectors, and 1 of its 8 axes, toward "8 audit axes" without ever testing duplicate-key rejection.** Nothing in the cohort can emit a duplicate key through the adapter interface — Python `dict` forbids it, and the cbor2 adapter never constructs one. This is the one axis where a real §4.2.1-vs-§4.2.3 difference could have surfaced and it is structurally untestable here.

---

## 4. Safe-to-disclose, or correction needed?

**CORRECTION NEEDED. Do not disclose in the current form.** `disclosure: public` with `disclosure_channels` naming "CBOR-WG interop matrix entry" and the cbor2 / ciborium issue trackers makes this actively harmful right now: the finding tells two upstream maintainers that their libraries "independently produce byte-exact identical canonical-mode output to the Frontier cleanroom oracle," when the repo's own committed oracle contradicts that on the one axis where they disagree.

### Required corrections before any disclosure

1. **Fix the stale oracle/vector mismatch.** Regenerate `vectors_map_key_sort.jsonl` (or all vectors) against the repaired oracle at HEAD, re-run the matrix, and record the real numbers. Under HEAD the canonical result is **cbor2 108/111**, not 111/111.
2. **Rewrite the summary and title to name the ordering explicitly.** Replace bare "canonical-mode" with "§4.2.3 length-first ordering (RFC 7049 §3.9 canonical, 'old canonical' in RFC 8949)". Keep the existing §4.2.3 sentence — that part was always correct. Stop calling the mode "canonical" while the oracle function carrying that name is a distinct, differently-sorted function.
3. **Correct the oracle's header comment** to state that `encode_canonical` = §4.2.1 and `encode_deterministic` = §4.2.3, and note that `encode_deterministic` *also* emits §4.2.1-conformant output on every non-discriminating vector.
4. **Correct or withdraw vrf-2026-0015 steps 2, 4, 5.** As recorded they assert matches that do not reproduce. Step 4 in particular must be re-run and will return DIVERGE.
5. **Re-baseline the evidence chain.** Every artifact in the chain (obs-2026-0041, rev-2026-0015, vrf-2026-0015, rpr-2026-0014) was produced against the pre-repair oracle. Per AGENTS.md, a finding whose evidence chain predates a change to its own oracle cannot retain `verified_conclusion` without re-verification.
6. **Commit the Rust ciborium driver source** (or the pinned `Cargo.lock` + driver) outside the disposable ramdisk, or mark the ciborium leg explicitly unverifiable. 101 of 222 canonical cells currently rest on code that no longer exists.
7. **Fix `spc-2026-0004`'s fabricated §4.2.1 quotations** and reconcile the `map_key_sort` axis definition, which currently specifies §4.2.3 while the finding claims §4.2 conformance.
8. **Either exercise or drop the `duplicate_key_rejection` axis**, and stop counting it among the "8 audit axes" that support the claim.
9. **Soften or evidence the "independently" / "strongest possible evidence" language.** The cohort is 2 languages across 3 implementations; 108/111 vectors cannot discriminate the two orderings; the cbor.me URLs are citations without captured output and cannot test ordering in principle.
10. **Reconcile the 52-vs-54 divergence-cell count** with the artifact.

### What survives

The narrow, defensible claim is: *for integer, float, tag, simple-value and definite-length shortest-form encoding, cbor2 6.1.4's `canonical=True` and the Frontier oracle produce byte-identical output on all 95 non-map vectors, and on 108/111 vectors overall; on the 3 vectors that discriminate §4.2.1 from §4.2.3, cbor2 matches the oracle's §4.2.3 length-first ordering and diverges from the oracle's §4.2.1 bytewise-lex ordering.* That is a real, useful, correctly-scoped interop result. It is not what the artifact currently says, and it does not support "222/222, 100%, strongest possible evidence short of formal verification."

### Note on the prior adversarial review

`rev-2026-0015` (the review that authorised this promotion) got the *right answer for the wrong reason*. Its ATTACK 5 correctly identified that §4.2.1 is bytewise-lex and that the cohort uses length-first, then dismissed the conflict with a correct verbatim RFC quote but an inverted conclusion: it wrote that §4.2.3 is length-first and called this "a documentation/interpretation choice, not a bug," concluding "§4.2.3 length-first is one of two normative canonical modes." It never ran `encode_canonical` against cbor2 on a discriminating vector — which would have exposed both the stale-oracle problem and the later falsified steps. The methodological gap flagged in (c) survived the review process intact.
