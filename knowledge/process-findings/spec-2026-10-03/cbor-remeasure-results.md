<!-- Preserved from .scratch/ (gitignored, not durable).
     Supports knowledge/reports/rpt-2026-0017.yaml.
     Original filename: rework_cbor_remeasure.md -->

# Re-measurement of fnd-2026-0013 — Phase 1 diagnosis + Phase 2 measurement

**Role:** experiment-designer + verifier
**Date:** 2026-10-03
**Scope:** Frontier oracle (`cbor_oracle.py`) + cbor2 only. ciborium / cbor-x cohorts NOT run
(out of scope per task; `R:\cbor-cohort` no longer exists).
**Environment:** `C:\Users\Dhane\frontier\.venv\Scripts\python.exe`, CPython 3.11.15, cbor2 **6.1.4**
(dist metadata; module has no `__version__` attribute).
**Scratch scripts:** `R:\remeasure\phase1_diagnose.py`, `phase2_measure.py`, `selfcheck.py`,
`final_table.py`, `cose_regen_inmemory.py`.
**Read-only guarantee:** no file under `knowledge/`, `missions/`, `src/`, `cbor-cross-impl/vectors/`,
or `cbor-cross-impl/results/` was modified. No commit. No regeneration written to disk — the
COSE regeneration check was done in memory only.

---

## 1. Phase 1 — diagnosis

### 1.1 The mislabelled-oracle story: CONFIRMED

The audit's central claim holds. Two independent lines of evidence:

**(a) The diff of the repair commit.** `git show 8148462 -- cbor-cross-impl/oracle/cbor_oracle.py`
shows the single-line sort being split:

```diff
-        # Sort keys by encoded length then lexicographically (RFC 8949 §4.2 rule 2)
...
-        encoded_keys.sort(key=lambda x: (len(x[0]), x[0]))
+        if canonical:
+            # §4.2.1: bytewise lex on encoded form (regardless of length)
+            encoded_keys.sort(key=lambda x: x[0])
+        else:
+            # §4.2.3: shorter byte length first, then bytewise lex
+            encoded_keys.sort(key=lambda x: (len(x[0]), x[0]))
```

Before `8148462` (2026-09-02 03:51:37 +0400), **both** branches of `_encode_deterministic_value`
used the length-first key `(len(x[0]), x[0])`. The `canonical` flag existed but only controlled
duplicate-key rejection, never the sort.

**(b) Direct inspection of the pre-repair blob.** `git show c4b58d5:cbor-cross-impl/oracle/cbor_oracle.py`
(the promotion commit, 2026-08-31 22:39:26 +0400 — two days earlier) contains:

```python
        # Sort keys by encoded length then lexicographically (RFC 8949 §4.2 rule 2)
        ...
        # Sort: shorter byte length first, then lexicographically on bytes
        # (RFC 8949 §4.2.3 length-first ordering)
        encoded_keys.sort(key=lambda x: (len(x[0]), x[0]))
```

while the module header at that same blob still advertised:

```
Two output modes:
  - encode_deterministic: RFC 8949 §4.2 (deterministic, ...)
  - encode_canonical: RFC 8949 §4.2.1 (canonical, strictly enforced)
```

So `encode_canonical` genuinely was a §4.2.3 implementation carrying a §4.2.1 name, and the
entire evidence chain (promotion `c4b58d5`, 2026-08-31 22:39Z) was built against it. **The
audit is right and I could not break this story.**

**Timing confirmed.** Vectors were last touched by `793eedb` / `86ae0b7` (2026-08-31 01:58:28),
i.e. before the promotion and before the repair. `git log -- cbor-cross-impl/vectors/` shows
exactly two commits, both from msn-2026-0016; the repair `8148462` touched **zero** CBOR vector
files. The corpus rotted silently.

**Mechanism of the rot, confirmed by reading `gen_vectors.py`.** The generator does
`from cbor_oracle import encode_deterministic, encode_canonical` and calls them at generation
time to populate the two `oracle_*_hex` columns. Because the two functions were byte-identical
for map sorting at that moment, both columns received the same length-first string. Regenerating
is a pure re-run of the generator — no schema change needed.

### 1.2 Discriminating vectors: 3, exactly as predicted

Running both oracle functions over every vector's maps at HEAD:

```
STORED oracle_canonical_hex == oracle_deterministic_hex : 111/111   (0 differ)
LIVE HEAD encode_canonical == encode_deterministic      : 108/111   (3 differ)
```

The three discriminating vectors, all in the `map_key_sort` axis:

| vector_id | keys | mixed encoded key lengths |
|---|---|---|
| `map_mixed_lengths` | 19 | yes (0,1,5,10,23,100,200,-1,-10,-100, "a","b","aa","ab","ba","abc","abd","xyz","aaa") |
| `map_rfc_4_2_3_example` | 8 | yes (100, 10, -1, false, (100,), (-1,), "z", "aa") |
| `map_mixed_types` | 6 | yes ("aa", -1, 10, "z", 100, false) |

Full corpus map census at HEAD:

| axis | vector_id | #maps | mixed-len keys | §4.2.1 ≠ §4.2.3 | stored canonical == fresh §4.2.1 |
|---|---|---|---|---|---|
| definite_length_preferred | map_empty | 1 | 0 | no | yes |
| definite_length_preferred | map_1pair | 1 | 0 | no | yes |
| duplicate_key_rejection | map_int1_vs_str1_not_duplicate | 1 | 1 (len1 `01`, len2 `6131`) | **no** | yes |
| duplicate_key_rejection | map_duplicate_test_inert | 1 | 0 | no | yes |
| map_key_sort | map_mixed_lengths | 1 | yes | **YES** | **no** |
| map_key_sort | map_rfc_4_2_3_example | 1 | yes | **YES** | **no** |
| map_key_sort | map_same_length_lex | 1 | 0 | no | yes |
| map_key_sort | map_boundary_lengths_1_2_3 | 1 | 1 (len1 `00`, len2 `1864`, len3 `626161`) | **no** | yes |
| map_key_sort | map_mixed_types | 1 | yes | **YES** | **no** |

### 1.3 Adversarial correction to the audit — I found a wrong number in it

The audit (§2.5) states: *"108 of 111 vectors additionally have **all map keys of identical
encoded length**, so §4.2.1 and §4.2.3 provably coincide."*

**That statement is false as written.** The measured figures are:

- vectors containing **no map anywhere**: **102**
- vectors containing **at least one map**: **9**
- vectors where §4.2.1 and §4.2.3 **provably coincide** (all map keys equal encoded length): **108**

Only **2** of the 111 vectors have "all map keys of identical encoded length." **Six** vectors have
mixed-length map keys but still do not discriminate, because for *those specific* key sets the two
orderings happen to produce the identical permutation:

- `map_boundary_lengths_1_2_3` — keys encode to `00`(len1), `1864`(len2), `626161`(len3). Bytewise-lex
  orders `00 < 1864 < 626161`; length-first orders `00 < 1864 < 626161`. **Identical permutation.**
  (This vector's *description* literally says "keys at length boundaries 1/2/3 bytes" — it was
  intended as a discriminator and fails to be one. It is the most misleading vector in the corpus.)
- `map_int1_vs_str1_not_duplicate` — `01`(len1) < `6131`(len2) under both.
- `map_empty`, `map_1pair`, `map_duplicate_test_inert`, `map_same_length_lex` — trivially single-key
  or all-equal-length.

The operative conclusion is **unchanged and, if anything, strengthened**: 108/111 vectors cannot
discriminate, 3 can. The *reason* is "the two orderings yield the same permutation on this key set,"
not "the keys have equal length." The corrected reason matters because it identifies
`map_boundary_lengths_1_2_3` as a **latent test-design defect** — it is a boundary-case vector
that silently tests nothing.

The audit is also off by one in a different place. Its replacement claim (§"What survives") says
*"all 95 non-map vectors."* Measured: **102** non-map vectors. 95 does not correspond to any
natural partition of this corpus:

| partition | size |
|---|---|
| total | 111 |
| vectors containing a map | 9 |
| vectors containing **no** map | **102** |
| vectors **not** in the `map_key_sort` axis | 106 |
| integer + float + tag + simple + chunked axes | 98 |
| `map_key_sort` axis | 5 |
| `definite_length_preferred` + `duplicate_key_rejection` + `map_key_sort` | 13 |

Nothing yields 95. The `95` appears to be unsourced and should not be propagated into the
replacement claim.

---

## 2. Phase 2 — measurement

Method: for each vector, encode the data item through the **repo's own adapter path**
(`lib_cbor2_adapter.encode`) — so the measurement exercises the identical materialization the
matrix runner used — and cross-check every result against a direct `cbor2.dumps()` call bypassing
the adapter. All 222 adapter outputs equalled their direct counterparts (asserted in
`phase2_measure.py`, no assertion fired). Oracle outputs come from the live HEAD
`encode_canonical` / `encode_deterministic`.

### 2.1 Headline numbers (all 111 vectors, cbor2 `canonical=True`)

| comparison | result |
|---|---|
| `cbor2.dumps(m, canonical=True)` == `encode_canonical(m)` — **RFC 8949 §4.2.1** bytewise-lex | **108 / 111** |
| `cbor2.dumps(m, canonical=True)` == `encode_deterministic(m)` — **RFC 8949 §4.2.3** length-first | **111 / 111** |
| `cbor2.dumps(m, canonical=True)` == **stored** `oracle_canonical_hex` (the finding's assertion) | 111 / 111 |

Per-axis:

| axis | n | == §4.2.1 | == §4.2.3 |
|---|---|---|---|
| chunked_string_consistency | 3 | 3 | 3 |
| definite_length_preferred | 6 | 6 | 6 |
| duplicate_key_rejection | 2 | 2 | 2 |
| float_shortest_form | 19 | 19 | 19 |
| integer_shortest_form | 52 | 52 | 52 |
| **map_key_sort** | 5 | **2** | 5 |
| simple_value_shortest_form | 4 | 4 | 4 |
| tag_shortest_form | 20 | 20 | 20 |
| **TOTAL** | **111** | **108** | **111** |

Subset splits:

| subset | n | == §4.2.1 | == §4.2.3 |
|---|---|---|---|
| vectors containing **no** map | 102 | 102 / 102 | 102 / 102 |
| vectors containing ≥ 1 map | 9 | 6 / 9 | 9 / 9 |
| **discriminating** (§4.2.1 ≠ §4.2.3) | 3 | **0 / 3** | **3 / 3** |
| **non-discriminating** | 108 | 108 / 108 | 108 / 108 |

The `0/3` and `108/108` cells are the key result: cbor2 agrees with **exactly one** of the two
orderings on every single vector. It never mixes, never approximates.

### 2.2 The three discriminating vectors, in full

**`map_key_sort/map_rfc_4_2_3_example`** (keys `{100, "z", "aa", 10, -1, false, (100,), (-1,)}`)

```
§4.2.1  encode_canonical      a80a011864012001617a016261610181186401812001f401
§4.2.3  encode_deterministic  a80a012001f401186401617a018120016261610181186401
cbor2    canonical=True        a80a012001f401186401617a018120016261610181186401   -> §4.2.3
cbor2    default (insertion)   a8186401617a01626161010a012001f40181186401812001   -> neither
stored   oracle_canonical_hex  a80a012001f401186401617a018120016261610181186401   -> §4.2.3
```

**`map_key_sort/map_mixed_types`** (keys `{"aa":1, -1:2, 10:3, "z":4, 100:5, false:6}`)

```
§4.2.1  encode_canonical      a60a031864052002617a0462616101f406
§4.2.3  encode_deterministic  a60a032002f406186405617a0462616101
cbor2    canonical=True        a60a032002f406186405617a0462616101                  -> §4.2.3
cbor2    default (insertion)   a66261610120020a03617a04186405f406                  -> neither
stored   oracle_canonical_hex  a60a032002f406186405617a0462616101                  -> §4.2.3
```

**`map_key_sort/map_mixed_lengths`** (19 mixed-length keys)

```
§4.2.1  encode_canonical      b30001010105010a01170118640118c801200129013863016161016162016261610162616201626261016361616101636162630163616264016378797a01
§4.2.3  encode_deterministic  b30001010105010a0117012001290118640118c8013863016161016162016261610162616201626261016361616101636162630163616264016378797a01
cbor2    canonical=True        b30001010105010a0117012001290118640118c8013863016161016162016261610162616201626261016361616101636162630163616264016378797a01   -> §4.2.3
cbor2    default (insertion)   b30001010105010a01170118640118c80161610161620162616101626162016262610120012901386301636162630163616264016378797a016361616101   -> neither
stored   oracle_canonical_hex  b30001010105010a0117012001290118640118c8013863016161016162016261610162616201626261016361616101636162630163616264016378797a01   -> §4.2.3
```

**Storing the length-first ordering under the name `oracle_canonical_hex` is confirmed for all
three** — the stored column equals `encode_deterministic`, not `encode_canonical`.

### 2.3 Default-mode (the corollary the audit noted)

`cbor2.dumps(m)` matches **neither** ordering on the 3 discriminating vectors, because insertion
order is a third, unrelated permutation. It matches §4.2.1 or §4.2.3 on only 5/9 map vectors.
Whole-corpus: default agrees with stored `oracle_deterministic_hex` on **93/111** — which exactly
reproduces the committed `matrix.jsonl` (`lib_cbor2` default PASS = 93, with 14 SPEC_AMBIGUITY +
4 SPEC_VIOLATION). My independent re-measurement agrees with the committed artifact cell-for-cell
on default mode.

---

## 3. The §4.2.1-vs-§4.2.3 verdict for cbor2 — one sentence

**cbor2 6.1.4's `canonical=True` implements RFC 8949 §4.2.3 length-first map key ordering and not
§4.2.1 bytewise-lexicographic ordering — it agrees with the oracle's §4.2.3 output on 111/111
vectors and with the oracle's §4.2.1 output on 108/111, diverging on precisely the 3 vectors where
the two orderings are distinguishable.**

This is a **false alarm, not a bug report.** §4.2.3 length-first is the deterministic mode required
by RFC 7049 §3.9 (the predecessor "canonical" mode, retained as §4.2.3 in RFC 8949 and used by
RFC 9052 §4 / the COSE core deterministic profile). cbor2's own documentation states that
`canonical=True` targets RFC 7049 §3.9 / RFC 8949 §4.2 deterministic encoding. What cbor2 does not
do — and this is not a defect — is implement the *stricter* §4.2.1 core deterministic profile that
RFC 9052 §9 mandates for COSE. Calling that a conformance bug would require the operator to
believe COSE requires §4.2.1 ordering for arbitrary third-party CBOR producers, which no RFC
asserts.

The defect is 100% in Frontier: a function named for §4.2.1 that computed §4.2.3, plus a corpus
generated against it and never regenerated.

---

## 4. Is the audit's replacement claim accurate?

**Substantially yes, with two corrections.**

| audit's replacement claim | measured | verdict |
|---|---|---|
| "cbor2 matches the oracle on 108/111" | 108/111 vs live `encode_canonical` | ✅ **CONFIRMED** |
| "matches the oracle's §4.2.3 ordering on the 3 that discriminate" | 3/3 | ✅ **CONFIRMED** |
| "fails exactly the 3 discriminating vectors" | `map_mixed_lengths`, `map_rfc_4_2_3_example`, `map_mixed_types` | ✅ **CONFIRMED** |
| "matches on all 95 non-map vectors" | **102** non-map vectors | ❌ **WRONG COUNT** — use 102 |
| (implicit) "108/111 have all-equal-length map keys" | only **2/111** do; 108 coincide because the permutations match | ❌ **WRONG REASON** |

The replacement claim is therefore **directionally correct and numerically confirmed on its load-bearing
number (108/111)**. Both supporting figures should be restated: *108/111*, and the non-map subset is
**102/111**, not 95/111.

### Additional findings not in the audit

**(a) The divergence-cell count is resolved, and the audit's own objection is what is wrong.**
The audit (§3.7) wrote that the finding's breakdown *"sums to 52 by its own arithmetic while the
artifact shows 54"* and that no grouping yielding 52 could be reconstructed. Measured from
`matrix.jsonl` (555 cells: cbor2 222, ciborium 222, cbor-x 111):

```
lib_cbor2   default  SPEC_AMBIGUITY 14  + SPEC_VIOLATION 4  = 18
lib_ciborium default SPEC_VIOLATION  4                       = 4
lib_cbor_x  default  SPEC_AMBIGUITY 20 + INTEROP_BREAK 5 + SPEC_VIOLATION 5 + ERROR 2 = 32
                                                               total = 54
```

The finding's **enumerated per-library numbers sum to 54 and match the artifact exactly.** Only the
bare summary token "52" is wrong; the detailed breakdown in the same finding is correct and
self-consistent. The audit inverted this — it is the audit's "sums to 52 by its own arithmetic"
claim that fails.

**(b) The COSE corpus is NOT stale — a control the audit never ran.** `cose-cross-impl` imports
`encode_canonical` and binds it as `_ENCODE` (`cose_oracle.py:57`), so it is exposed to the same
repair. I regenerated **all 10 cose generator functions in memory** (never written to disk) and
compared every `oracle_structure_hex` / `oracle_message_hex` field against the committed
`.jsonl`: **80 fields identical, 0 different.** The cose vectors were regenerated *inside the same
commit* `8148462` that repaired the oracle. This is the decisive control: the stale-vector rot is
confined to `cbor-cross-impl`, and it is not a systemic property of the repo. Any corrected story
should say so.

**(c) The COSE corpus is nonetheless mostly non-discriminating too.** Its
`header_label_sorting` axis has 4 vectors and **none** discriminates:

| cose vector | keys | §4.2.1 == §4.2.3? |
|---|---|---|
| `int_labels_sorted` | 4, 3 | yes |
| `int_labels_reverse_insertion` | 4, 3 | yes |
| `mixed_int_tstr_labels` | ctyp, kid | yes |
| `tstr_lex_sort` | a, aa, b, ab, z | yes |

For text-string keys both orderings coincide because the major-type-3 header byte is constant (`0x6x`)
and the first content byte dominates the comparison; for small int keys the headers coincide too.
So the COSE axis named `header_label_sorting` also has **zero** discriminating power at HEAD. If a
future mission claims to have re-verified COSE ordering, it has measured nothing on that axis.

**(d) `vrf-2026-0015` step 2 confirmed falsified.** Recorded `actual` for
`encode_canonical(m).hex()` on `map_rfc_4_2_3_example`:
`a80a012001f401186401617a018120016261610181186401`. Measured at HEAD:
`a80a011864012001617a016261610181186401812001f401`. The recorded string is byte-identical to
`encode_deterministic`. Independently reproduces the audit.

---

## 5. What I could NOT determine, and why

1. **The ciborium leg — completely unmeasured.** Out of scope by instruction and in any case
   unreproducible: `R:\cbor-cohort` does not exist, the Rust driver source was never committed, and
   the adapter returns `None` → `ERROR` when the driver is absent. I did **not** build cbor.me, did
   **not** fetch cbor-x, and did **not** run `run_matrix.py`. **I therefore cannot confirm the audit's
   implied claim that ciborium also uses §4.2.3 length-first.** That claim rests entirely on the
   pre-repair evidence chain and on `imp-2026-0018`'s citation of Rust source that no longer exists
   in this repo. The replacement claim is currently a **2-implementation** claim (Frontier oracle +
   cbor2), not a 3-lineage claim. Calling it a "3-lineage agreement" would reintroduce the exact
   defect that got the finding refuted.

2. **Whether cbor2 6.1.5 (PyPI latest) behaves identically.** Installed is 6.1.4. `cross_version_tested`
   is `false` and the adapter's `LIB_VERSION = "6.1.4"` is an unverified literal. Installing another
   version would have been a new build/environment change beyond a read-only re-measurement.

3. **Whether the 3 discriminating vectors would flip under §4.2.1-conformant regeneration.**
   Regenerating the vectors is a separate decision reserved for the human (per the task's explicit
   constraint). I can state exactly what a regeneration would produce — `oracle_canonical_hex`
   becomes the §4.2.1 string for those 3 vectors, and the canonical column then differs from the
   default column for 3/111 — but I have not produced or committed that file, and I have not
   re-run the full matrix against a regenerated corpus.

4. **The ciborium/cbor-x divergence cells.** `matrix.jsonl` records 36 non-MATCH cells for those two
   adapters (4 + 32). I verified these counts are present in the artifact but could not confirm any
   of them still holds, for the reason in (1).

5. **Whether `spc-2026-0004`'s `map_key_sort` axis definition is a defect or a description.**
   The spec defines the axis as §4.2.3 (per the audit) while `fnd-2026-0013` claims "§4.2
   conformance." I did not re-verify the audit's claim that `spc-2026-0004` contains fabricated
   RFC quotations — that requires an independent search of the RFC 8949 text, which is a
   spec-audit task, not a measurement task, and is outside this mission's scope.

6. **cbor.me was not contacted.** Its contribution to the original evidence chain remains
   unsubstantiated by anything committed.

---

## 6. Bottom line

The mislabelled-oracle story is **correct and unbreakable** on the evidence available in this
repo. The audit's load-bearing number, **108/111**, is **confirmed by independent measurement**, and
cbor2's `canonical=True` is **§4.2.3 length-first**, matching the oracle's `encode_deterministic`
on **111/111** vectors and its `encode_canonical` on **108/111**.

The audit's replacement claim should be restated with **102** non-map vectors (not 95) and without
the "all map keys of identical encoded length" rationale, which is wrong — only 2/111 vectors have
that property, while 108/111 coincide for a different reason.

A defensible replacement claim now exists, and it is narrower than the original: **a 2-implementation
(oracle + cbor2) agreement on the 95/98 non-map-key-sort axes, with 3 discriminating vectors on which
cbor2 is demonstrably §4.2.3 and the oracle is demonstrably §4.2.1 — a documented specification-choice
divergence between a COSE-oriented oracle profile and a general-purpose library, not a bug in either.**
The ciborium leg remains unmeasured and must not be counted.
