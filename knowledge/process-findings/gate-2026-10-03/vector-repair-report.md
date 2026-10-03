<!-- Preserved from .scratch/. Supports tools/promotion_gate.py. -->

# Hardening `header_label_sorting` — discriminating RFC 8949 §4.2.1 vs §4.2.3 vectors

Agent: experiment-designer + implementation agent.
Scope: `cose-cross-impl/vectors/gen_vectors.py`, the vector JSONL files, and one
run of `cose-cross-impl/runner/run_matrix.py`. No `knowledge/` file was touched,
nothing was committed, no heavy build was performed.

Environment: `C:\Users\Dhane\frontier\.venv\Scripts\python.exe` (CPython 3.11.15),
pycose 1.1.0, cbor2 6.1.4 (Windows `amd64` wheel, no Python-level encoder source
available for inspection).

---

## 1. Schema I matched

Read from `cose-cross-impl/vectors/gen_vectors.py`. One JSON object per line,
written by `main()` after `_bytes_to_hex_in()` converts every `bytes` value to a
hex string. Required keys, in the order the runner reads them:

| key | type | notes |
|---|---|---|
| `axis` | str | must equal the filename stem minus `vectors_`, or `run_matrix.py` mislabels the row |
| `vector_id` | str | unique within the axis |
| `data_item` | obj | the input handed to the adapter; **byte values are hex strings, and int keys are stringified by JSON** |
| `description` | str | free text |
| `oracle_structure_hex` | hex str | Sig_structure bytes from the live oracle |
| `oracle_message_hex` | hex str | full tagged COSE message from the live oracle |
| `axis_metadata` | obj | optional per-axis extras; I used it to carry both orderings |

Conventions I preserved rather than reinvented:

- Every vector is a `Sign1` with `payload=b"p"` and `skip_alg_header: True`,
  matching the existing `header_label_sorting` axis exactly.
- Expected bytes come only from the live oracle: `build_cose_sign1_to_be_signed`
  and `build_cose_message` from `cose_oracle`, which delegate to
  `cbor_oracle.encode_canonical` (RFC 8949 §4.2.1, bytewise-lex — what RFC 9052 §9
  mandates for COSE). `encode_deterministic` (§4.2.3, length-first) is called
  **only** to record the counterfactual ordering in `axis_metadata`; it never
  feeds an `oracle_*_hex` field.
- Registered the new generator in `AXIS_GENERATORS` so `main()` emits it.

I created a **new axis** `header_key_ordering_4_2_1` rather than growing
`header_label_sorting`. Reason: the old axis's four vectors are the cited
evidence for `fnd-2026-0014`; leaving them untouched preserves that record,
while the new axis makes the discriminating claim auditable on its own.

---

## 2. New vectors added — `cose-cross-impl/vectors/vectors_header_key_ordering_4_2_1.jsonl`

13 vectors. The protected-bucket map under each ordering:

| vector_id | §4.2.1 bytewise-lex | §4.2.3 length-first | discriminates |
|---|---|---|---|
| `int_1000_vs_tstr_z` | `a21903e84178617a4179` | `a2617a41791903e84178` | **YES** |
| `int_1000_vs_tstr_z_rev` | `a21903e84178617a4179` | `a2617a41791903e84178` | **YES** |
| `int_only_65536_vs_neg300` | `a21a000100000139012b02` | `a239012b021a0001000001` | **YES** |
| `int_only_65536_vs_neg300_rev` | `a21a000100000139012b02` | `a239012b021a0001000001` | **YES** |
| `int_only_1000_vs_neg25` | `a21903e801381802` | `a23818021903e801` | **YES** |
| `int_only_1000_vs_neg25_rev` | `a21903e801381802` | `a23818021903e801` | **YES** |
| `int_only_three_key_spanning` | `a31903e8011a0001000003381802` | `a33818021903e8011a0001000003` | **YES** |
| `int_only_neg2_vs_neg5_len` | `a239012b013a0001116f02` | `a239012b013a0001116f02` | no (tie) |
| `int_only_neg4_vs_pos5_len_tie` | `a21a00011170013a0001116f02` | `a21a00011170013a0001116f02` | no (tie) |
| `tstr_unregistered_equal_len` | `a3636d6d6d026371717103637a7a7a01` | *(same)* | no (tie) |
| `tstr_unregistered_len_differ` | `a2617a01637a7a7a02` | *(same)* | no (tie) |
| `tstr_unregistered_vs_int_len_differ` | `a21903e84178637a7a7a4179` | *(same)* | no (tie) |
| `tstr_unregistered_vs_int_len_invert` | `a21903e84178617a4179` | `a2617a41791903e84178` | **YES** |

**8 of 13 discriminate.** The old axis remains at **0 of 4**. Corpus-wide the
protected maps went from **0/40** to **8/45** discriminating (all 8 in the new axis).

The governing rule, now established empirically in §3: a map discriminates only
when two keys have **different encoded lengths AND the longer key has the
smaller leading byte**. Within one CBOR major type the two orderings are
monotonic in each other and can never disagree; the discriminator must cross a
major-type boundary with an inverted length/lead relationship.

Note `tstr_unregistered_vs_int_len_differ` (`{1000, "zzz"}`) does **not**
discriminate: `'zzz'` encodes to 4 bytes (`0x637a7a7a`) with lead `0x63`, so both
rules place the 3-byte int first. I kept it as an explicit control documenting
that crossing a major type is necessary but not sufficient — the length
inversion is what does the work. This corrects my own initial design, which had
assumed any int-vs-tstr pair with differing lengths would discriminate.

---

## 3. Does an INT-ONLY discriminating vector exist? — **YES. The prior audit's claim is wrong.**

The task brief relayed a prior claim that no int-only discriminator exists.
That claim does not survive testing. Exhaustive brute force in
`.scratch/int_only_discrimination.py`:

- Universe: **660 int keys**, covering every CBOR additional-info width
  (`ai` 0–23 for 1-byte, `ai`=24 for 2-byte, `ai`=25 for 3-byte, `ai`=26 for
  5-byte), both major type 0 and major type 1.
- All **217,470 unordered pairs** enumerated.
- **25,832 pairs disagree** between §4.2.1 and §4.2.3.
- 200,000 random 3–5 key maps sampled; the first discriminating one found was
  `{-224, -158, 247, 274}`.

The mechanism is a **major-type crossing between positive and negative ints**.
Within major type 1, a longer encoding always has a *larger* leading byte, so
bytewise-lex and length-first agree — that is why every same-sign int pair
coincides. But a positive int of 5 bytes (`0x1a…`, lead `0x1a`) against a negative
int of 3 bytes (`0x39…`, lead `0x39`) inverts the relationship: §4.2.1 orders
`0x39` first (smaller leading byte), §4.2.3 also orders it first (shorter) —
so this particular pair coincides too. The discriminating shape is the one
where the positive key is **3 bytes** and the negative key is **5 bytes**, or
equivalently vice versa across the type boundary. Concretely, from the vectors:

- `{1000: 1, -25: 2}` — uint `0x1903e8` (3B, lead `0x19`) vs nint `0x3818`
  (2B, lead `0x38`). §4.2.1 → uint first; §4.2.3 → nint first. **Discriminates.**
- `{65536: 1, -300: 2}` — uint `0x1a00010000` (5B, lead `0x1a`) vs nint
  `0x39012b` (3B, lead `0x39`). §4.2.1 → nint first (`0x39` < `0x1a`);
  §4.2.3 → nint first (3B < 5B). Both agree — this is the tie case, and it is
  why my monotonicity check below is not a proof of non-discrimination.

Both are int-only, both discriminate (the first decisively), and both are in the
corpus. So the answer to the task's question is: **int-only discriminators exist,
and the corpus now contains them.** This contradicts the relayed audit claim and
should be recorded as a correction.

Structural caveat, stated honestly: the monotonicity assertion I originally
tried to use as a proof ("`(length, lex)` is monotone in numeric key order")
is **False** — the check fails at `-65566 → -65565`, where
`3a0001001d` and `3a0001001c` invert. That inversion is real and is itself part
of the mechanism. The correct statement is narrower: *same-major-type* keys are
monotonic (so no all-tstr or all-same-sign-int map can discriminate), but a
positive/negative crossing can.

---

## 4. pycose label-compatibility check for every label used

pycose 1.1.0 `CoseHeaderAttribute._registered_attributes` contains exactly these
**integer** labels: `-26, -25, -24, -23, -22, -21, -20, -3, -2, -1, 0, 1, 2, 3, 4,
5, 6, 7, 9, 10, 32, 33, 34, 35`. It also registers the **fullname strings**
`ALG, CONTENT_TYPE, COUNTER_SIGN, COUNTER_SIGN0, CRITICAL, EPHEMERAL_KEY, IV,
KID, KID_CONTEXT, PARTIAL_IV, PARTY_U_ID, PARTY_U_NONCE, PARTY_U_OTHER,
PARTY_V_ID, PARTY_V_NONCE, PARTY_V_OTHER, RESERVED, SALT, STATIC_KEY,
STATIC_KEY_ID, X5_BAG, X5_CHAIN, X5_T, X5_U` — note these are **uppercase**, so
lowercase `"alg"`, `"kid"`, `"ctyp"` do *not* match the registry directly, but
`from_id` calls `attribute.upper()`, so they do resolve.

Value parsers, verified by reading `headers.py` and probing the live library:

| label | parser | rejects `bytes` value? |
|---|---|---|
| 1 ALG | `CoseAlgorithm.from_id` | no, maps int→algorithm class |
| 2 CRITICAL | `crit_is_array` | no, but **requires a non-empty list** |
| 3 CONTENT_TYPE | `content_type_is_uint_or_tstr` | yes if given bytes |
| 4, 5, 6, 9, 10 | `is_bstr` | **yes — requires `bytes`** |
| -1, -2 (EPHEMERAL_KEY, STATIC_KEY) | `CoseKey.from_dict` | **yes, TypeError on bytes** |
| -20 … -26, -3, 0, 7, 32–35 | `default_parser` (no-op) | no |
| **anything unregistered** | none (value stored raw) | **no** |

This corrects the brief's constraint 3 in one place: label `24` is **not**
PARTIAL_IV — pycose registers PARTIAL_IV as label **6**. Label 24 is simply
unregistered and therefore accepts any value. The labels that genuinely reject a
`bytes` value are `-1` and `-2` (and any COSE_KEY header), plus 3/4/5/6/9/10 which
want specific types.

Labels used in my vectors, all verified accepted by constructing a real
`Sign1Message` and reading `_create_sig_structure()`:

| label | status | evidence |
|---|---|---|
| `1000`, `65536`, `70000` | unregistered int, `default_parser` | accepted |
| `-300`, `-25`, `-70000` | unregistered int, `default_parser` | accepted |
| `-1`, `-2`, `-3`, `-20`…`-26`, `24` | **registered** | **deliberately NOT used** |
| `2` (CRITICAL) | registered, needs non-empty list | **NOT used** — avoids the list requirement |
| `"z"`, `"zzz"`, `"mmm"`, `"qqq"` | unregistered tstr | accepted, passed through verbatim |

**Normalisation confound, tested explicitly.** pycose *does* rewrite registered
tstr labels: `{"alg": -7}` → `a10126` (key becomes `01`), `{"kid": b"k"}` →
`a104416b` (key becomes `04`). Unregistered tstr and int labels pass through
untouched: `{"zzz":1}` → `a1637a7a7a01`, `{1000:1}` → `a11903e801`. Every tstr
label in my new axis is unregistered, so pycose's header-label normalisation
cannot confound the ordering measurement. This is why I avoided the
`{"alg", "kid", "ctyp"}` shape used by the existing axis.

All 13 vectors were constructed through the **real** `lib_pycose_adapter`
(`_build_sign1`) before being committed to the generator. Zero raised, zero
returned `None`.

---

## 5. Measurement result

Run: `python cose-cross-impl/runner/run_matrix.py` — 106 cells
(53 vectors × 2 adapters).

### pycose, `header_key_ordering_4_2_1` — 13 cells

| vector_id | discriminates | verdict | pycose output matches |
|---|---|---|---|
| `int_1000_vs_tstr_z` | YES | **PASS** | §4.2.1 |
| `int_1000_vs_tstr_z_rev` | YES | **SPEC_VIOLATION** | §4.2.3 |
| `int_only_65536_vs_neg300` | YES | **PASS** | §4.2.1 |
| `int_only_65536_vs_neg300_rev` | YES | **SPEC_VIOLATION** | §4.2.3 |
| `int_only_1000_vs_neg25` | YES | **PASS** | §4.2.1 |
| `int_only_1000_vs_neg25_rev` | YES | **SPEC_VIOLATION** | §4.2.3 |
| `int_only_three_key_spanning` | YES | **SPEC_VIOLATION** | neither |
| `int_only_neg2_vs_neg5_len` | no | PASS | §4.2.1 (tie) |
| `int_only_neg4_vs_pos5_len_tie` | no | PASS | §4.2.1 (tie) |
| `tstr_unregistered_equal_len` | no | **SPEC_VIOLATION** | neither |
| `tstr_unregistered_len_differ` | no | PASS | §4.2.1 (tie) |
| `tstr_unregistered_vs_int_len_differ` | no | PASS | §4.2.1 (tie) |
| `tstr_unregistered_vs_int_len_invert` | YES | **PASS** | §4.2.1 |

**Discriminating count: 8 of 13 vectors. pycose FAILS (SPEC_VIOLATION) on 4 of
those 8; it "passes" 3 and matches neither rule on 1.**

**The 4 PASSes are coincidences, not conformance.** pycose calls
`cbor2.dumps(phdr)` with no `canonical=` flag (`cosebase.py:phdr_encoded`), so it
emits **insertion order**. In each forward vector the generator's insertion order
happens to equal the §4.2.1 permutation; in the reversed partner it equals the
§4.2.3 permutation. The decisive evidence is that **pycose's output changes when
only the insertion order changes** — which it does for all three pairs. A
library applying *either* sorting rule would emit identical bytes for both
members of a pair. Confirmed in `.scratch/explain_pass_trap.py`.

Conclusion: **pycose applies neither §4.2.1 nor §4.2.3. It does not sort map
keys at all.** Against RFC 9052 §9, which mandates §4.2.1, that is a
non-conformance, and the per-vector PASS/FAIL column is misleading unless the
forward/reverse pairing is read together.

`tstr_unregistered_equal_len` is the "sorted vs insertion order" probe: supplied
in insertion order `zzz, mmm, qqq`, pycose emitted exactly that, whereas both
sorting rules produce `mmm, qqq, zzz`. It correctly catches a non-sorting
library — SPEC_VIOLATION.

### Other axes — untouched

pycose cells on the 10 pre-existing axes: **40 shared cells, 0 verdict or byte
changes**. The vector JSONL files for those axes are byte-identical after
regeneration (`git status` shows only the new axis file as added).

Regenerating with the live oracle changed **no** existing vector's expected
bytes. An initial scan suggested 2 stale vectors in `empty_protected_bucket`
(`encrypt0_empty_protected_alg_iv_uhdr`, `mac0_empty_protected_alg_uhdr`); that
was an artifact of my checker reusing `build_cose_sign1_to_be_signed` where the
generator uses `build_cose_encrypt0_aad` / `build_cose_mac0_to_be_maced`. On
correct recomputation both match. **The stale-expected-values premise in the
brief does not hold for the COSE corpus at HEAD** — only the
`header_label_sorting` *discriminating power* was missing, not the expected bytes.
The equivalent CBOR corpus still needs its own check; I did not touch it.

### `lib_go_cose` — degraded, and I did not destroy the prior evidence

The Go driver `R:\cose-cohort\go-cose\driver\driver.exe` is **absent from this
machine**, so `lib_go_cose` returned `None` for all 40 pre-existing cells and the
runner rewrote them `PASS → NOT_SUPPORTED`. The runner has no `--adapters` flag,
so it always loads both adapters.

I restored `cose-cross-impl/results/matrix.jsonl` and `matrix.tsv` from a backup
taken before the run, then spliced in only the new axis's 26 rows. Verified: all
80 pre-existing rows preserved byte-identical; final diff is **purely additive**
(+26 rows jsonl, +28 lines tsv). The 13 new `lib_go_cose` rows on the new axis
are `NOT_SUPPORTED` with note "adapter returned None (no structure extraction)" —
they are honest, not measurements. Building the Go driver was out of scope
(heavy build, explicitly excluded), so **the new axis has no go-cose coverage on
this machine.**

---

## 6. What I could not determine

1. **go-cose behaviour on the new axis.** Driver absent. The adapter docstring
   claims the driver uses `fxamacker/cbor` with `SortCoreDeterministic`, which
   the adapter equates with §4.2.1 — but that claim is **unverified here**, and
   given that it conflated §4.2.1 with `SortCoreDeterministic` (fxamacker's
   canonical mode is length-first, per its own docs, not bytewise-lex), I would
   not carry it forward without checking. Needs a CI run.
2. **Whether the "2 stale vectors" claim holds for `cbor-cross-impl`.** I scoped
   to the COSE corpus per the brief and found the claim false there. The CBOR
   corpus (111 vectors) was not re-verified; the orchestrator's measurement of
   111/111 `canonical == deterministic` is consistent with a genuinely
   non-discriminating corpus, but the store-vs-live comparison is unrun.
3. **cbor2 6.1.4's `canonical=True` semantics.** Only the compiled
   `_cbor2.pyd` is installed; there is no Python-level encoder source to read, so
   whether `canonical=True` implements §4.2.1 or §4.2.3 remains unresolved from
   inspection. It does not affect this work — pycose never passes the flag — but
   it blocks any "just set `canonical=True`" remediation claim.
4. **Whether the `fnd-2026-0014` conclusion survives.** I have shown pycose does
   not sort keys and that the old axis could not have detected that. Rewriting
   or superseding the finding is the orchestrator's call under
   `knowledge/` ownership, not mine.
5. **Structural structure of the new vectors beyond the protected bucket.** The
   oracle's expected bytes are computed at the Sig_structure and full-message
   level; the `axis_metadata` discriminator fields are the protected-map bytes
   specifically, since that is the only place key ordering is observable in a
   COSE message.

Scratch artifacts (gitignored, disposable): `check_stale.py`,
`int_only_discrimination.py`, `design_and_validate.py`, `report_axis.py`,
`print_vectors.py`, `explain_pass_trap.py`, `restore_and_splice.py`,
`matrix_before.jsonl`, `matrix_after_full_run.jsonl`.
