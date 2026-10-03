<!-- Preserved from .scratch/ (gitignored, not durable).
     Supports tools/promotion_gate.py committed alongside this file.
     Original filename: promotion_gate_report.md -->

# Promotion Gate — Design, Results, and Limits

**Tool:** `C:\Users\Dhane\frontier\tools\promotion_gate.py` (v1.0.0, 1900 lines, ruff-clean)
**Fixture:** `C:\Users\Dhane\frontier\tools\fixtures\rfc_sections.yaml` (940 KB, recorded authoritative text)
**Date:** 2026-10-03
**Scope of change:** `tools/` and `.scratch/` only. No YAML artifact, no `src/`, no `missions/`, no `.github/` was modified. No commit made.

```
promotion_gate 1.0.0
  artifacts scanned: 252   gated (claim-making types): 38
  20 REFUSE   0 ALLOW-with-normative-claims   18 in-scope with no normative claim
  214 not gated (evidence types)
  exit-blocking (assertive-status only): 4 artifacts -> exit 1
```

---

## 1. Design

### The rule being enforced

> A normative claim cannot be promoted unless the exact cited specification
> clause has been independently checked against the authoritative source during
> verification.

### Why not a parallel schema

The repo already has a place for this, so the gate uses it:

- **Primary — the `verification` artifact (`vrf-*`).** `normative_checks` is a
  block on a verification artifact referenced from `links.verifications`. The
  gate reads every linked verification and merges its `normative_checks` entries
  into the claimant's check set. This is idiomatic because `vrf-2026-0016` and
  siblings already carry free-form sub-blocks (`verification_steps`,
  `byte_evidence_chain`, `promotion_rationale`, `promotion_actions`).
- **Secondary — inline.** A `normative_checks` list directly on the artifact.
  Specifications are the reason this exists: `spc-*` artifacts are not on the
  promotion ladder, `_validate_finding` does not require them to link
  verifications, and `spc-2026-0004`'s fabricated quotations are exactly the
  thing that must be blockable.

Both spellings are read, so an author uses whichever matches the artifact type.
`method:` stays inside `frontier.validate.VERIFICATION_METHODS`
(`deterministic-script`) — **no change to `src/frontier/validate.py`, no change
to `localdocs/schemas/verification.schema.json`, and therefore no schema
migration for existing artifacts.**

### Record shape

```yaml
normative_checks:
  - id: NC-1
    source:     https://www.rfc-editor.org/rfc/rfc9052.html#section-9
    section:    RFC 9052 section 9
    quoted:     "<the exact text the artifact attributes to that clause>"
    method:     section-scoped-substring
    checked_at: 2026-09-28            # fetch date
    checker:                            # checker identity
      kind: model-agent
      role: specification-analyst
    verdict:   confirmed               # confirmed | misattributed | unverifiable
    detail:    "Fetched rfc9052.txt; every clause located in section 9."
```

Required by the gate: `source`, `section` (when the source is an RFC),
`quoted`, `checked_at`, `checker`, `verdict`. A record missing any of these is
itself a refusal (G7) — a check nobody can audit is not a check.

### Extending `verify_citations.py` vs wrapping it

**Wrapping, by import.** `promotion_gate.py` imports `verify_citations.py` via
`importlib` and reuses `Artifact`, `walk_strings`, `extract_urls`,
`_find_rfc_body`, `_normalize_text`, `_quote_probe_sentences` and `_parse_date`.
One fetch implementation, one normalization, one sentence splitter — the two
tools cannot drift apart on the same quotation.

The genuinely new capability is **section resolution**: parsing an RFC plain-text
body into `section-number -> text`. `verify_citations.py` documented this as its
own limitation ("checks a quote appears *somewhere* in the cited RFC"). RFC plain
text has body headings at column 0 and an indented table of contents, so dropping
everything before the first body heading removes the TOC; a section runs until the
next heading that is neither itself nor one of its subsections, which is why a
quote in 4.2.1 resolves under both 4.2 and 4.2.1.

### The offline fixture, and why it is not fabricated data

`--selftest` must be deterministic without a network. `tools/fixtures/rfc_sections.yaml`
holds **recorded authoritative text**, not mock data: RFC 8949 and RFC 9052 fetched
from rfc-editor.org, with source URL, fetch timestamp, whole-body SHA-256, byte count
and parsed sections. Under `--online` the gate fetches live and **re-checks the
recorded hash**; a mismatch is reported as a stale fixture and the live text wins.
Regenerate with `tools/promotion_gate.py --record-fixtures`. An RFC that cannot be
fetched is skipped and reported, never filled in.

---

## 2. Gate rules

| Rule | Meaning | Effect |
|---|---|---|
| **G1** | normative claim has no recorded source check | REFUSE |
| **G2** | quotation not located in its cited source section | REFUSE (online) |
| **G3** | quotation attributed to a source that does not contain it (found elsewhere in the same RFC) | REFUSE (online) |
| **G4** | normative text not re-checked within the window (default 180 days, `--recheck-days`) | REFUSE |
| **G5** | `links.reviews` empty, or no linked review is independent | REFUSE |
| **G6** | every independent review is `disputes`/`inconclusive`/unfinished | REFUSE |
| **G7** | a check record is missing required provenance | REFUSE |
| **G8** | a recorded verdict did not confirm | REFUSE |

**Exit codes:** `0` allow, `1` refuse, `2` tool error.

**Network policy.** G2/G3 need source bytes. When the source cannot be read —
offline with no fixture, fetch failure, 5xx, a non-RFC source with no
deterministic locator (an I-D, a FIPS PDF, a source file) — the outcome is
`UNVERIFIABLE` and never blocks. The offline rules (G1, G4–G8) refuse on their
own, because a missing or stale provenance record is a defect whether or not the
network is up. **Verified:** `.scratch/verify_outage.py` asserts that a total
fetch outage yields `decision=ALLOW`, `unverifiable=2`, zero blocking rules,
zero exit-blocking results.

**Scoping.** Only `finding`, `specification` and `report` are gated
(`GATED_TYPES`). Those are the types that assert a claim of their own. An
experiment or observation is *evidence for* someone else's claim; gating them
punishes the evidence chain for the claimant's omission. The first corpus run
made this mistake — it refused 134 artifacts, mostly `exp-*` — and the fix took
refusals from 134 to 20.

**Claim extraction.** A claim is prose attributed to a *clause*. Attribution comes
from the field's **key path** (`normative_basis.rfc_9052_section_9` — how the
corpus actually records most citations, where the *value* carries no RFC token at
all) or from the **value**, which is split into segments at each citation so a
multi-clause extract like `spc-2026-0005`'s is checked clause by clause rather than
against the first clause mentioned.

**Quotation intent is required.** A claim must sit under a quotation field
(`normative_extract`, `rule_ref`, `normative_basis`, `*_original`, `quoted_text`,
`excerpt`, `clause`, `verbatim`) or the string must state that it *says/is* the
source's wording. Without this test, `fnd-2026-0014`'s own correction text —
"RFC 9052 section 9 does not contain this" — is itself reported as a misquotation
of RFC 9052 section 9. Adding this test took corpus G2 refusals from 37 to 12.

**Retracted text is excluded.** `correction_*` blocks and `*_original` keys hold a
deliberately preserved bad quotation. Re-litigating it on every run is noise, and
`verify_citations.T1_CORRECTION_UNMARKED` already polices that it is marked.

**Matching robustness.** Two decompositions are tried — ellipsis-split (for a
quotation joining two passages of one section) and sentence-split — and the
better ratio wins, at the same 0.6 quorum `verify_citations` uses. Taking the
maximum is the conservative direction for a gate: it can make a claim look better
sourced, never worse, so it never manufactures a refusal, and it still cannot
manufacture a pass.

---

## 3. Selftest results

`tools/promotion_gate.py --selftest` — **PASS**, and **PASS** again with
`--selftest-network` against the live RFCs. Six fixtures, exit 0.

```
[PASS] failure mode 1 (fnd-2026-0014 class): RFC 8949 4.2.1 text spliced into
       an RFC 9052 section 9 attribution [fnd-2026-9001]:
       REFUSE rules=['G1', 'G2_quote_not_in_cited_source']
[PASS] right RFC, wrong section (invisible to a document-level check)
       [fnd-2026-9006]: REFUSE rules=['G1', 'G3_quote_attributed_to_source_lacking_it']
[PASS] failure mode 2: normative claim never re-checked [fnd-2026-9002]:
       REFUSE rules=['G1']
[PASS] every review disputes [fnd-2026-9004]: REFUSE rules=['G6']
[PASS] stale normative check [fnd-2026-9005]: REFUSE rules=['G4']
[PASS] clean fixture [fnd-2026-9003]: ALLOW rules=[]
```

Both real failure modes are reproduced and refused:

- **Failure mode 1** (`fnd-2026-0014`): the fixture quotes RFC 8949 §4.2.1
  text as RFC 9052 §9. **REFUSED.**
- **Failure mode 2**: full evidence chain, fresh artifacts, supporting
  independent review, valid passing verification — but nobody re-fetched the
  clause. **REFUSED** on G1 alone. This is the exact shape of `fnd-2026-0014`'s
  history: the measurement was re-checked every session and the source never was.
- **Right document, wrong clause**: genuine verbatim RFC 9052 §3 text presented
  as §9. **REFUSED** on G3. A document-level "does this RFC contain it" check
  passes this one — which is precisely the gap `verify_citations.py` documents.
- **Clean fixture**: inline check, fresh, quote located in the cited clause,
  supporting independent review. **ALLOWED** — so the gate is not simply
  refusing everything.

Three real bugs were found and fixed while building the fixtures, each a case of
the tool disagreeing with reality:

1. `store.origin` referenced a nonexistent attribute — crash on every run.
2. A zero-denominator division reported "0/0 quoted units found" as a
   *misquotation*, converting UNVERIFIABLE into FAIL.
3. `_best_ratio` compared only the ratio, so a decomposition with zero hits left
   the unit count at 0 and was indistinguishable from "nothing to probe".

Two of my own test fixtures were also wrong before the tool was: a fabricated
G3 fixture whose first passage was a paraphrase, and a spurious assertion that
the spliced quote should trip G3 rather than G2. Both were corrected against the
fetched RFC text rather than by loosening the tool.

---

## 4. Corpus dry-run (read-only)

252 artifacts scanned, 38 gated, **20 REFUSE**, 4 of which block the exit code.

### Exit-blocking (assertive status) — 4

| Artifact | Status | Why blocked |
|---|---|---|
| `fnd-2026-0003` | `verified_conclusion` | G1, G2 |
| `rpt-2026-0015` | complete | G1 |
| `rpt-2026-0016` | complete | G1 |
| `rpt-2026-0017` | complete | G1 |

### Refused but not exit-blocking (non-assertive status) — 16

`fnd-2026-0002`, `fnd-2026-0004`, `fnd-2026-0005`, `fnd-2026-0006`,
`fnd-2026-0009`, `fnd-2026-0012`, `fnd-2026-0013`, `fnd-2026-0014`,
`fnd-2026-0015`, `rpt-2026-0012`, `rpt-2026-0013`, `rpt-2026-0014`,
`spc-2026-0003`, `spc-2026-0004`, `spc-2026-0005`, `spc-2026-0006`.

By rule: G5 ×15, G2 ×12, G1 ×10, G6 ×5. 26 clause-location checks were
UNVERIFIABLE (non-RFC sources: I-Ds, FIPS 203, source files) and blocked nothing.

### The three cases named in the task

**`fnd-2026-0014`** — REFUSED on three independent grounds:
- G1: 3 live normative claims, no `normative_checks` anywhere. Nobody re-fetched.
- G2: quotations attributed to RFC 9052 §3 not located there.
- G6: the only completed independent review, `rev-2026-0017`, has
  `verdict: disputes`.
- 2 of its 3 claims *are* correctly located — the gate is not just objecting to
  the artifact's existence.

**`spc-2026-0004`** — REFUSED on G1 and G2. Confirmed independently against the
fetched RFC: the §4.2 and §4.2.1 passages attributed to it are **not in RFC 8949
at those sections**. The `map_key_sort` axis defined against §4.2.3 is a real
axis of §4.2.3; the artifact's §4.2.1 quotations are fabricated.

**`spc-2026-0005`** — REFUSED on G1 and G2, with 14 live claims including the
§9 passage "Map keys in protected headers: lexicographic by label", which does
not exist in RFC 9052 §9.

**`fnd-2026-0009`** — REFUSED on G5 only (`rev-2026-0009` has no `independent`
field). The gate finds **zero** normative claims in it. That is the honest result
and it belongs in section 6: the `file:line` abstraction-layer error is
invisible to this tool.

### Honest caveats on the dry-run

- **Every refusal is a refusal to promote, not a finding of error.** An artifact
  with no `normative_checks` may be perfectly correct and simply predate the
  convention. G1 on all 10 is a bookkeeping gap, not 10 discovered errors.
- **G5 ×15 is mostly noise.** Many of these are reports and specifications that
  legitimately have no independent review. G5 belongs in the gate as a rule
  (the task requires it) but on this corpus it is the weakest signal, and I
  would not weight it as highly as G2/G3.
- **G2 on `spc-2026-0003`/`spc-2026-0006` has not been individually
  adjudicated** by me against the RFC text. They are refused; whether each
  refusal is correct is a human review task.
- The `--strict` mode (all statuses count) would block 35.

---

## 5. Integration status

**`frontier validate`: untouched, and still passing.** Confirmed after all
changes: `python -m frontier.cli validate` → `ok: research state structurally
consistent`, exit 0. Full test suite: 48 passed.

**No change was made to `src/frontier/validate.py` or to
`localdocs/schemas/*.json`.** This is the blocker, and it is a deliberate
design constraint rather than an obstacle I failed to clear:

> **The gate cannot be wired into `frontier validate` as an error today,
> because 20 existing artifacts would fail it — 4 of them
> `verified`/`complete`.** Adding `normative_checks` as a required field on
> `verified` findings would break `frontier validate`, which the test suite and
> `ci.yml` both depend on.

The exact integration, in the order it should be done by a human decision:

1. **Land the gate as a non-blocking CI job now.** Add to `.github/workflows/ci.yml`
   a step that runs the gate and uploads its report, but **does not fail the
   build**:
   ```yaml
   - name: Promotion gate (advisory)
     run: |
       python -m pip install pyyaml
       python tools/promotion_gate.py --all --report promotion-gate.txt || true
   ```
   This is safe today: it needs no artifact change and gives visibility.
2. **Remediate the 4 exit-blocking artifacts.** Add `normative_checks` records
   to `fnd-2026-0003`, `rpt-2026-0015/16/17`. This requires editing
   `knowledge/`, which was read-only for this task.
3. **Then make it blocking.** Change `ci.yml` to drop `|| true`.
4. **Then encode it in `validate.py`**, by adding to `_validate_finding`:
   ```python
   if doc.get("status") in ("verified", "verified_conclusion"):
       if not _has_normative_check(doc, objects):
           errors.append(f"{did}: verified finding with normative claims requires "
                         "a normative_checks record ...")
   ```
   with `normative_checks` accepted inline **or** on a linked verification, and
   an artifact with no normative claims exempted. Only after step 2, otherwise
   `frontier validate` breaks and CI goes red on a clean checkout.
5. Optionally add `normative_checks` to `localdocs/schemas/verification.schema.json`
   as a non-required property. Not required for correctness — the schema is not
   enforced by `validate.py` — but it documents the convention.

**Why not simply wire it in now:** AGENTS.md forbids editing `knowledge/`, and
the gate's whole purpose is to be satisfied by adding records to `knowledge/`
artifacts. Wiring it in before remediation would make CI permanently red for a
reason no agent may fix under the current constraints. The advisory-first
sequence gets the machinery into the pipeline today without breaking anything.

---

## 6. What this gate CANNOT catch

This is the section that matters most. The gate is an **attribution** check. It
verifies that text attributed to a clause is text of that clause. It has no
notion of meaning, and its coverage is bounded by four hard limits.

### 6.1 The abstraction-layer error (`fnd-2026-0009`) — not detectable, at all

This is the important one.

`fnd-2026-0009` cited `kexmlkem768x25519.c` for a FIPS 203 §7.2 check that lived
one call frame below, in vendored `libcrux-mlkem-mldsa.c`. **The gate found zero
normative claims in it and refused it only for an unrelated reason (no
independent review).** Had that review been present, the gate would have allowed
it.

No tool can catch this, and I am not going to pretend otherwise. The citation is
*true*: the file exists, the lines exist, the function really is called, the code
really is a real check of a real kind. Every mechanical property holds. What is
wrong is a judgement about **semantic altitude** — whether the cited location is
the one that implements the property — and that requires either reading the code
path or knowing the call graph. Nothing in this repo, and nothing in this gate,
can derive "the check is one frame below the cited file" from a YAML string.

The only defences against this class are procedural: an adversarial reviewer that
actually follows the call chain, and the practice already recorded in
`fnd-2026-0009`'s own `preserved_as_negative_result` — *"auditing a KEX wrapper
is not auditing a KEM."*

### 6.2 Paraphrase presented as quotation

A correct claim in the artifact's own words is **not** a misquotation and will
pass. The gate confirms that quoted text is in the cited clause; it cannot
confirm that a paraphrase faithfully renders the clause. `spc-2026-0005`'s
"RFC 9052 §9: Integers MUST use shortest form" is close to true and is refused
only because the probe text is absent — the gate is not reasoning about
correctness of paraphrase, it is doing substring matching.

### 6.3 The 0.6 quorum and format drift

A quotation is confirmed when ≥60% of its probe units match verbatim. A
fabricated quotation with substantial genuine content could clear that bar by
reusing real sentences around an invented one. Genuine quotations that drift in
formatting (RFC backticks around hex literals, list re-flow) can also fail it.
The corpus contains exactly such a case — `verify_citations`' own docstring notes
one sentence in the real corpus renders a hex literal in backticks. **A pass from
this gate is evidence of attribution, not proof of it.**

### 6.4 Coverage is RFC-only, and only for recorded clauses

- Non-RFC normative sources are structurally **UNVERIFIABLE**: I-Ds
  (`draft-ietf-sshm-mlkem-hybrid-kex-10`), FIPS 203 (a PDF in
  `localdocs/refs/`), and source files. 26 claims in this corpus sit in that
  bucket. They can only ever be discharged by a recorded human check — the gate
  will not silently pass them, but it also cannot help.
- Only section-scoped text is checked. A citation to a whole document, or to a
  figure, is not located and does not trigger a refusal.
- The gate reads **only the two RFCs in the fixture plus live RFC fetches**.
  Other standards are out of reach.

### 6.5 Provenance records are only as honest as their author

`normative_checks` is a self-report. The gate checks that a record exists, is
complete, is in-window, and records a confirming verdict. It **cannot** check
that the checker actually fetched the source. An agent that writes
`verdict: confirmed` without re-fetching produces a record that passes every
mechanical check and reproduces the original failure exactly.

The fixture-hash discipline (live fetch re-checks the recorded SHA-256) is a
partial countermeasure, and it is worth extending: **a deterministic tool that
writes the record would close this**, but that is future work, not done here.

### 6.6 Scope

- G1 and G5 are **bookkeeping rules, not truth checks.** Every G1 refusal on this
  corpus means "nobody wrote a check record", which may reflect an accurate
  artifact that predates the convention.
- The gate does not model the promotion ladder's other links (experiment,
  observation, reproducer, determinstic verification). `frontier.promotion` does.
  They are complementary, not substitutes.
- Review-verdict vocabulary is matched **by prefix** (`support*` supports,
  `dispute*`/`refute*`/`inconclusive` do not) because the corpus is not uniform —
  `support`, `supports`, `SUPPORT_WITH_MAGNITUDE_CORRECTION`, `PARTIAL_SUPPORT`
  all appear. A new verdict spelling could be misclassified.
- The gate is **read-only** by construction: it never writes to `knowledge/`,
  `missions/` or `src/`. Verified by `git status` — only `tools/promotion_gate.py`,
  `tools/fixtures/` and `.scratch/` are new.

---

## Files

| Path | Status |
|---|---|
| `C:\Users\Dhane\frontier\tools\promotion_gate.py` | new, ruff-clean, selftest PASS |
| `C:\Users\Dhane\frontier\tools\fixtures\rfc_sections.yaml` | new, recorded RFC 8949 + 9052 with SHA-256 provenance |
| `C:\Users\Dhane\frontier\.scratch\promotion_gate_report.md` | this report |
| `C:\Users\Dhane\frontier\.scratch\verify_outage.py` | network-outage non-blocking proof |
| `knowledge/`, `missions/`, `src/`, `.github/` | **unmodified** |
