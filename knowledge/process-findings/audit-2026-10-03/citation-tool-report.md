<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: citation_tool_report.md -->

# Citation verification tool — design, selftest, dry-run, limits

Tool: `tools/verify_citations.py` (v1.0.0). Stdlib + PyYAML only.
`requests` is **not** installed in `.venv`; Tier 2 uses `urllib.request`.

```
.venv\Scripts\python.exe tools\verify_citations.py [--finding <id> | --all]
    [--online] [--json] [--report <path>] [--missions]
    [--stale-days N] [--selftest [--selftest-network]]
```

Exit codes: `0` no tier-1 findings · `1` tier-1 FAILs · `2` tool error.
Network state never changes the exit code.

## 1. Design decisions

**Four severities, not pass/fail.** `FAIL` (deterministic defect), `WARN`,
`REVIEW` (needs a human), `UNVERIFIABLE` (not checkable). Only tier-1 `FAIL`
affects the exit code. This is the mechanism that keeps the "never fabricate"
rule: nothing is ever asserted as PASS, and anything uncheckable is explicitly
labelled rather than silently skipped.

**Tier 2 always emits rows, online or not.** Offline, every citation and
quotation candidate produces an `UNVERIFIABLE` row ("not checked (offline)").
The report therefore records what is *unchecked* rather than omitting it.

**Commit-shape check is positional, not lexical.** A survey of the corpus found
**985** hex-looking strings of other lengths (CBOR test vectors, CBOR byte
strings, GHA run IDs, base64). Scanning for bare 40-hex produced pure noise, so
the trigger is `commit|revision|rev|sha` immediately followed by hex. Valid
lengths are git's own: 7–12 (abbreviation), 40 (sha-1), 64 (sha-256).

One deliberate non-flag: `0ef0f5a8` in `fnd-2026-0009` is a *valid* 8-char
abbreviation of `0ef0f5a839831c213f24e3f2ae434765c607fb50`. My first draft
flagged it (I assumed a truncation bug); that would have been a false positive
on the very artifact the tool was built for. Only genuinely malformed tokens
(truncated 20-char, oversized) are reported.

**Link resolution always spans `missions/`.** A `knowledge/` finding routinely
links to the mission that produced it. Scoping resolution to `knowledge/` alone
made `fnd-2026-0009`'s `msn-2026-0010` link report as dangling. Scanning is
still opt-in (`--missions`); resolution is unconditional.

**Quotation matching uses a 0.6 sentence quorum, not 100%.** RFC plain text
hard-wraps mid-sentence and renders hex literals in backticks. The genuine
RFC 9052 §9 quotation in `fnd-2026-0014` matches 7/8 sentences; requiring 100%
flags it. The misquotation matches 0/2, far below any reasonable threshold.
Quotations are compared against the **`.txt`** RFC, the canonical artifact.

**`WITHDRAWN_STATUSES` includes `disputed`.** `fnd-2026-0010` is `disputed` and
depends on the rejected `fnd-2026-0009`; a disputed sibling resting on a
refuted one is exactly what a pre-disclosure gate should surface.

**Query strings exempt from the "bare host" rule.** `https://cbor.me/?bytes=…`
encodes its vector in the query; that is a document selector, not a site
citation. Flagging it was a false positive found during the dry-run.

## 2. Selftest

`--selftest` builds a throwaway corpus in `%TEMP%` (nothing written to the
repo). It proves both **detection** and **no false positives**.

```
[PASS] known-bad fixture: raised ['correction_contradiction', 'link_dangling',
       'link_withdrawn', 'sha_shape', 'staleness', 'url_scheme']
[PASS] clean fixture: 0 findings (no false positives)
[PASS] rfc discrimination: PASS (spliced sentence found in RFC 8949 and absent
       from RFC 9052, so misattributing it is detectable)
selftest: PASS   (exit 0)
```

The known-bad fixture `fnd-2026-9999` reproduces **both** real failures at
once — the spliced RFC 8949 text presented as an RFC 9052 quotation, and a
dependency on a `rejected` artifact — plus a malformed commit token, an http
citation, and `verified_conclusion` alongside a correction calling its own
substance false. It raised all six expected checks.

### Proof against the real pattern

The offline fixture check does not by itself prove the RFC discrimination works,
so `--selftest-network` verifies it against the live documents:

| Sentence | In RFC 8949 | In RFC 9052 |
|---|---|---|
| "the keys in every map MUST be sorted in the bytewise lexicographic order…" | **True** | **False** |
| "encoding restrictions are aligned with Core Deterministic Encoding Requirements specified in Section 4.2.1 of RFC 8949" | — | **False** |

Run against the real artifact, the tool reports:

```
MANUAL fnd-2026-0014: quotation at normative_basis_original
  .rfc_9052_section_9_as_previously_quoted did not match the cited RFC text
  (rfc9052: 0/2 sentences found; rfc8949: 0/2; rfc9052.html#section-9: 0/2);
  treat as SUSPECT and re-read the source before relying on it

MANUAL fnd-2026-0014: quotation at normative_basis_verified
  .rfc_9052_section_9_actual matches text in the cited RFC
```

The **misattributed** text is flagged and the **corrected** text is not. That
separation is the check that would have caught `fnd-2026-0014` before it reached
`verified_conclusion`.

## 3. Dry-run against the real corpus (no network)

`--all --missions`: **246 artifacts**, 252 distinct URLs.

**Tier 1 — 27 observations, 18 FAIL:**

| Check | Count | Severity |
|---|---|---|
| `link_withdrawn` | 18 | FAIL |
| `url_noncanonical` | 6 | WARN |
| `correction_contradiction` | 3 | REVIEW |

`link_withdrawn` FAILs across 16 artifacts. The ones that matter:

- `fnd-2026-0010` → `fnd-2026-0009` (`rejected`) — the exact fnd-2026-0009
  blast radius, still carried.
- `msn-2026-0010` → `fnd-2026-0009` (`rejected`)
- `msn-2026-0011` → `fnd-2026-0010` (`disputed`)
- `fnd-2026-0001` (×2) → `hyp-2026-0006`, `hyp-2026-0007` (both `rejected`) —
  a `verified` finding resting on two rejected hypotheses.
- `rev-2026-0009`, `rpr-2026-0009`, `vrf-2026-0010`, `rpt-2026-0010` and others.

`correction_contradiction` REVIEWs are `fnd-2026-0014` (×2) and
`rpt-2026-0015` — all three are the *corrected* artifacts, which is a healthy
signal (the correction is recorded, the status was not revisited).

**Tier 2 — 819 rows, all `UNVERIFIABLE` offline** (498 reachability +
321 quotation candidates). Exit code `1` from tier 1 alone.

No tier-1 FAIL fired on the URL or SHA checks against the live corpus: the repo
already uses https everywhere (0 plain-http citations) and its commit hashes are
well-formed. That is the tool reporting a clean bill on those axes, not a
silent no-op.

**Read-only verified**: SHA-256 of all 230 `knowledge/` YAML files, before and
after an `--online` run — byte-identical.

## 4. Known limitations — what this tool CANNOT catch

Stated plainly, because the point is to close a real gap, not to look complete.

1. **It does not verify that a quote comes from the *right* source.** It checks
   whether sentences appear somewhere in the cited RFC. Splicing is caught
   only because the spliced sentence is absent from the wrongly-cited document.
   A quote from a *different section of the same RFC* passes silently.
2. **Tier 2 covers RFCs only.** 278 of the corpus's citations are GitHub URLs.
   `github.com/.../blob/<commit>/<file>` is only HEAD-checked for reachability.
   The `fnd-2026-0009` defect — reading one layer above the function that
   actually validates — is **not** detectable here. It needs a source-reading
   agent, which is why the re-verification in that correction was done by an
   archaeologist and then re-checked by the orchestrator.
3. **`url_reachability` never implies correctness.** A 200 means the URL exists,
   not that it says what the finding claims. 498 rows is mostly inventory.
4. **Section-level attribution is not checked.** Matching "the restriction
   applies to the encoding of the Sig_structure" against the RFC body does not
   confirm it is in §9 and not §3.
5. **`sha_shape` is shape-only.** It confirms a commit token is 7–12/40/64 hex
   characters. It does **not** confirm the commit exists, or is the commit the
   code was actually tested at. A well-formed hash for the wrong commit passes.
6. **The 0.6 quorum is a tuned threshold, not a proof.** A quotation more than
   40% fabricated could still cross it. It is tuned against one verified and
   one fabricated example; it is not calibrated against a corpus of known-good
   quotations.
7. **Quotation detection is a heuristic.** The `QUOTE_MIN_WORDS=40` +
   `RFC_KEYWORDS` + context-regex filter misses short quotations and non-RFC
   specs (FIPS 203, drafts, source files). 321 candidates on this corpus is a
   rough recall, not coverage.
8. **`correction_contradiction` is word-matching.** It flags `verified` +
   "refuted"/"withdrawn"/"false". It will fire on a correction that legitimately
   withdraws a *sub-claim* while the rest stands — which is why it is `REVIEW`,
   never `FAIL`. It cannot tell which reading is correct.
9. **`link_withdrawn` is noisy by design.** 18 FAILs include many that are
   *correct* history — an artifact faithfully recording that a hypothesis was
   rejected. The check cannot distinguish "cites a rejection as evidence" from
   "rests on a refuted conclusion". It wants a human, not a CI gate.
10. **Not wired into CI.** No workflow invokes it. It is a pre-disclosure /
    pre-promotion instrument; nothing yet forces anyone to run it.
11. **Untested scale.** 246 artifacts with `--online` exceeds the foreground
    command timeout; a full online sweep needs batching or a background run.
12. **Reads text, not semantics.** It never follows a link to check that the
    linked page supports the sentence that cites it.

## 5. Recommended use

Run before promotion or disclosure, and after any correction pass:

```
.venv\Scripts\python.exe tools\verify_citations.py --finding fnd-2026-0014 --online
.venv\Scripts\python.exe tools\verify_citations.py --all --missions --json
```

Exit 1 means deterministic tier-1 defects exist. Exit 0 means *no tier-1
defect found* — never "the citations are correct".
