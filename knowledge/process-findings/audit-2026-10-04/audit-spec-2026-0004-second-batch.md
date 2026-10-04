# Process finding — SPEC-2 second-batch audit, 2026-10-04

**Scope.** Independent audit of `knowledge/specifications/spc-2026-0004.yaml`
(the RFC 8949 deterministic-encoding specification), conducted while
`msn-2026-0022` (X.509 pathLenConstraint) was the primary mission.

**Role.** SPEC-2, non-synthesizer, read-only. It did not edit any committed
artifact.

## Premise correction

The session brief asserted that `spc-2026-0004` still carried fabricated
quotations and that SPEC-1 was repairing them. **That premise was stale.**
By the time SPEC-2 ran, SPEC-1 had already withdrawn the `normative_extract`,
removed the `audit_axes` list, and added a `fabricated_quotations_removed`
inventory. SPEC-2 recovered the previous revision read-only from git
(`5270b10`, blob `d8e8dde3`) and audited that instead. SPEC-1 and SPEC-2 may
therefore have duplicated work; that is recorded here rather than hidden.

Lesson: a task brief that describes an artifact's state can go stale within a
single session. The brief is a hypothesis about the repository; the repository
is the evidence.

## Source identity (fetched independently, not inherited)

| Source | Bytes | SHA-256 (prefix) | Fetched |
|---|---|---|---|
| RFC 8949 | 185226 | `F1164A5B…8A214A` | 2026-10-04 |
| RFC 9052 | 149835 | `01EECD7F…38CD0A45` | 2026-10-04 |

## Findings

1. **29 of 29 quoted fragments are absent from RFC 8949.** All 8 `rule_ref`
   strings are wrong locators. RFC 8949 §4.2 has no numbered rules; §4.2.1 has
   three unnumbered bullets. Confirmed by re-derivation, not by trusting the
   artifact's own correction list.

2. **A wrong constant the artifact's own correction list misses.** The axis
   claimed `1.5 → 0xf93c00`. RFC 8949 §4.2.1 says **1.5 is encoded as
   `0xf93e00`** (binary16). The artifact gave the same hex value for 1.0 and
   1.5 within one clause.

   *Orchestrator verification:* I fetched RFC 8949 independently and read §4.2.1
   directly. It reads "1.5 is encoded as 0xf93e00 (binary16) and 1000000.5 as
   0xfa49742408 (binary32)". SPEC-2's finding is CONFIRMED.

3. **The wrong-RFC failure mode, confirmed and consequential.** The artifact
   attributed COSE determinism to RFC 9052 §4 ("Signing Objects"). It is §9, and
   §9's three restrictions **omit map-key ordering**. The citation error
   therefore manufactured the false `duplicate_key_rejection` axis — a defect
   that exists only because of a misattribution.

4. **Discriminating power is low.** Only 2 of 8 axes discriminate between
   implementations; 3 are vacuous, one of those because its rule does not
   exist. 91 of 111 corpus cells sit in axes that never separated anything, so
   the headline "111/111 byte-exact" is largely arithmetic rather than map
   ordering.

5. **Two escalations.**
   - `rev-2026-0018` returned "accurate" on fabricated quotations and is what
     made the defect durable. **A review that certified fabricated text as
     accurate is itself a process failure** and deserves its own finding.
   - `msn-2026-0017` stands at `verified` on a withdrawn authority.

6. **The measurement chain survives.** `obs-2026-0047`'s conclusion is sound, and
   RFC 8949's §4.2.3 worked example is genuinely length-first. The later
   `imp-2026-0018/0020/0021` artifacts got §4.2.1-vs-§4.2.3 **right**; only the
   specification artifact got it wrong.

7. **Defects outside the family.** The "14 integer vectors" count propagated into
   `rpt-2026-0012` and `rev-2026-0015` as a "correction" — RFC 8949 Appendix A
   Table 6 actually has **18**. `rev-2026-0016` used the mislabelled oracle to
   disprove correlation.

## Not verified (stated, not glossed)

- RFC 9053 and RFC 8152 were **not fetched**. The artifact's "RFC 9052 §9 /
  RFC 9053 §9" assertion is false on the 9052 half; the 9053 half is
  **unverifiable**, not disproved.
- cbor.me was not consulted.
- The `R:\` corpus was wiped mid-session, so the 111-vector figures are
  **inherited, not re-measured**.
- **No library was executed.** This is a citation audit only.

## What this changes for the X.509 mission

Nothing directly. It is recorded because the same failure shape — an
attribution error creating a defect that then propagates — is the shape the X.509
mission was built to avoid, and because `tests/test_x509_pathlen_citations.py`
(now committed) is the concrete countermeasure this audit argues for: verify
every quotation against the fetched authoritative source, with the source's byte
count and digest pinned so a stale or substituted text cannot make the check
pass vacuously.

## Honest limits of this finding

SPEC-2's own report is an agent claim. I independently verified only the
`0xf93e00` constant and the existence of the §4.2.1 text by fetching RFC 8949
myself. The 29-of-29 count, the vacuity percentages and the `rev-2026-0018`
review-failure claim are **recorded as agent-reported and not independently
re-verified by the orchestrator**.
