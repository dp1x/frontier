# Workflow: Crypto Vertical Slice (bootstrap pipeline validation)

Runbook for `msn-2026-0001`. Purpose: prove the full pipeline end-to-end on a
small, real question. Research value is real but secondary to exercising the
machinery honestly.

## Phase 0 — Machinery green
`pytest` passes; `frontier validate` clean. (If the `src/frontier` package is
not yet implemented, that comes first — the tests define it.)

## Phase 1 — Spec grounding (no compute)
Spec analyst reads `localdocs/refs/fips203.pdf` §7.2/§4.2.1 (facts already in
`spc-2026-0001.yaml`) and derives the malformed-key oracle: for parameter set
with modulus q=3329 and ek length 384k+32, craft ek bytes whose decoded
coefficients include values ≥ q (e.g. 12-bit segments ≥ 3329), so the §7.1
round-trip fails while the length check passes.

## Phase 2 — Implementation archaeology (read-only + builds in scratch)
For each candidate (`imp-2026-0001..3`): pin exact released version; locate the
encaps entry point; determine from source whether the type/modulus checks run
at encaps or import time; record citations (file/line). Output:
implementation objects updated with verified versions + analysis notes.

## Phase 3 — Hypotheses (parallel, independent)
e.g. H1: "No candidate performs the §7.1 round-trip at Encaps."
H2: "At least one rejects non-canonical keys at import." Each with falsifiable
predictions. Adversarial critic attacks each hypothesis's reasoning first.

## Phase 4 — Experiments (lightweight, local scratch)
Per implementation × per crafted key: tiny driver (C harness against the
library) built and run via `frontier.execute.run_command` in an `R:` scratch
workspace. Record observation YAML per run (environment, stdout, exit code).
Expected experiment wall-time: seconds.

## Phase 5 — Differential table & classification
Assemble table: implementation × version × check-performed(yes/no/where) ×
behavior-on-malformed-key. Classify: implementations omitting the check are
**not automatically buggy** — FIPS 203 explicitly allows other-means assurance;
classify as compliant/plausible vs spec-violation only with evidence.

## Phase 6 — Review, reproduction, verification
Independent adversarial review of the classification; reproducer scripts
committed under `crypto/mlkem-input-checks/`; deterministic re-run by verifier
role; finding promoted only through `frontier.promotion`.

## Phase 7 — Knowledge update & closure
Notes rendered; negative results preserved (implementations that DO check are
findings too); follow-ups proposed via continuation rules; mission terminal.
