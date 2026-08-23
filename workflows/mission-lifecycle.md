# Workflow: Mission Lifecycle

## 1. Creation
A mission enters as `missions/pending/msn-YYYY-NNNN.yaml` — human objective or
machine-generated follow-up (must pass `frontier.continuation.evaluate_followup`).
Required fields per `localdocs/schemas/mission.schema.json`. Run
`frontier validate` before activation.

## 2. Activation (`pending → active`)
Move the file to `missions/active/`. Confirm the knowledge base has been
consulted: relevant targets, specs, findings, rejected hypotheses, unresolved
questions. Rediscovering a rejected line is a defect.

## 3. Swarm execution (inside budget)
Typical phase order, sized by complexity:

1. **Scout** — target discovery/refinement (`knowledge/targets/`).
2. **Specification analyst** — normative requirements with citations
   (`knowledge/specifications/`, committed PDFs preferred).
3. **Implementation archaeologist** — map actual behavior, APIs, encodings,
   state transitions, error semantics; pin exact versions.
4. **Test archaeologist** — what existing suites already cover.
5. **Hypothesis generators** (parallel, independent) — falsifiable predictions
   into `knowledge/hypotheses/`.
6. **Experiment designer** — smallest decisive experiments;
   `frontier.compute.route`; record decisions.
7. **Execution** — `frontier.execute.run_command` in scratch; observations to
   `knowledge/observations/`.
8. **Adversarial critics** (≥1, independent) — try to disprove.
9. **Independent reproducer** — re-run reproducers from committed commands.
10. **Verifier** — deterministic pipeline judgment (`knowledge/verifications/`).

Budget fields cap attempts, reviews, compute runs; the diminishing-returns
window stops no-progress grinding.

## 4. Synthesis & promotion
Synthesizer assembles report + finding draft. Promotion to `verified` only via
`frontier.promotion.can_promote_finding` (full evidence chain, independent
non-synthesizer review). Security-sensitive results divert to embargo per
`localdocs/security.md`.

## 5. Terminal transition
Set terminal status + `terminal_reason`; move file to `missions/completed/`
(or `archive/` for low-value closures). Render/update Obsidian notes
(`frontier.knowledge`). Rebuild indices. Commit coherent state.

## 6. Continuation
Follow-ups proposed via `frontier.continuation` only: cited unresolved
evidence, non-duplicate objective, below generation cap, never from a
security-sensitive parent. Else the mission ends.

## Status at any time
`python -m frontier.cli status` — missions by state, findings, negative
results, blocked work, awaiting external research, recommended next missions.
