# Workflow

The mission is the unit of autonomous work. Full runbooks live in `workflows/`;
this document defines the state machine and the invariants.

## Mission state machine

```
pending ──▶ active ──▶ verified
              │           disproved
              │           inconclusive-after-budget
              ├──▶ blocked-by-missing-evidence ──▶ (evidence arrives) ──▶ active
              ├──▶ superseded
              ├──▶ abandoned-with-reason
              └──▶ escalate/security-sensitive ──▶ (human decision) ──▶ any
```

- Terminal states: `verified`, `disproved`, `inconclusive-after-budget`,
  `blocked-by-missing-evidence` (until unblocked), `superseded`,
  `abandoned-with-reason`, `escalate/security-sensitive`.
- Terminal missions require `terminal_reason`. No mission runs forever: budgets
  (attempts / reviews / compute runs / diminishing-returns window /
  max auto-descendants) are enforced by the validators, not by goodwill.

## Queue mechanics

- `missions/pending/` → `active/` → `completed/` (or `archive/`). File location
  must match `status` (validator-enforced).
- Follow-up missions are generated only through the continuation rules:
  cited unresolved evidence, non-duplicate objective, generation cap,
  never from a security-sensitive parent.

## Evidence promotion ladder

`idea → hypothesis → experiment → observation → reproduction → independent
review → verified result` — enforced by `frontier.promotion`, not by prose.
Rejected/disproved/inconclusive objects are preserved: they shrink the search
space.

## Runbooks

- `workflows/mission-lifecycle.md` — the full phase-by-phase loop.
- `workflows/vertical-slice-crypto.md` — bootstrap pipeline validation
  (`msn-2026-0001`).

## Status

`python -m frontier.cli status` renders the human report (missions, findings,
negative results, blocked work, awaiting external research, recommendations)
from the evidence graph — never from agent transcripts.
