# Schemas

Machine-readable contracts for Frontier artifacts. JSON Schema files here
document the contracts; `src/frontier/validate.py` enforces them in code
(structural checks + cross-reference + state-transition rules), because some
rules (dangling links, promotion evidence) are graph-level, not per-document.

Common envelope for every object:

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | `<prefix>-<year>-<seq4>`, prefix must match type |
| `type` | enum | one of the 15 core types |
| `status` | enum | type-specific vocabulary (see schemas) |
| `created_at` / `updated_at` | ISO-8601 UTC | |
| `summary` | string | one line |
| `epistemic_status` | enum | idea, assumption, hypothesis, observation, interpretation, verified_conclusion — must not overstate |
| `provenance` | object | `created_by{kind, role, model, tool}`, `sources[]`, `parent`, `generation` |
| `links` | map | typed arrays of artifact IDs; must resolve repo-wide |

Statuses by type (highlights):

- **mission**: pending, active, verified, disproved, inconclusive-after-budget,
  blocked-by-missing-evidence, superseded, abandoned-with-reason,
  escalate/security-sensitive. Terminal ⇒ `terminal_reason` required.
- **finding**: proposed, under-review, verified, rejected, disputed, stale,
  superseded, archived, escalate/security-sensitive. `verified` requires
  experiment+observation+reproducer+independent review+deterministic
  verification linked.
- **verification**: method ∈ executable | formal-verifier | differential |
  deterministic-script | reproduction — never agent-assertion.
- **review**: `independent` bool + role; synthesizer reviews cannot satisfy
  independent-review requirements for promotion.
- **experiment**: carries `compute_decision{location, isolation}` and
  reproducible command(s).
- **observation**: carries `environment{where, isolation, ...}` and raw captured
  results.
