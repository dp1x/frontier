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
| `supersedes` | map | optional typed relations to artifacts this one corrects; see below |

### `supersedes`

The envelope's one optional field. `supersedes` states that THIS artifact
corrects, withdraws, or replaces a NAMED artifact — the direction is always
from the correcting artifact to the corrected one. Relations are typed, and
the type is the relation:

```yaml
supersedes:
  corrects: [obs-2026-0043]   # target's wording/scope was wrong; substance may survive
  withdraws: [fnd-2026-0014]  # target's claim is dead and nothing of it carries
  replaces: [msn-2026-0017]   # this artifact takes over the target's entire question
```

All three keys are optional, but an artifact with a non-empty `supersedes`
needs at least one, and every listed ID must resolve like any other link
(dangling supersession references fail validation). Nothing requires the
field: it is absent on all artifacts written before it existed, and adding it
is opt-in per artifact.

The four words are NOT interchangeable:

- `corrects` — the target made an error (wrong scope, wrong locator, wrong
  count) but part of it stands. Use it when the target's `status` stays as it
  is.
- `withdraws` — the target asserted something now known to be false. Use it
  when the target's `status` becomes `withdrawn`, `rejected`, or `superseded`.
- `replaces` — this artifact takes over the target's subject wholesale. Use
  it when the target becomes `superseded` and this artifact is its successor.

`supersedes` does not change the target's `status`: withdrawal is recorded in
`status`, and `supersedes` records *who did it and in what capacity*, which is
the information the corpus previously kept only in prose.

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
