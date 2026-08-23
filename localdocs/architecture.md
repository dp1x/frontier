# Architecture

Frontier is a monorepo with three layers:

```
┌─────────────────────────────────────────────────────────────┐
│ Human layer: README, knowledge/notes/*.md (Obsidian-compatible) │
├─────────────────────────────────────────────────────────────┤
│ Machine layer (authoritative): YAML evidence graph +        │
│ missions queue + indices, cross-checked by validators       │
├────────────────────────────────────────────────────────-----┤
│ Deterministic machinery (src/frontier): ids, validate,      │
│ promotion, continuation, compute routing, scratch, execute  │
└─────────────────────────────────────────────────────────────┘
        ▲ agents operate through files + CLI + scratch runs ▲
```

## Components

- **`frontier.ids`** — stable ID allocation (`<prefix>-<year>-<seq>`, zero-padded
  4) and parsing; per-type-per-year counters derived from existing artifacts.
- **`frontier.validate`** — structural integrity. Per-document checks (required
  fields, enum statuses, ID/type agreement, terminal-state invariants,
  evidence-level rules) and repo-wide checks (ID uniqueness, dangling
  references, mission-directory/status consistency). `validate_repo` returns
  `ok`, `errors`, `warnings`; CI fails on any error.
- **`frontier.promotion`** — the promotion ladder as code. `can_promote_finding`
  requires the full chain (experiment → observation → reproducer → independent
  non-synthesizer review → deterministic verification).
- **`frontier.compute`** — hybrid router. Inputs: workload class
  (lightweight/medium/heavy), disk estimate, matrix needs, untrusted flag;
  host facts (scratch capacity, GitHub Actions availability). Outputs location
  (`local` / `github-actions` / `escalate` / `blocked`) and isolation level.
- **`frontier.scratch`** — disposable workspace management: root selection
  (`R:` ramdisk → `$FRONTIER_SCRATCH` → `.scratch/`), capacity inspection,
  init/clean of mission-scoped workspaces.
- **`frontier.execute`** — untrusted command execution inside a scratch
  workspace with a scrubbed environment (tokens, API keys, SSH/browser/cloud
  credentials removed), timeout handling, captured stdout/stderr/exit code.
- **`frontier.continuation`** — bounded automatic follow-up missions from
  terminal/inconclusive parents, justified only by cited unresolved evidence,
  deduplicated against existing objectives, generation-capped.
- **`frontier.status`** — human-facing status report assembled from the graph:
  no transcripts required.
- **`frontier.knowledge`** — Obsidian note rendering/writing with wikilinks.
- **`frontier.index`** — rebuilds `knowledge/indices/by-type.yaml` and
  `by-status.yaml` from all YAML objects.

## Data flow (one mission)

objective → `missions/pending/msn-*.yaml` → activated to `active/` → agents
produce hypotheses/experiments/observations/reproducers under `knowledge/` →
reviews + verification → finding promoted or rejected → mission reaches terminal
state → moved to `completed/` (or `archive/`) → follow-ups proposed through
`frontier.continuation` → notes rendered to `knowledge/notes/`.

## Design invariants

1. The machine layer is authoritative; prose never overrides structured status.
2. Everything durable is Git-tracked; everything transient is scratch.
3. Verification is deterministic and re-runnable from committed commands.
4. No model/provider names are load-bearing anywhere in the protocol.
5. Schemas in `localdocs/schemas/` document the contracts enforced by code.

## Extension points

- New domain track = new top-level dir + verification adapter description in
  `workflows/` after passing the charter's core test.
- New artifact type = new prefix in `frontier.ids.PREFIXES`, schema file,
  validator rules, index inclusion.
