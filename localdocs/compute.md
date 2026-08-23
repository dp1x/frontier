# Compute Policy

Decision mechanism, not vibes. Route every execution through
`frontier.compute.route(JobSpec, HostFacts)` and record the decision in the
experiment artifact.

## Classes

| Class | Definition | Default route | Isolation |
|-------|-----------|---------------|-----------|
| lightweight | CPU/RAM/disk footprint insignificant vs host; seconds-scale, deterministic (small crypto tests, parser tests, Lean checks, tiny compiler examples, unit tests) | local scratch | env-scrubbed scratch workspace |
| medium | substantial compilation, cross-platform matrices, moderate fuzzing, longer suites, benchmarks, platform comparisons | GitHub Actions public runners | runner-provided; no secrets on untrusted branches |
| heavy | genuinely exceeds both of the above | escalate to external compute (requires explicit justification recorded on the mission) | mechanism chosen per job |

## Rules

- Local lightweight jobs prefer `R:` (ramdisk) so SSD writes stay near zero.
  Fall back: `$FRONTIER_SCRATCH` → `<repo>/.scratch/`.
- Inspect capacity before large local operations
  (`ensure_capacity`); when short, block locally and reroute rather than
  thrash the host.
- GitHub Actions is a tool, not an ideology: don't use it when a local run is
  cheaper, simpler, and small; do use it when it avoids local CPU/heat/RAM/SSD
  cost. Public runners get no secrets; PR-triggered workflows must not leak
  environment material.
- Every execution artifact records: where it ran, isolation used, environment,
  version/commit tested, seed policy, outcome.
- Escalations are rare and explicit; if a "heavy" claim can't justify itself,
  it's medium.

## Environment notes (this host, 2026-08)

- Windows 11, PowerShell. Repo venv: `.venv\Scripts\python.exe` (Python 3.11.15,
  uv-managed base). `python` on PATH points at a foreign interpreter without pip;
  scoop `python3` is broken; `uv.exe` itself not installed.
- `R:` exists as RAM-disk (~4 GB free at init). Treat as disposable.
- No Docker assumed present; use env-scrubbed scratch until a stronger sandbox
  is provisioned (see security.md).
