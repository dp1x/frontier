# Frontier

**Frontier is an autonomous, AI-amplified frontier technical research
organization whose defining resource is abundant machine intelligence.**

Central thesis:

> Use abundant machine intelligence to search enormous intellectual spaces;
> use ordinary commodity computation only to perform the decisive physical
> experiment.

Frontier exploits the widening asymmetry between *intelligence availability*
(frontier-grade reasoning deployable in large parallel quantities) and
*physical compute availability* (used selectively, economically,
deterministically, to decide what is actually true).

## How it works, in one paragraph

A human gives a high-level objective ("investigate how public ML-KEM
implementations treat the FIPS 203 input-checking requirements"). The system
decomposes it into a **mission**, dispatches parallel agents with distinct
epistemic roles (specification analyst, implementation archaeologist, hypothesis
generator, adversarial critic, independent reproducer, …), turns promising
theories into small deterministic experiments, runs those experiments in
isolated scratch workspaces or free CI, has independent agents try to *disprove*
every claim, promotes only what survives the promotion ladder
`idea → hypothesis → experiment → observation → reproduction → independent
review → verified result`, records everything as structured, cross-referenced,
Git-committed artifacts, and updates an Obsidian-compatible knowledge base.
Model output is never evidence. The experiment decides.

## Domains

Initial tracks, chosen because their intellectual search space is much larger
than their decisive experiment:

- `crypto/` — cryptography implementation, interoperability, protocol, and
  engineering questions (PQC included); never reinventing generic encryption apps.
- `compilers/` — language-systems differential and conformance analysis across
  GCC / Clang / MSVC / runtimes.
- `formal/` — proof repair, formalization, lemma discovery, conjecture work with
  a formal verifier as the trusted judge.
- `interop/` — protocol/data-format specification-vs-implementation behavior.

New domains enter only if they pass the core test: *Is the intellectual problem
substantially harder than the physical experiment? Can abundant parallel
reasoning create value that ordinary compute can verify? Can results be made
reproducible and externally inspectable?*

## Repository orientation

| Path | Purpose |
|------|---------|
| `AGENTS.md` | Operational constitution for every agent (read this first). |
| `missions/` | Machine-readable mission queue: `pending/`, `active/`, `completed/`, `archive/`, `embargoed/`. |
| `knowledge/` | Filesystem evidence graph: targets, specifications, implementations, hypotheses, experiments, observations, reproducers, reviews, verifications, findings, conjectures, proofs, reports, process findings, notes, indices. |
| `ai-io/` | Narrow human-mediated external deep-research interface (`prompts/` out, `outputs/` back in, treated as untrusted input). |
| `crypto/ compilers/ formal/ interop/` | Domain workspaces for experiments, reproducers, and domain tooling. |
| `roles/` | Epistemic role cards for agent delegation. |
| `workflows/` | Mission lifecycle and per-track pipeline runbooks. |
| `src/frontier/` | Deterministic machinery: IDs, validation, compute routing, sandboxed execution, status. |
| `tests/` | Executable contract for all of the above. |
| `localdocs/` | Architecture, workflow, compute, security, external-research docs, schemas, reference PDFs. |

## What you can trust here

Only what carries evidence. A finding marked `verified` has an executable
experiment, a recorded observation, a reproducer, an independent review, and a
verification by deterministic means attached. Everything else — however
confident its prose — is hypothesis, interpretation, or assumption, and is
labeled as such. Negative results (rejected hypotheses, disproven conjectures)
are preserved deliberately because they shrink future search spaces.

## Status

Ask the CLI once implemented:

```
python -m frontier.cli status        # active/pending missions, findings, blocked work
python -m frontier.cli validate      # structural integrity of the whole repo
```

The repository is intentionally honest about what it is not: no guaranteed
discoveries, no guaranteed novelty, no promises of profitability. The valuable
outputs are executable reproducers, verified findings, upstream fixes, formal
proofs, and analyses that survive scrutiny.

## License

MIT — see [LICENSE](LICENSE). Research artifacts carry their own provenance
metadata inside each file.
