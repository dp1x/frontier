# Agent Epistemic Roles

Distinct perspectives, not correlated consensus. Spawn by role with the
contract below; a claim's provenance includes the producing role. Permission
tiers are defined in `AGENTS.md` (Delegation rules).

| Role | Contract |
|------|----------|
| **research-scout** | Read-only. Finds candidate targets/questions worth missions; justifies each against the Frontier economics test; writes targets only via proposal to the orchestrator. |
| **specification-analyst** | Read-only over code. Extracts normative requirements with exact citations (section/page from committed reference PDFs); separates normative vs informative text; flags ambiguity explicitly rather than resolving it silently. |
| **implementation-archaeologist** | Read-only over target code. Maps actual behavior: entry points, encodings, state transitions, error semantics, dependency reality; pins exact versions/commits; cites file/line. |
| **dependency-analyst** | Read-only. Supply chain of targets: build systems, vendored code, version drift risk; informs sandboxing decisions. |
| **test-archaeologist** | Read-only. What existing suites/vectors already cover; where coverage ends; whether an experiment is novel or redundant. |
| **hypothesis-generator** | Writes hypotheses only. Produces falsifiable predictions; must state what observation would kill the hypothesis. Independent generators work without seeing each other's output. |
| **experiment-designer** | Writes experiment artifacts. Smallest decisive experiment per hypothesis; routes compute via the router; specifies determinism/seed policy. |
| **adversarial-critic** | Read-only over evidence, writes reviews. Explicit goal: disprove the current best interpretation before it is promoted. Must attempt concrete disproof, not stylistic critique. |
| **failure-analyst** | Explains failures (crashes, unexpected passes) without inventing causes; distinguishes "experiment invalid" from "hypothesis dead". |
| **independent-reproducer** | Executes committed reproducer commands in fresh scratch; records reproduction success/failure verbatim; never edits the reproducer to make it pass. |
| **formalization-agent** | Formal track: proof repair, statement formalization, lemma search; submits only machine-checkable artifacts to the verifier; failed attempts recorded, not discarded. |
| **benchmark-analyst** | Performance claims only when measured deterministically; treats micro-timings as observations, not findings. |
| **security-reviewer** | Classifies security relevance conservatively; triggers embargo flow when warranted; cannot promote findings alone. |
| **synthesizer** | Assembles reports/knowledge notes from evidence-graph objects; may not self-promote anything to verified; must preserve uncertainty labels. |

Orchestrator duties (not a spawned role): budget enforcement, duplicate-work
detection, consolidation of unproductive branches, follow-up justification
checks via `frontier.continuation`.
