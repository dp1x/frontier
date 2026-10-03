# Deliberately excluded material

Two untracked paths sit in the working tree and are **intentionally not staged and
not committed**. This file records why, so the exclusion is a decision rather than
an oversight, and so a future session does not "clean up" the tree by sweeping
them into a commit.

`.gitignore` is law per `AGENTS.md`. These two paths are not gitignored — they are
simply never `git add`ed, and this file documents the intent.

---

## 1. `.freebuff/`

**Contents:** a single file, `project-id`, containing the UUID
`cea3bfda-83d0-43ef-992b-9a5b15241b7e` (37 bytes).

**What is known:** nothing about its origin. The string "freebuff" appears nowhere
else in this repository. It is not Frontier tooling output — no Frontier code,
workflow, or script writes it. It is not referenced by any artifact.

**Why it is left alone:**

- Deleting unidentified user data is not a safe default. It may belong to a tool
  the human runs that is not part of this repository.
- Adding it to `.gitignore` would be a decision to disown it permanently, and we do
  not yet know what it is.

**Resolution needed from the human:** if you recognise it, this becomes a one-line
`rm -rf .freebuff` or a `.gitignore` entry. Until then it stays.

---

## 2. `ai-io/pycose_deterministic_cbor/`

**Contents:** 5 files, ~77 KB — Qwen research transcripts (`turn_1` through
`turn_3`), pasted by the human.

**Why it is NOT evidence:**

- It has no prompt/mission frontmatter, so it is not a paired `ai-io/outputs/`
  artifact under the `ai-io` rules. `ai-io/prompts/README.md` records this
  explicitly.
- `AGENTS.md` requires external-research material to be extracted, traced to
  primary sources, and independently verified before it influences anything. These
  transcripts were never promoted through that path.
- Its Turn 2 output labelled itself "VERIFIED (Library Bug)" and was **retracted by
  Turn 3** after retrieval failed.

**Two concrete errors this session measured, which are why it must not be cited:**

1. Turn 3 marked the `phdr_encoded` question "UNRESOLVED" and speculated the
   callers could not work around it. It is answerable locally in one grep of
   `cosebase.py`, and the answer is that `phdr_encoded` **is** the shipped upstream
   fix for pycose issue #82.
2. Turn 2 cited the encoder as living in `pycose/messages/cosemessage.py`. It is in
   `pycose/messages/cosebase.py:136`. Wrong file.

The `v1.1.0` → commit `a61ac735a53925612ec38234f9c944ab71b6782b` mapping in the
transcript **was independently confirmed** against the GitHub API, so the file is
not worthless — but that fact was verified against the primary source, not taken
from the transcript.

**Why it is still not committed:** committing it would place untrusted, partly
retracted material inside the evidence graph where a future reader could mistake it
for a reviewed artifact. The salvageable facts are already recorded in
`knowledge/reviews/rev-2026-0017.yaml` and `rpt-2026-0016.yaml`, sourced to the
primary URLs.

**Resolution needed from the human:** commit as clearly-labelled raw input, or
delete. Either is fine; silent ingestion is not.

---

## 3. `.scratch/`

**Already gitignored** (`.gitignore:29`). Previously held the audit reports and
specifications that this session's evidence chain depended on — that was a
mistake, and it is corrected: those 12 files were moved into
`knowledge/process-findings/audit-2026-10-03/` and
`knowledge/process-findings/spec-2026-10-03/` and are now committed.

**Standing rule this exposed:** anything that informs a verdict recorded in the
knowledge graph must live in the knowledge graph or another committed path.
`.scratch/` is for scratch, not for the basis of a `verified_conclusion`.