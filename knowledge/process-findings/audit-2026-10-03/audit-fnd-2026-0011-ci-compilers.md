<!-- Preserved from .scratch/ (gitignored, not durable). Source of the
     verdicts recorded in knowledge/reviews/rev-2026-0018.yaml.
     Original filename: audit_fnd_0011.md -->

# Adversarial Audit — `fnd-2026-0011`

**Target:** `knowledge/findings/fnd-2026-0011.yaml` (status `verified_conclusion`, disclosure `public`)
**Auditor role:** adversarial-critic (disproof attempt)
**Audit date:** 2026-10-03
**Finding age at audit:** 34 days (created 2026-08-30T09:15:00Z)
**Repo HEAD:** `07607e3` (2026-10-02)

---

## 1. VERDICT

**CONFIRMED-STILL-TRUE** — the core empirical claim survives disproof, and it is *not* stale.

I attempted to break this finding four ways and failed to break its central claim. The specific
failure mode I predicted (a true-but-stale version pin, because `ubuntu-latest` moves) did
**not** materialize: `ubuntu-latest` is still Ubuntu 24.04 and still ships clang 18.1.3 and
gcc 13.3.0, byte-for-byte as recorded.

However, the finding is promoted to `verified_conclusion` on an evidentiary base that has
**rotted since promotion**, and it carries one demonstrably false sub-claim. Three material
defects are documented in §6. The headline verdict is confirmed; the artifact needs
correction before it is quoted as-is.

| Sub-claim | Status |
|---|---|
| `ubuntu-latest` ships clang 18.1.3 + gcc 13.3.0 | **VERIFIED — current** |
| clang 18.x does not support `#embed` (any flag) | **VERIFIED** |
| gcc 13.3.0 does not support `#embed` | **VERIFIED** (by version; see §5 nuance) |
| Need clang-19+ to reproduce LLVM #212075 / #219332 | **VERIFIED — and understated** |
| "Reproducible by anyone with clang-19+" | **REFUTED** (needs an *assertions* build) |
| Reproducer `rpr-2026-0011` still runs as written | **REFUTED** — no gcc cell remains |
| Primary evidence (26 TSV cells) recoverable | **REFUTED** — never committed, ramdisk gone |

---

## 2. Current compiler versions — VERIFIED

Source (fetched 2026-10-03):
- `https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2404-Readme.md`
- `https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2204-Readme.md`
- `https://raw.githubusercontent.com/actions/runner-images/main/images/ubuntu/Ubuntu2604-Readme.md`
- `https://github.com/actions/runner-images/blob/main/README.md`

**`ubuntu-latest` → Ubuntu 24.04 x64** (confirmed from the runner-images README image table,
which maps YAML label `ubuntu-latest` or `ubuntu-24.04` → Ubuntu 24.04).

| Image | Deployed | Clang | GNU C/C++ | Status |
|---|---|---|---|---|
| **Ubuntu 24.04** = `ubuntu-latest` | `20260927.320.1` | 16.0.6, 17.0.6, **18.1.3** | 12.4.0, **13.3.0**, 14.2.0 | current `ubuntu-latest` |
| Ubuntu 22.04 | `20260927.309.1` | 13.0.1, 14.0.0, 15.0.7 | 10.5.0, 11.4.0, 12.3.0 | deprecating (dead 2027-04-17) |
| Ubuntu 26.04 | `20260927.149.1` | 20.1.8, 21.1.8, 22.1.2 | 13.4.0, 14.3.0, **15.2.0** | GA; **`ubuntu-latest` in Nov 2026** |

The finding's pins — **clang-18.1.3 and gcc-13.3.0** — are **exactly correct today**. Not stale.

> **Forward-looking staleness cliff (dated, imminent).** The runner-images README carries the
> announcement *"[Ubuntu] `ubuntu-latest` label will use Ubuntu 26.04 in November 2026"*
> (issue #14748). Ubuntu 26.04 ships **clang 22.1.2 and gcc 15.2.0**. At that point:
> - the `#embed` claim **becomes false** for the default toolchain (gcc 15.2.0 implements
>   `#embed`; clang 22 does too);
> - the finding's prescribed remedy ("gcc-15+ via a PPA") becomes **obsolete** — gcc-15 is in
>   the base image, no PPA required.
>
> Every workflow in `.github/workflows/` uses unpinned `runs-on: ubuntu-latest`
> (`ci.yml`, `compiler-alias.yml`, `formal.yml`, `clang-embed-crash.yml`). So this is a
> **~1-month-away scheduled invalidation**, not a hypothetical. The finding is currently
> accurate; it is also on a known collision course with a published announcement.

---

## 3. Exact `#embed` support status — VERIFIED against primary sources

### clang 18.1.3 → **NO `#embed` support**

- Clang 18.1.0 release notes, *C23 Feature Support* section
  (`https://releases.llvm.org/18.1.0/tools/clang/docs/ReleaseNotes.html`) enumerate N3007,
  N2508, N2940, `<stdckdint.h>`, `-std=c23`, `counted_by`, N2653. **`#embed` is absent.**
- Clang 19.1.0 release notes, *C23 Feature Support*
  (`https://releases.llvm.org/19.1.0/tools/clang/docs/ReleaseNotes.html`):
  > "Clang now supports N3017 `#embed` - a scannable, tooling-friendly binary resource
  > inclusion mechanism."

**This directly refutes the disproof hypothesis I was asked to test.** The hypothesis was
"clang-18.1.3 may have `#embed` behind `-std=c2x`/`-std=c23` in later point releases." It does
not. `#embed` first shipped in **clang 19.1.0**. Clang 18 *does* accept `-std=c23` and
`-std=c2x` (aliases) — so the flag was accepted and the lexer reached the directive — but the
directive itself is unknown. There is no flag that enables it in 18.x. Point releases 18.1.1+
are bugfix-only and did not add it.

### gcc 13.3.0 → **NO `#embed` support**

- GCC 15 changes page (`https://gcc.gnu.org/gcc-15/changes.html`), under *C* → *"Some more C23
  features have been implemented:"*:
  > "`#embed` preprocessing directive support."
- GCC 14 changes page (`https://gcc.gnu.org/gcc-14/changes.html`) lists C23 work (BitInt,
  `<stdckdint.h>`, redefinition rules) and adds `-std=c23` / `-std=gnu23` — **no `#embed`**.

So: **gcc 14 does not support `#embed`; gcc 15 is the first.** The finding's "gcc-15+" remedy
is the correct boundary.

### `-std=c23` flag status (attack point — the finding is CORRECT here)

GCC 14 changes page: *"`-std=c23`, `-std=gnu23` … are equivalent to the previous options
`-std=c2x`, `-std=gnu2x`."* This confirms `-std=c23` arrived in **GCC 14**, not 13. So
gcc 13.3.0 legitimately emits `unrecognized command-line option '-std=c23'`, exactly as
`obs-2026-0036` records. **The observation's interpretation is accurate.**

### Summary table

| Compiler | `-std=c23` | `#embed` | Source |
|---|---|---|---|
| clang 18.1.3 | **accepted** (added in 18.1.0; `-std=c2x` alias) | **NO** — any flag | clang 18.1.0 RN (absent) + clang 19.1.0 RN (added) |
| gcc 13.3.0 | **rejected** — `-std=c2x` only | **NO** | gcc-14 changes (flag), gcc-15 changes (feature) |
| clang 19.1.0 | accepted | **YES** | clang 19.1.0 RN |
| gcc 15.x | accepted; **C23 is the default** (`-std=gnu23`) | **YES** | gcc-15 changes |

**Finding's core technical claim: VERIFIED. Not refuted.**

---

## 4. Downstream consequence — VERIFIED, and the finding *understates* it

The claimed consequence is: Frontier's default image cannot reproduce LLVM #212075 or #219332
without an explicit clang-19+ / gcc-15+ install. I fetched both issues.

**LLVM #212075** — `https://github.com/llvm/llvm-project/issues/212075`
- Title: assertion ``(Params || CurTok.is(tok::eod)) && "expected success or to be at the end of the directive"`` failed.
- Opened **2026-07-25** by k-arrows. Status **Open**.
- Labels include **`regression:19` "Regression in 19 release"** and `embed`, `clang:frontend`.
- Backtrace frame: `clang::Preprocessor::HandleEmbedDirective` — matches the finding's naming.
- Reproducer: `#embed <foo> limit(defined(bar)),` — matches the harness stimulus `iss212075_min`.

**LLVM #219332** — `https://github.com/llvm/llvm-project/issues/219332`
- Title: crash (out of memory) when `#embed __FILE__` uses a prefix referring to a previous embedded array.
- Opened **2026-08-27** by k-arrows. Status **Open**.
- Labels: `crash-on-invalid`, `embed`, `generated by fuzzer`.
- `LLVM ERROR: out of memory / Allocation failed`; frames
  `BumpPtrAllocatorImpl<...>::AllocateSlow` → `InitListExpr::updateInit` — matches the
  finding's naming.
- Reproducer matches the harness stimulus `iss219332_min` **exactly**.

Both bugs are real, both are genuinely post-clang-18, and both require `#embed` support to
reach. **The consequence holds.** `#212075` being labelled `regression:19` *strengthens* the
clang-19+ requirement.

**One overclaim, though.** Both reports reproduce on **`clang-assertions-trunk` on Compiler
Explorer** (visible in the command lines: `/opt/compiler-explorer/clang-assertions-trunk/`).
Assertions are compiled out of release builds. The finding asserts the bugs are
"reproducible by anyone with clang-19+" and that installing `clang-19` from apt.llvm.org
will make them crash. **A distro `clang-19` is a release build; `HandleEmbedDirective` will not
assert.** The actual requirement is **clang 19+ built with assertions (or trunk)**. The
`ebddd71` workflow change installs release clang-19, so the finding's own predicted outcome —
"at least the 2 known_bug_repro stimuli should crash clang-19" — is **unlikely to materialize as
written**. See §6.2.

**Verdict on consequence: VERIFIED (INFERRED for the gcc half — see §5).**

---

## 5. A precision gap: the gcc cells never tested `#embed`

`run_embed_matrix.sh` line 40 hardcodes:

```bash
timeout 30 "$CLANG_BIN" -std=c23 -c "$file" -o /tmp/${id}.o 2> "$stderr_file" > /dev/null
```

For gcc 13.3.0, `-std=c23` is an **unrecognized option**, so every gcc invocation aborts at
command-line parsing. **Zero gcc cells ever reached the preprocessor or attempted to parse an
`#embed` directive.** The "gcc rejects every stimulus with `rejects_with_error`" result is a
*harness/flag incompatibility*, not a measurement of gcc's `#embed` handling.

The underlying claim ("gcc 13.3.0 has no `#embed`") is nonetheless **true and independently
confirmed** from the GCC release notes (§3) — so this is a rigor/precision defect in the
evidence chain, **not** a factual error. Re-running with `-std=c2x` would produce a genuine
per-cell `rejects_with_error` and make the gcc half empirical.

**Second precision gap.** The harness sets `ulimit -v 2097152` (2 GB) before every stimulus.
For the #219332 OOM reproducer this converts an unbounded allocation failure into a
*deliberately induced* allocation failure under a memory cap. A `crashes_oom` verdict there is
partly an artifact of the harness's own limit, not solely evidence of a compiler defect. This
does not invalidate the finding (the direction of the claim is unchanged) but should be
disclosed if the matrix is ever re-run and compared cell-by-cell.

---

## 6. Defects requiring correction

### 6.1 The reproducer is broken as written — material

`rpr-2026-0011` step_5 instructs:

```
cat R:/clang-embed/clang-embed-crash-gcc-default-<run_id>/gcc-default/embed_crash_matrix.tsv
```

There is no `gcc-default` cell in the workflow any more. Git history of
`.github/workflows/clang-embed-crash.yml`:

| Commit | Date (local +0400) | Change |
|---|---|---|
| `1870b6f` | 2026-08-30 14:36 | original; matrix had `clang-19`, **`gcc-15`** (via `ppa:ubuntu-toolchain-r/test`) |
| `feb01d8` | 2026-08-30 14:38 | dropped the PPA; `gcc-15` → **`gcc-default`** (`bin: gcc`) |
| `91c31ad` | 2026-08-30 14:44 | dropped `sudo` |
| `a22bf2e` | 2026-08-30 14:51 | use preinstalled system compilers (`clang-default`, `gcc-default`) |
| `f4db973` | 2026-08-30 14:55 | clean rewrite |
| `ebddd71` | 2026-08-30 15:06 | **deleted `gcc-default` entirely**, added `clang-19` (apt.llvm.org) |

Current matrix = `{clang-19, clang-default}` only. A re-run today yields **26 cells… no:
2 compilers × 13 stimuli = 26 cells only if gcc is present; today it is 13 + 13 = 26 if you
count the clang-19 and clang-default cells — but the `gcc-default` artifact directory the
reproducer cats will never exist.** Anyone following `rpr-2026-0011` verbatim gets a missing
file and no signal.

**Recommendation:** drop step_5, or re-add a `gcc-default` cell (cheap, and it restores the
cross-implementation check `msn-2026-0012` listed as an acceptance criterion).

### 6.2 The confirming run never landed — the promotion rests on an absence

`vrf-2026-0012` records:

> "follow_up_run: Run 33308097591 (in progress) adds clang-19 from apt.llvm.org. Expected
> outcome: at least the 2 known_bug_repro stimuli crash clang-19"

`fnd-2026-0011` repeats this as `second_gha_run`. **No result for run 33308097591 is recorded
anywhere in the repo**, and per §4 the expectation it encodes is probably wrong (release
clang-19 will not fire the assertions). So the finding reached `verified_conclusion` on the
strength of a *negative* result (compilers lack support) plus an *unfulfilled prediction* for
the positive one. That is legitimate for the environment-gap claim as scoped — but
`rev-2026-0011` scored `SUPPORT` on all four axes without noticing that its own confirming run
was still open, which is a review gap.

### 6.3 Primary evidence is not durable — material for an "environment" finding

The AGENTS.md contract requires durable, committed artifacts. For this finding:

- Every cited TSV path is on `R:` (ramdisk), which AGENTS.md explicitly declares
  non-durable. **`R:\clang-embed` no longer exists on this machine** (verified 2026-10-03).
- **No embed TSV is tracked in git.** `git ls-files` shows `compilers/embed/run_embed_matrix.sh`
  but nothing under `compilers/embed/reports/`. `git check-ignore` returns non-zero, i.e. the
  directory is neither ignored nor populated — it simply has no committed content.
- This is anomalous for this repo: **every other experiment family commits its TSVs**
  (`crypto/mlkem-input-checks/reports/*.tsv` ×16, `crypto/frost-cross-impl/results/matrix.tsv`,
  `cbor-cross-impl/results/matrix.tsv`, `compilers/alias-diff/reports/*.tsv`,
  `interop/protocol-placement/rustls_loopback/reports/*.tsv`, …). The embed matrix is the
  single exception.
- The harness itself is fine and deterministic (fixed heredocs, no RNG, no network after the
  install step). Committing one `embed_crash_matrix.tsv` per compiler would close the gap.

### 6.4 Corrupted provenance path — material integrity defect

The audited artifact cites a path that exists nowhere else in the repo:

```
# fnd-2026-0011.yaml and vrf-2026-0012.yaml:
R:/claw-embed/claw-embed-crash-clang-default-33307657900/claw-default/embed_crash_matrix.tsv

# obs-2026-0036.yaml and rpr-2026-0011.yaml (the correct form):
R:/clang-embed/clang-embed-crash-clang-default-33307657900/clang-default/embed_crash_matrix.tsv
```

`claw-embed` / `claw-default` vs `clang-embed` / `clang-default` — a dropped `g` in the
directory, artifact, and compiler subdirectory names. The same garbled path with
`artifact_size_bytes: 2727` appears in `vrf-2026-0012` as well. **The finding under audit
propagated a typo'd path into its verification record.** For a `verified_conclusion` artifact
whose entire value is being a citable measurement, the citation must be exact.

(Timeline note, not a finding-defect: workflow commits are timestamped 10:36–11:06 UTC while
`obs-2026-0036.created_at` is 09:05 UTC and `fnd-2026-0011.created_at` is 09:15 UTC — i.e. the
artifacts claim to predate the workflow state they describe. `ebddd71` had already removed the
gcc cell by then. These `created_at` values are synthesizer-authored and are unreliable;
I could not determine which workflow revision produced run 33307657900 without
`gh run view`, which I did not execute. Flagging as COULD-NOT-DETERMINE rather than asserting
a contradiction.)

### 6.5 Minor — overclaim in the summary

> "reproducible by anyone with clang-19+"

Correct form: reproducible with a **clang 19+ assertions build** (or trunk), per the
`clang-assertions-trunk` command lines in both upstream reports. The apt.llvm.org
`clang-19` release package will very likely not assert.

---

## 7. Does the repo corroborate or contradict?

**Corroborates (weakly).** Grep for `#embed` across `.github/` returns exactly one hit — the
comment header of `clang-embed-crash.yml`. No workflow anywhere in the repo compiles `#embed`
successfully through a system toolchain. `compiler-alias.yml` installs `gcc clang` from apt and
prints versions but targets C11 6.5p6-7 aliasing, never `#embed`. **No contradiction exists
in-repo.**

**Corroborates (negatively, and this is the real tell).** The workflow's own evolution —
original `gcc-15`+PPA and `clang-19` cells, repeatedly deleted in favour of preinstalled
system compilers (`feb01d8`, `f4db973`), then the gcc cell dropped again (`ebddd71`) — is an
independent, in-repo record of exactly the capability gap `fnd-2026-0011` describes. The
finding's central claim is consistent with how Frontier actually behaved.

---

## 8. Safe to disclose, or correction needed?

**Disclosure: `public` is correct and should be retained.** Nothing here is security-sensitive.
The upstream bugs are already public on the LLVM tracker, the finding is explicitly scoped to
*Frontier's environment* and not to the bugs, and there is no embargo, no vulnerability
claim, and no undisclosed finding. `rev-2026-0011`'s assessment that this is an
`environment-capability-gap` rather than a vulnerability is correct.

**But corrections are needed before the artifact is quoted externally or relied on
internally.** Ranked:

1. **Fix the garbled provenance path** in `fnd-2026-0011.yaml` and `vrf-2026-0012.yaml`
   (`claw-*` → `clang-*`). Smallest edit, highest integrity payoff.
2. **Commit the embed matrix TSV(s)** to `compilers/embed/reports/` so the finding rests on
   committed evidence rather than a vanished ramdisk, matching every other experiment family
   in this repo. If re-running is too costly, mark the primary evidence as
   `evidence_retained: no` and say so explicitly rather than implying reproducibility.
3. **Fix `rpr-2026-0011` step_5** (references a `gcc-default` cell that no longer exists),
   or restore a gcc matrix entry.
4. **Correct "reproducible by anyone with clang-19+"** → requires an assertions build.
5. **Record the status of run 33308097591** (result or explicit abandonment), and correct the
   expectation that a release `clang-19` will assert.
6. **Add an expiry/refresh note** to the finding: "`ubuntu-latest` moves to Ubuntu 26.04 in
   November 2026, which ships gcc 15.2.0 and clang 22.1.2 — this finding must be re-verified
   or retired at that point." Given every workflow uses unpinned `ubuntu-latest`, and given
   AGENTS.md's compute-routing rules, **pinning `runs-on: ubuntu-24.04` for compiler-sensitive
   work is the durable fix** and would have prevented this class of rot entirely.

---

## 9. Epistemic marking

| Statement | Mark |
|---|---|
| `ubuntu-latest` = Ubuntu 24.04 shipping clang 18.1.3 / gcc 13.3.0, on 2026-10-03 | **VERIFIED** (primary source: runner-images manifests, image `20260927.320.1`) |
| clang 18.x has no `#embed` under any `-std` flag | **VERIFIED** (clang 18.1.0 + 19.1.0 release notes) |
| gcc 13.3.0 / 14 have no `#embed`; gcc 15 does | **VERIFIED** (gcc.gnu.org changes pages) |
| `-std=c23` absent in gcc 13, added in gcc 14 | **VERIFIED** (gcc-14 changes page) |
| LLVM #212075 and #219332 are real, open, and post-clang-18 | **VERIFIED** (fetched both issues) |
| Consequence: default image cannot reach those bugs | **VERIFIED** |
| Consequence, **gcc** half (no `#embed` reached empirically) | **INFERRED** — version-based, not measured (§5) |
| "Reproducible by anyone with clang-19+" | **REFUTED** — needs assertions build |
| Which workflow revision produced run 33307657900 | **COULD-NOT-DETERMINE** (needs `gh run view`; not executed) |
| Result of follow-up run 33308097591 | **COULD-NOT-DETERMINE** (no record in repo) |
| `gcc-15 via a PPA` remedy | **STALE-FORWARD** — obsolete once `ubuntu-latest` → 26.04 (Nov 2026) |
| `clang.llvm.org/docs/CStatus.html` | **404** (reported, not guessed) |

---

## 10. Summary

I could not disprove the finding. Its central empirical claim — the default GHA image ships
clang 18.1.3 and gcc 13.3.0 and neither implements C23 `#embed` — is **still exactly true on
2026-10-03**, 34 days after it was recorded, and is independently confirmed from primary
compiler-release sources rather than only from the GHA run. The `ubuntu-latest` staleness
failure mode I was told to expect did not occur, because `ubuntu-latest` has not yet moved to
Ubuntu 26.04.

The finding does, however, sit on a **dated collision course**: GitHub has announced
`ubuntu-latest` → Ubuntu 26.04 for November 2026, and that image ships gcc 15.2.0 (which
implements `#embed`) and clang 22.1.2. Frontier uses unpinned `ubuntu-latest` everywhere. The
claim is true today and scheduled to become false in about a month.

Separately, the artifact's evidentiary apparatus has decayed since promotion: the primary TSV
evidence was never committed to git and its ramdisk path is gone; the reproducer references a
matrix cell that was deleted from the workflow; the provenance path is corrupted; and the
summary overstates reproducibility. None of this refutes the finding, but it means the
artifact should be corrected rather than quoted as-is.
