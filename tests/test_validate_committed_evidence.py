"""Enforcement of the compute-routing HARD RULE's evidence exception.

The rule carves out an exception for build products that ARE evidence -- it
names the Lean ``.olean`` files as the example.  Six artifacts claimed those
files were "committed", while ``.gitignore`` excludes ``formal/.lake/`` and
``git ls-files formal/.lake`` returns nothing, so the exception was being
reasoned from an existence that was false.  See ``obs-2026-0056``.

The check is deliberately narrow.  It fires only when one sentence both asserts
that evidence is committed and names a path carrying ``.olean`` that git does
not track.  Corrected prose, unrelated uses of "committed", and a bare
``.olean`` with no directory component are all left alone -- otherwise
recording the correction would itself become a validation error.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from frontier.validate import validate_repo


def _finding_with_note(root: Path, note: str) -> None:
    """Write a single finding whose ``note`` carries the claim under test."""
    import yaml

    doc = {
        "id": "fnd-2026-0001",
        "type": "finding",
        "status": "candidate",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "summary": "committed-evidence probe",
        "epistemic_status": "interpretation",
        "classification": "conformance-observation",
        "provenance": {
            "created_by": {"kind": "human", "role": "verifier"},
            "sources": [],
            "parent": None,
            "generation": 0,
        },
        "links": {},
        "note": note,
    }
    target = root / "knowledge" / "findings" / "fnd-2026-0001.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(doc), encoding="utf-8")


@pytest.fixture
def git_repo(repo_root: Path) -> Path:
    """``repo_root`` with a .git, so ``git ls-files`` resolves."""
    subprocess.run(
        ["git", "init", "-q", str(repo_root)], check=False, capture_output=True
    )
    return repo_root


def test_the_real_repository_tracks_no_olean_files(repo_root: Path):
    """The premise of the whole check, asserted rather than assumed.

    If this ever starts failing, the .olean files HAVE been promoted into the
    repository and the "committed" wording becomes true -- at which point the
    check below should start firing on the artifacts that use it.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        pytest.skip("not a git checkout")
    tracked = [p for p in proc.stdout.split("\0") if p.endswith(".olean")]
    assert tracked == [], (
        f"olean files are now tracked ({tracked}); the committed-evidence "
        "wording in the formal artifacts may now be accurate"
    )

def test_committed_evidence_claim_is_refused_for_an_untracked_olean(git_repo: Path):
    """POSITIVE: calling gitignored evidence "committed" is a defect.

    Six artifacts justified themselves with "the committed .olean proof terms
    under formal/.lake/build", while .gitignore excludes formal/.lake/ and
    `git ls-files formal/.lake` returns nothing.
    """
    _finding_with_note(
        git_repo,
        "Reading the committed .olean proof terms under "
        "formal/.lake/build/lib/Formal/LengthCheck.olean remains valid.",
    )
    result = validate_repo(git_repo)
    assert not result.ok
    assert any("asserts evidence is committed" in e for e in result.errors), result.errors


def test_committed_evidence_check_ignores_a_corrected_claim(git_repo: Path):
    """NEGATIVE: recording the correction must not itself be an error."""
    _finding_with_note(
        git_repo,
        "The .olean proof terms under formal/.lake/build/lib/Formal/ValidKey.olean "
        "stay LOCAL-ONLY: formal/.lake/ is gitignored, so they are NOT committed "
        "evidence.",
    )
    result = validate_repo(git_repo)
    assert not any("asserts evidence is committed" in e for e in result.errors), result.errors


def test_committed_evidence_check_ignores_unrelated_committed_prose(git_repo: Path):
    """NEGATIVE: "committed" in an unrelated sentence is not the claim.

    obs-2026-0017 says "the prior session committed claims ..." in one sentence
    and "re-grep the .olean output" in another. Neither makes the claim, so the
    window is one sentence.
    """
    _finding_with_note(
        git_repo,
        "The prior session committed claims T1=canonicalRoundtrip. After a clean "
        "build, re-grep the .olean output for sorries.",
    )
    result = validate_repo(git_repo)
    assert not any("asserts evidence is committed" in e for e in result.errors), result.errors


def test_committed_evidence_check_ignores_a_bare_olean_token(git_repo: Path):
    """NEGATIVE: a bare ".olean" names no path, so it asserts nothing."""
    _finding_with_note(git_repo, "Reading the committed .olean proof terms is unreliable.")
    result = validate_repo(git_repo)
    assert not any("asserts evidence is committed" in e for e in result.errors), result.errors
