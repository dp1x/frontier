"""A verified conclusion cannot sit on an artifact that does not hold.

Seven artifacts recorded ``epistemic_status: verified_conclusion`` while their
own ``status`` said ``disputed``, ``rejected`` or ``withdrawn``. A reader
resolving the pair by ``epistemic_status`` would treat a withdrawn claim as
settled. See ``knowledge/observations/obs-2026-0060.yaml``.

This is a PAIR check, not a prose check: what a disputed artifact's residual
verified content is worth is an open epistemic question, but whether the two
fields may flatly disagree is not.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from frontier.validate import NON_HOLDING_STATUSES, validate_repo


def _write(root: Path, *, status: str, epistemic: str, aid: str = "fnd-2026-0001") -> None:
    doc = {
        "id": aid,
        "type": "finding",
        "status": status,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "summary": "probe",
        "epistemic_status": epistemic,
        "classification": "conformance-observation",
        "provenance": {
            "created_by": {"kind": "human", "role": "verifier"},
            "sources": [],
            "parent": None,
            "generation": 0,
        },
        "links": {},
    }
    target = root / "knowledge" / "findings" / f"{aid}.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(doc), encoding="utf-8")


@pytest.mark.parametrize("status", sorted(NON_HOLDING_STATUSES))
def test_verified_conclusion_on_a_non_holding_status_is_refused(repo_root: Path, status: str):
    _write(repo_root, status=status, epistemic="verified_conclusion")
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("contradicts status" in e for e in result.errors), result.errors


def test_verified_conclusion_on_a_holding_status_is_allowed(repo_root: Path):
    """The control: the rule must not refuse an honest verified artifact."""
    _write(repo_root, status="verified", epistemic="verified_conclusion")
    result = validate_repo(repo_root)
    assert not any("contradicts status" in e for e in result.errors), result.errors


def test_interpretation_on_a_non_holding_status_is_allowed(repo_root: Path):
    """The control that matters: downgrading is the intended resolution."""
    _write(repo_root, status="withdrawn", epistemic="interpretation")
    result = validate_repo(repo_root)
    assert not any("contradicts status" in e for e in result.errors), result.errors


def test_the_live_repository_has_none():
    """The rule is aimed at the real corpus, so assert the real corpus is clean."""
    repo = Path(__file__).resolve().parents[1]
    result = validate_repo(repo)
    offenders = [e for e in result.errors if "contradicts status" in e]
    assert not offenders, offenders