"""A current conclusion cannot rest on a dead claim.

``msn-2026-0017`` stood ``verified`` on ``fnd-2026-0013`` (``rejected``). Nothing
caught it because the dependency was a plain ID and the retraction lived in the
target's prose. ``supersedes`` makes the relation machine-readable, and
``check_superseded_authority`` makes the contradiction a graph fact.

Each test below constructs one contradiction that previously survived and asserts
the validator refuses it. The controls assert the rule does NOT fire on the
shapes that are legitimate, including the real corpus.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from frontier.validate import (
    DEAD_CLAIM_STATUSES,
    check_superseded_authority,
    validate_repo,
)

FIRE = "A dead claim is not an authority"


def _artifact(
    aid: str,
    atype: str,
    status: str,
    directory: str,
    *,
    epistemic: str = "hypothesis",
    links: dict | None = None,
    dependencies: list[str] | None = None,
    parent: str | None = None,
    summary: str = "probe",
    extra: dict | None = None,
) -> dict:
    doc = {
        "id": aid,
        "type": atype,
        "status": status,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "summary": summary,
        "epistemic_status": epistemic,
        "provenance": {
            "created_by": {"kind": "human", "role": "verifier"},
            "sources": [],
            "parent": parent,
            "generation": 0,
        },
        "links": links or {},
    }
    if dependencies is not None:
        doc["dependencies"] = dependencies
    if extra:
        doc.update(extra)
    return doc


def _write(root: Path, rel: str, doc: dict) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _dead_finding(root: Path, aid: str = "fnd-2026-0001", status: str = "rejected") -> None:
    _write(
        root,
        f"knowledge/findings/{aid}.yaml",
        _artifact(
            aid,
            "finding",
            status,
            "findings",
            epistemic="interpretation",
            extra={"classification": "not-a-bug", "statement": "a claim that is now dead", "disclosure": "public"},
        ),
    )


# --------------------------------------------------------------------------
# Contradiction 1: the live case. A verified mission resting on a rejected
# finding, with no record of the rejection anywhere in the mission.
# --------------------------------------------------------------------------


def test_verified_mission_resting_on_rejected_finding_is_refused(repo_root: Path):
    """msn-2026-0017's shape: ``verified`` + dependency on a ``rejected`` finding."""
    _dead_finding(repo_root)
    _write(
        repo_root,
        "missions/completed/msn-2026-0017.yaml",
        _artifact(
            "msn-2026-0017",
            "mission",
            "verified",
            "completed",
            dependencies=["fnd-2026-0001"],
            extra={
                "terminal_reason": "promoted after the cohort agreed",
                "title": "CBOR cross-impl conformance matrix",
                "objective": "determine cross-implementation agreement",
                "domain": "interop",
                "scope": "x",
                "constraints": [],
                "desired_evidence_level": "verified",
                "candidate_targets": [],
                "compute": {"expected_class": "lightweight"},
                "budget": {
                    "max_attempts": 1,
                    "max_independent_reviews": 1,
                    "max_compute_runs": 1,
                    "diminishing_returns_window": 1,
                    "max_auto_descendants": 0,
                },
                "acceptance_criteria": ["x"],
                "stopping_conditions": ["y"],
            },
        ),
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("msn-2026-0017" in e and FIRE in e for e in result.errors), result.errors


# --------------------------------------------------------------------------
# Contradiction 2: the specification case. A verified verification whose
# normative authority is withdrawn.
# --------------------------------------------------------------------------


def test_verified_verification_resting_on_withdrawn_specification_is_refused(repo_root: Path):
    """An authority edge via ``links.specifications`` counts as resting on."""
    _write(
        repo_root,
        "knowledge/specifications/spc-2026-0004.yaml",
        _artifact("spc-2026-0004", "specification", "withdrawn", "specifications"),
    )
    _write(
        repo_root,
        "knowledge/verifications/vrf-2026-0014.yaml",
        _artifact(
            "vrf-2026-0014",
            "verification",
            "verified",
            "verifications",
            epistemic="verified_conclusion",
            links={"specifications": ["spc-2026-0004"]},
            extra={"method": "deterministic-script", "result": "pass", "environment": {}},
        ),
    )
    errors = check_superseded_authority(
        [(Path("v.yaml"), yaml.safe_load((repo_root / "knowledge/verifications/vrf-2026-0014.yaml").read_text())),
         (Path("s.yaml"), yaml.safe_load((repo_root / "knowledge/specifications/spc-2026-0004.yaml").read_text()))]
    )
    assert errors, "dead specification authority was not caught"
    assert FIRE in errors[0]


# --------------------------------------------------------------------------
# Contradiction 3: the parentage case. A review that declares epistemic
# verified_conclusion while its own parent artifact has been withdrawn.
# --------------------------------------------------------------------------


def test_review_with_verified_conclusion_on_a_withdrawn_parent_is_refused(repo_root: Path):
    _dead_finding(repo_root, aid="fnd-2026-0014", status="withdrawn")
    _write(
        repo_root,
        "knowledge/reviews/rev-2026-0016.yaml",
        _artifact(
            "rev-2026-0016",
            "review",
            "current",
            "reviews",
            epistemic="verified_conclusion",
            parent="fnd-2026-0014",
            extra={"role": "adversarial-critic", "verdict": "supports", "independent": True},
        ),
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("rev-2026-0016" in e and FIRE in e for e in result.errors), result.errors


# --------------------------------------------------------------------------
# Contradiction 4: a ``superseded`` target, and the relation-type variant.
# Each dead status in DEAD_CLAIM_STATUSES must trigger.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("dead_status", sorted(DEAD_CLAIM_STATUSES - {"archived", "abandoned"}))
def test_every_dead_claim_status_is_caught(repo_root: Path, dead_status: str):
    """The rule is defined over the dead-status set, not over ``rejected`` alone."""
    _dead_finding(repo_root, status=dead_status)
    _write(
        repo_root,
        "knowledge/implementations/imp-2026-0018.yaml",
        _artifact(
            "imp-2026-0018",
            "implementation",
            "current",
            "implementations",
            epistemic="verified_conclusion",
            links={"specifications": ["fnd-2026-0001"]},
        ),
    )
    result = validate_repo(repo_root)
    assert any(FIRE in e for e in result.errors), (dead_status, result.errors)


# --------------------------------------------------------------------------
# The discharge paths: recording the supersession makes the state coherent.
# --------------------------------------------------------------------------


def test_recording_the_supersession_discharges_the_contradiction(repo_root: Path):
    """The intended repair: declare the relation instead of leaving it implicit."""
    _dead_finding(repo_root)
    _write(
        repo_root,
        "missions/completed/msn-2026-0017.yaml",
        _artifact(
            "msn-2026-0017",
            "mission",
            "superseded",
            "completed",
            dependencies=["fnd-2026-0001"],
            extra={
                "terminal_reason": "the finding it rested on was rejected",
                "title": "CBOR cross-impl conformance matrix",
                "objective": "determine cross-implementation agreement",
                "domain": "interop",
                "scope": "x",
                "constraints": [],
                "desired_evidence_level": "verified",
                "candidate_targets": [],
                "compute": {"expected_class": "lightweight"},
                "budget": {
                    "max_attempts": 1,
                    "max_independent_reviews": 1,
                    "max_compute_runs": 1,
                    "diminishing_returns_window": 1,
                    "max_auto_descendants": 0,
                },
                "acceptance_criteria": ["x"],
                "stopping_conditions": ["y"],
                "supersedes": {"withdraws": ["fnd-2026-0001"]},
            },
        ),
    )
    result = validate_repo(repo_root)
    assert not any(FIRE in e for e in result.errors), result.errors


def test_prose_that_states_the_supersession_discharges_the_contradiction(repo_root: Path):
    """Backward compatibility: the corpus recorded corrections in prose for years.

    Requiring the machine field everywhere would make every historical
    correction an error, which is the opposite of what the record is for.
    """
    _dead_finding(repo_root)
    _write(
        repo_root,
        "missions/completed/msn-2026-0017.yaml",
        _artifact(
            "msn-2026-0017",
            "mission",
            "verified",
            "completed",
            dependencies=["fnd-2026-0001"],
            summary=(
                "CBOR matrix. fnd-2026-0001 was rejected; its conformance "
                "reading is withdrawn and only the raw matrix cells survive."
            ),
            extra={
                "terminal_reason": "the finding it rested on was rejected",
                "title": "CBOR cross-impl conformance matrix",
                "objective": "determine cross-implementation agreement",
                "domain": "interop",
                "scope": "x",
                "constraints": [],
                "desired_evidence_level": "verified",
                "candidate_targets": [],
                "compute": {"expected_class": "lightweight"},
                "budget": {
                    "max_attempts": 1,
                    "max_independent_reviews": 1,
                    "max_compute_runs": 1,
                    "diminishing_returns_window": 1,
                    "max_auto_descendants": 0,
                },
                "acceptance_criteria": ["x"],
                "stopping_conditions": ["y"],
            },
        ),
    )
    result = validate_repo(repo_root)
    assert not any(FIRE in e for e in result.errors), result.errors


# --------------------------------------------------------------------------
# Non-vacuity: the rule must stay silent on everything legitimate.
# --------------------------------------------------------------------------


def test_disputed_authority_is_not_treated_as_dead(repo_root: Path):
    """The corpus uses ``disputed`` for 'survives, evidence overstated'.

    fnd-2026-0001, fnd-2026-0005 and fnd-2026-0010 all use it that way, so a
    disputed artifact is still citable and must not fire the rule.
    """
    _dead_finding(repo_root, status="disputed")
    _write(
        repo_root,
        "missions/completed/msn-2026-0010.yaml",
        _artifact(
            "msn-2026-0010",
            "mission",
            "verified",
            "completed",
            dependencies=["fnd-2026-0001"],
            extra={
                "terminal_reason": "the claim survives; only the evidence was overstated",
                "title": "SSH hybrid KEX protocol-layer audit",
                "objective": "determine whether the server enforces the check",
                "domain": "cryptography",
                "scope": "x",
                "constraints": [],
                "desired_evidence_level": "verified",
                "candidate_targets": [],
                "compute": {"expected_class": "lightweight"},
                "budget": {
                    "max_attempts": 1,
                    "max_independent_reviews": 1,
                    "max_compute_runs": 1,
                    "diminishing_returns_window": 1,
                    "max_auto_descendants": 0,
                },
                "acceptance_criteria": ["x"],
                "stopping_conditions": ["y"],
            },
        ),
    )
    result = validate_repo(repo_root)
    assert not any(FIRE in e for e in result.errors), result.errors


def test_examination_links_do_not_count_as_authority(repo_root: Path):
    """A report listing every finding in the corpus is not resting on any of them.

    Counting ``links.findings`` would fire on 91 edges in this corpus instead of
    4. obs-2026-0058 states the distinction outright: a link is not an inherited
    claim, and treating link-carriers as contaminated overstates the blast radius.
    """
    _dead_finding(repo_root)
    _write(
        repo_root,
        "knowledge/reports/rpt-2026-0016.yaml",
        _artifact(
            "rpt-2026-0016",
            "report",
            "final",
            "reports",
            epistemic="verified_conclusion",
            links={"findings": ["fnd-2026-0001"]},
        ),
    )
    result = validate_repo(repo_root)
    assert not any(FIRE in e for e in result.errors), result.errors


def test_a_non_conclusion_artifact_may_depend_on_a_dead_claim(repo_root: Path):
    """Only artifacts ASSERTING a current conclusion are constrained."""
    _dead_finding(repo_root)
    _write(
        repo_root,
        "knowledge/hypotheses/hyp-2026-0029.yaml",
        _artifact(
            "hyp-2026-0029",
            "hypothesis",
            "open",
            "hypotheses",
            links={"specifications": ["fnd-2026-0001"]},
            extra={"statement": "an open question", "falsifiable_predictions": ["x"]},
        ),
    )
    result = validate_repo(repo_root)
    assert not any(FIRE in e for e in result.errors), result.errors


def test_a_holding_conclusion_on_a_holding_authority_is_fine(repo_root: Path):
    """The control that matters most: the rule must not refuse honest evidence."""
    _dead_finding(repo_root, aid="fnd-2026-0002", status="rejected")
    _write(
        repo_root,
        "knowledge/observations/obs-2026-0041.yaml",
        _artifact(
            "obs-2026-0041",
            "observation",
            "recorded",
            "observations",
            epistemic="verified_conclusion",
            links={"specifications": ["spc-2026-0004"]},
            extra={
                "statement": "recorded results",
                "environment": {"where": "local", "isolation": "scratch"},
            },
        ),
    )
    _write(
        repo_root,
        "knowledge/specifications/spc-2026-0004.yaml",
        _artifact("spc-2026-0004", "specification", "current", "specifications"),
    )
    result = validate_repo(repo_root)
    assert not any(FIRE in e for e in result.errors), result.errors


# --------------------------------------------------------------------------
# The live corpus. Non-vacuity on real evidence, and a tripwire if the corpus
# changes. Deliberately NOT pinned to a count: the corpus is live, other work is
# landing in it concurrently, and a hard-coded count turns the moment an
# unrelated artifact is corrected into a spurious failure. What is pinned is
# the property the rule exists to protect.
# --------------------------------------------------------------------------


def test_the_real_corpus_has_no_unacknowledged_dead_authority(repo_root: Path):
    """Every current conclusion in the repository names its dead authorities.

    This is the property, not a count. It failed on the real corpus before
    ``msn-2026-0017`` was superseded (the mission stood ``verified`` on
    ``fnd-2026-0013``, which is ``rejected``), and obs-2026-0058 independently
    reached the same verdict and recorded "SUPERSEDE" as the disposition. If a
    future artifact asserts a current conclusion on a dead claim without
    recording the relation, this fails.
    """
    repo = Path(__file__).resolve().parents[1]
    result = validate_repo(repo)
    offenders = [e for e in result.errors if FIRE in e]
    assert not offenders, offenders