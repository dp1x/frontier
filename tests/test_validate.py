"""Schema validation and promotion-ladder enforcement."""

from pathlib import Path

import pytest
import yaml

from tests.conftest import envelope, provenance, write_yaml


def _mission(**overrides) -> dict:
    doc = envelope(
        "msn-2026-0001",
        "mission",
        "pending",
        epistemic_status="hypothesis",
        title="ML-KEM modulus check survey",
        objective="Determine how public ML-KEM implementations treat FIPS 203 §7.2 checks.",
        domain="cryptography",
        scope="Encapsulation-key type and modulus checks only.",
        constraints=["Do not label a vulnerability from an unchecked theory."],
        desired_evidence_level="independently-reviewed",
        candidate_targets=[],
        dependencies=[],
        compute={"expected_class": "lightweight", "notes": "tiny key checks"},
        budget={
            "max_attempts": 20,
            "max_independent_reviews": 3,
            "max_compute_runs": 50,
            "diminishing_returns_window": 3,
            "max_auto_descendants": 3,
        },
        acceptance_criteria=[
            "At least one executable experiment against a named implementation version.",
            "Independent review of any claimed classification.",
        ],
        stopping_conditions=["Budget exhausted without new evidence."],
        artifacts=[],
        follow_ups=[],
        notes_path=None,
        blocked_reason=None,
        terminal_reason=None,
    )
    doc.update(overrides)
    return doc


def test_valid_mission_passes(repo_root: Path):
    from frontier.validate import validate_document

    errors = validate_document(_mission())
    assert errors == []


def test_unknown_domain_fails():
    from frontier.validate import validate_document

    errors = validate_document(_mission(domain="vibes"))
    assert any("domain" in e.lower() or "vibes" in e.lower() for e in errors)


def test_finding_cannot_be_verified_without_evidence_chain():
    from frontier.validate import validate_document

    finding = envelope(
        "fnd-2026-0001",
        "finding",
        "verified",
        epistemic_status="verified_conclusion",
        classification="spec-violation",
        statement="Something is wrong.",
        disclosure="public",
        links={},
    )
    errors = validate_document(finding)
    assert errors
    joined = " ".join(errors).lower()
    assert "verified" in joined


def test_agent_assertion_is_not_a_verification_method():
    from frontier.validate import validate_document

    vrf = envelope(
        "vrf-2026-0001",
        "verification",
        "pass",
        epistemic_status="verified_conclusion",
        method="agent-assertion",
        result="pass",
        environment={"where": "nowhere"},
        links={"finding": ["fnd-2026-0001"]},
    )
    errors = validate_document(vrf)
    assert errors
    assert any("agent-assertion" in e.lower() or "method" in e.lower() for e in errors)


def test_id_type_mismatch_is_rejected():
    from frontier.validate import validate_document

    doc = _mission()
    doc["id"] = "hyp-2026-0001"
    errors = validate_document(doc)
    assert errors


def test_terminal_mission_requires_terminal_reason():
    from frontier.validate import validate_document

    errors = validate_document(
        _mission(status="abandoned-with-reason", terminal_reason=None)
    )
    assert errors


def test_repo_validator_flags_dangling_refs(repo_root: Path):
    from frontier.validate import validate_repo

    write_yaml(
        repo_root / "missions/pending/msn-2026-0001.yaml",
        _mission(candidate_targets=["tgt-2026-0099"]),
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("tgt-2026-0099" in e for e in result.errors)


def test_mission_directory_must_match_status(repo_root: Path):
    from frontier.validate import validate_repo

    write_yaml(repo_root / "missions/completed/msn-2026-0001.yaml", _mission(status="pending"))
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("directory" in e.lower() or "location" in e.lower() for e in result.errors)


def test_duplicate_ids_are_rejected(repo_root: Path):
    from frontier.validate import validate_repo

    write_yaml(repo_root / "missions/pending/msn-2026-0001.yaml", _mission())
    write_yaml(
        repo_root / "knowledge/hypotheses/msn-2026-0001.yaml",
        envelope("msn-2026-0001", "mission", "pending"),
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("duplicate" in e.lower() for e in result.errors)
