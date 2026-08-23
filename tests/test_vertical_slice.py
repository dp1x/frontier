"""Vertical slice: objective → experiment → observation → blocked promotion → knowledge."""

from pathlib import Path

from tests.conftest import envelope, write_yaml


def test_tiny_hash_experiment_records_observation_and_blocks_unearned_verification(
    repo_root: Path, tmp_path: Path
):
    from frontier.execute import run_command
    from frontier.promotion import can_promote_finding
    from frontier.validate import validate_document

    mission = envelope(
        "msn-2026-0009",
        "mission",
        "active",
        epistemic_status="hypothesis",
        title="SHA-256 known-answer smoke",
        objective="Confirm the experiment runner records a deterministic hash observation.",
        domain="cryptography",
        scope="Machinery smoke only.",
        constraints=[],
        desired_evidence_level="verified",
        candidate_targets=[],
        dependencies=[],
        compute={"expected_class": "lightweight", "notes": ""},
        budget={
            "max_attempts": 1,
            "max_independent_reviews": 1,
            "max_compute_runs": 1,
            "diminishing_returns_window": 1,
            "max_auto_descendants": 0,
        },
        acceptance_criteria=["Observation matches FIPS 180-4 SHA-256 empty-string vector."],
        stopping_conditions=["One run."],
        artifacts=[],
        follow_ups=[],
        notes_path=None,
        blocked_reason=None,
        terminal_reason=None,
    )
    assert validate_document(mission) == []
    write_yaml(repo_root / "missions/active/msn-2026-0009.yaml", mission)

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    result = run_command(
        [
            "python",
            "-c",
            "import hashlib,sys; sys.stdout.write(hashlib.sha256(b'').hexdigest())",
        ],
        cwd=scratch,
        timeout_s=15,
    )
    assert result.exit_code == 0
    assert result.stdout == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    observation = envelope(
        "obs-2026-0009",
        "observation",
        "recorded",
        epistemic_status="observation",
        statement="SHA-256 of empty bytes matched the known test vector.",
        environment={
            "where": "local",
            "isolation": result.isolation,
            "cwd": result.cwd,
        },
        stdout=result.stdout,
        exit_code=result.exit_code,
        links={"mission": ["msn-2026-0009"]},
    )
    assert validate_document(observation) == []

    finding = envelope(
        "fnd-2026-0009",
        "finding",
        "under-review",
        epistemic_status="interpretation",
        classification="verified-known-answer",
        statement="Empty-string SHA-256 matches FIPS 180-4.",
        disclosure="public",
        links={"observations": ["obs-2026-0009"], "mission": ["msn-2026-0009"]},
    )
    from frontier.promotion import can_promote_finding as promote

    assert promote(finding, {"obs-2026-0009": observation}) is False
