"""Human-facing status does not require reading agent transcripts."""

from pathlib import Path

from tests.conftest import envelope, write_yaml


def _mission(status: str, **extra) -> dict:
    doc = envelope(
        extra.pop("id", "msn-2026-0001"),
        "mission",
        status,
        epistemic_status="hypothesis",
        title=extra.pop("title", "Test mission"),
        objective="Do a thing.",
        domain=extra.pop("domain", "cryptography"),
        scope="narrow",
        constraints=[],
        desired_evidence_level="reproduced",
        candidate_targets=[],
        dependencies=[],
        compute={"expected_class": "lightweight", "notes": ""},
        budget={
            "max_attempts": 5,
            "max_independent_reviews": 1,
            "max_compute_runs": 5,
            "diminishing_returns_window": 2,
            "max_auto_descendants": 1,
        },
        acceptance_criteria=["Have evidence."],
        stopping_conditions=["Budget."],
        artifacts=[],
        follow_ups=[],
        notes_path=None,
        blocked_reason=extra.pop("blocked_reason", None),
        terminal_reason=extra.pop("terminal_reason", None),
    )
    doc.update(extra)
    return doc


def test_status_lists_active_pending_and_findings(repo_root: Path):
    from frontier.status import collect_status

    write_yaml(
        repo_root / "missions/pending/msn-2026-0001.yaml",
        _mission("pending", title="Pending crypto"),
    )
    write_yaml(
        repo_root / "missions/active/msn-2026-0002.yaml",
        _mission("active", id="msn-2026-0002", title="Active compilers", domain="compilers"),
    )
    write_yaml(
        repo_root / "knowledge/findings/fnd-2026-0001.yaml",
        envelope(
            "fnd-2026-0001",
            "finding",
            "verified",
            epistemic_status="verified_conclusion",
            classification="not-a-bug",
            statement="No discrepancy after reproduction.",
            disclosure="public",
            links={
                "experiments": ["exp-2026-0001"],
                "observations": ["obs-2026-0001"],
                "reproducers": ["rpr-2026-0001"],
                "reviews": ["rev-2026-0001"],
                "verifications": ["vrf-2026-0001"],
            },
        ),
    )
    write_yaml(
        repo_root / "knowledge/hypotheses/hyp-2026-0001.yaml",
        envelope(
            "hyp-2026-0001",
            "hypothesis",
            "rejected",
            epistemic_status="hypothesis",
            statement="All implementations skip the modulus check.",
            links={"mission": ["msn-2026-0001"]},
        ),
    )
    write_yaml(
        repo_root / "ai-io/prompts/aio-2026-0001.md",
        "---\nid: aio-2026-0001\nmission: msn-2026-0001\nstatus: awaiting-output\nangle: landscape\n---\n\nPrompt body\n",
    )

    report = collect_status(repo_root)
    assert any(m["id"] == "msn-2026-0001" for m in report["pending_missions"])
    assert any(m["id"] == "msn-2026-0002" for m in report["active_missions"])
    assert any(f["id"] == "fnd-2026-0001" for f in report["verified_findings"])
    assert any(h["id"] == "hyp-2026-0001" for h in report["preserved_negative_results"])
    assert any(p["id"] == "aio-2026-0001" for p in report["external_research_awaiting"])
    markdown = report["markdown"]
    assert "msn-2026-0002" in markdown
    assert "Active missions" in markdown or "active" in markdown.lower()
