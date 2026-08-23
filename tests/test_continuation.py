"""Automatic continuation is bounded and evidence-justified."""

from frontier.continuation import FollowUpProposal, evaluate_followup


def _proposal(**kwargs) -> FollowUpProposal:
    data = dict(
        title="Classify FIPS 203 §7.2 vs SP 800-227 check placement",
        justification="unresolved-evidence",
        cited_evidence=["obs-2026-0001"],
        parent_id="msn-2026-0001",
        parent_generation=0,
        parent_status="inconclusive-after-budget",
        parent_security_sensitive=False,
        existing_objectives=["Determine how public ML-KEM implementations treat FIPS 203 §7.2 checks."],
        proposed_objective="Determine whether missing Encaps-time modulus checks are allowed by SP 800-227.",
    )
    data.update(kwargs)
    return FollowUpProposal(**data)


def test_justified_followup_from_terminal_parent_is_allowed():
    decision = evaluate_followup(_proposal())
    assert decision.allowed is True


def test_followup_without_justification_is_rejected():
    decision = evaluate_followup(_proposal(justification="because-we-can", cited_evidence=[]))
    assert decision.allowed is False


def test_followup_that_duplicates_parent_objective_is_rejected():
    decision = evaluate_followup(
        _proposal(
            proposed_objective="Determine how public ML-KEM implementations treat FIPS 203 §7.2 checks."
        )
    )
    assert decision.allowed is False
    assert "duplicate" in decision.reason.lower()


def test_generation_cap_blocks_runaway_descendants():
    decision = evaluate_followup(_proposal(parent_generation=3))
    assert decision.allowed is False
    assert "generation" in decision.reason.lower() or "depth" in decision.reason.lower()


def test_security_sensitive_parent_cannot_auto_spawn():
    decision = evaluate_followup(_proposal(parent_security_sensitive=True))
    assert decision.allowed is False
    assert "security" in decision.reason.lower() or "human" in decision.reason.lower()


def test_active_parent_cannot_spawn_unless_unresolved_evidence():
    decision = evaluate_followup(
        _proposal(
            parent_status="active",
            justification="defined-objective",
            cited_evidence=[],
        )
    )
    assert decision.allowed is False
