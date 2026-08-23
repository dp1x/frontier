"""Research promotion ladder: idea is not a verified result."""

from frontier.promotion import PromotionError, can_promote_finding, required_evidence


def test_verified_finding_requires_full_chain():
    missing = required_evidence(
        {
            "id": "fnd-2026-0001",
            "status": "verified",
            "links": {},
        }
    )
    assert "experiment" in missing
    assert "observation" in missing
    assert "reproducer" in missing
    assert "review" in missing
    assert "verification" in missing


def test_can_promote_when_chain_and_independent_review_exist():
    finding = {
        "id": "fnd-2026-0001",
        "status": "under-review",
        "classification": "implementation-spec-mismatch",
        "disclosure": "public",
        "links": {
            "experiments": ["exp-2026-0001"],
            "observations": ["obs-2026-0001"],
            "reproducers": ["rpr-2026-0001"],
            "reviews": ["rev-2026-0001"],
            "verifications": ["vrf-2026-0001"],
        },
    }
    objects = {
        "rev-2026-0001": {
            "id": "rev-2026-0001",
            "type": "review",
            "independent": True,
            "status": "complete",
            "verdict": "supports",
            "role": "adversarial-critic",
        },
        "vrf-2026-0001": {
            "id": "vrf-2026-0001",
            "type": "verification",
            "method": "executable",
            "status": "pass",
            "result": "pass",
        },
        "rpr-2026-0001": {
            "id": "rpr-2026-0001",
            "type": "reproducer",
            "status": "reproduced",
        },
    }
    assert can_promote_finding(finding, objects) is True


def test_synthesizer_review_alone_cannot_promote():
    finding = {
        "id": "fnd-2026-0001",
        "status": "under-review",
        "classification": "spec-violation",
        "disclosure": "public",
        "links": {
            "experiments": ["exp-2026-0001"],
            "observations": ["obs-2026-0001"],
            "reproducers": ["rpr-2026-0001"],
            "reviews": ["rev-2026-0001"],
            "verifications": ["vrf-2026-0001"],
        },
    }
    objects = {
        "rev-2026-0001": {
            "id": "rev-2026-0001",
            "independent": True,
            "status": "complete",
            "verdict": "supports",
            "role": "synthesizer",
        },
        "vrf-2026-0001": {
            "id": "vrf-2026-0001",
            "method": "executable",
            "status": "pass",
            "result": "pass",
        },
        "rpr-2026-0001": {"id": "rpr-2026-0001", "status": "reproduced"},
    }
    assert can_promote_finding(finding, objects) is False


def test_promote_raises_if_forced_without_evidence():
    try:
        can_promote_finding({"id": "fnd-2026-0001", "status": "under-review", "links": {}}, {})
        ok = True
    except PromotionError:
        ok = False
    # Function returns False rather than raising for the boolean API.
    assert ok is True
    assert can_promote_finding({"id": "fnd-2026-0001", "status": "under-review", "links": {}}, {}) is False
