"""Research promotion ladder enforcement.

The ladder is code, not prose: a finding cannot become ``verified`` without an
experiment, an observation, a reproducer, an independent non-synthesizer
review that supports it, and a deterministic verification. Model consensus is
never a substitute for any of these.
"""

from __future__ import annotations

# Link key (plural) -> evidence category name (singular).
EVIDENCE_LINKS: dict[str, str] = {
    "experiments": "experiment",
    "observations": "observation",
    "reproducers": "reproducer",
    "reviews": "review",
    "verifications": "verification",
}

# Roles whose review alone can never satisfy the independent-review gate.
NON_INDEPENDENT_ROLES = frozenset({"synthesizer"})

VERIFICATION_METHODS = frozenset(
    {
        "executable",
        "formal-verifier",
        "differential",
        "deterministic-script",
        "reproduction",
    }
)


class PromotionError(RuntimeError):
    """Raised when promotion state itself is inconsistent."""


def required_evidence(finding: dict) -> list[str]:
    """Return the missing evidence categories for a finding."""
    links = finding.get("links") or {}
    return [
        category
        for plural, category in EVIDENCE_LINKS.items()
        if not links.get(plural)
    ]


def _has_independent_support(links: dict, objects: dict[str, dict]) -> bool:
    for ref in links.get("reviews") or []:
        review = objects.get(ref)
        if not isinstance(review, dict):
            continue
        role = review.get("role", "")
        if (
            review.get("independent") is True
            and role not in NON_INDEPENDENT_ROLES
            and review.get("status") == "complete"
            and review.get("verdict") == "supports"
        ):
            return True
    return False


def _has_passing_verification(links: dict, objects: dict[str, dict]) -> bool:
    for ref in links.get("verifications") or []:
        verification = objects.get(ref)
        if not isinstance(verification, dict):
            continue
        if verification.get("method") == "agent-assertion":
            continue  # never acceptable evidence
        if verification.get("method") not in VERIFICATION_METHODS:
            continue
        if verification.get("status") == "pass" or verification.get("result") == "pass":
            return True
    return False


def _has_reproduced_reproducer(links: dict, objects: dict[str, dict]) -> bool:
    for ref in links.get("reproducers") or []:
        reproducer = objects.get(ref)
        if isinstance(reproducer, dict) and reproducer.get("status") == "reproduced":
            return True
    return False


def can_promote_finding(finding: dict, objects: dict[str, dict]) -> bool:
    """Decide whether ``finding`` may be promoted to ``verified``.

    All five evidence categories must be linked. Reviews, verifications, and
    reproducers must be present in ``objects`` and pass their gates;
    experiment/observation references must simply be recorded.
    """
    links = finding.get("links") or {}
    for plural in EVIDENCE_LINKS:
        if not links.get(plural):
            return False
    if not _has_independent_support(links, objects):
        return False
    if not _has_passing_verification(links, objects):
        return False
    if not _has_reproduced_reproducer(links, objects):
        return False
    return True
