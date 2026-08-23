"""Bounded automatic continuation of missions.

A mission may spawn follow-up work only when justified by cited unresolved
evidence, only below the generation cap, and never from a security-sensitive
parent. Objectives must differ from all existing objectives; a model inventing
more questions is never justification on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Children are allowed while the parent's generation is strictly below this.
MAX_GENERATION = 3

TERMINAL_STATUSES = frozenset(
    {
        "verified",
        "disproved",
        "inconclusive-after-budget",
        "blocked-by-missing-evidence",
        "superseded",
        "abandoned-with-reason",
    }
)


@dataclass
class FollowUpProposal:
    title: str
    justification: str
    cited_evidence: list[str]
    parent_id: str
    parent_generation: int
    parent_status: str
    parent_security_sensitive: bool
    existing_objectives: list[str]
    proposed_objective: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _normalize(text: str) -> str:
    words = re.sub(r"[^a-z0-9 ]+", " ", text.lower()).split()
    return " ".join(words)


def evaluate_followup(proposal: FollowUpProposal) -> Decision:
    """Decide whether an automatic follow-up mission may be created."""
    if proposal.parent_security_sensitive:
        return Decision(
            allowed=False,
            reason=(
                "security-sensitive parents require human judgment before any "
                "descendant work is created"
            ),
        )
    if proposal.parent_generation >= MAX_GENERATION:
        return Decision(
            allowed=False,
            reason=(
                f"generation depth cap reached ({proposal.parent_generation} >= "
                f"{MAX_GENERATION}); no further auto-descendants"
            ),
        )
    if proposal.justification != "unresolved-evidence":
        return Decision(
            allowed=False,
            reason=(
                f"justification {proposal.justification!r} does not establish "
                "unresolved evidence"
            ),
        )
    if not proposal.cited_evidence:
        return Decision(
            allowed=False,
            reason="no cited evidence justifying new work",
        )
    if proposal.parent_status not in TERMINAL_STATUSES:
        return Decision(
            allowed=False,
            reason=f"parent mission is not terminal (status: {proposal.parent_status})",
        )

    proposed = _normalize(proposal.proposed_objective)
    for existing in proposal.existing_objectives:
        if proposed == _normalize(existing):
            return Decision(
                allowed=False,
                reason="proposed objective duplicates an existing objective",
            )

    return Decision(allowed=True, reason="justified bounded follow-up")
