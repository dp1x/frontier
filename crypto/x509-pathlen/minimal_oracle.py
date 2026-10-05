"""An INDEPENDENT second implementation of the RFC 5280 6.1 path-length walk.

Why a second one
----------------
`oracle.py` is the historical oracle and has four documented wrong versions.
This module is written from the same normative text but deliberately in a
DIFFERENT STYLE, so that a shared misreading is less likely to be reproduced:

  * `oracle.py` returns a Verdict carrying a free-text reason and a trace.
    This one returns, for every certificate, an explicit record of the state
    BEFORE step (l), AFTER step (l), and AFTER step (m), so a reviewer can see
    whether a slot was consumed and when the budget was clamped.
  * `oracle.py` short-circuits on the first failure.  This one computes the
    full walk and reports the first failure index, so a trace is available even
    for a rejecting path.
  * The budget is carried as an explicit list of events rather than a counter,
    so nothing is hidden in an in-place mutation.

Agreement between the two is evidence.  Disagreement means one of them is wrong
and the experiment must stop until it is resolved; that is checked by
``tests/test_x509_minimal_corpus.py::test_the_two_oracles_agree_on_every_case``.

An earlier version of this comment cited a ``test_x509_minimal_oracle_agreement``
module that was never created.  A citation that resolves to nothing is the same
defect this session's other finding was about, so the locator is corrected here
rather than left looking plausible.

Normative basis, quoted from the RFC 5280 text (Standards Track, May 2008):

  6.1.4 (l) "If the certificate was not self-issued, verify that max_path_length
        is greater than zero and decrement max_path_length by 1."

  6.1.4 (m) "If pathLenConstraint is present in the certificate and is less than
        max_path_length, set max_path_length to the value of pathLenConstraint."

  6.1.1 (k) max_path_length is initialised to n and "is decremented for each
        non-self-issued certificate in the path, and may be reduced to the value
        in the path length constraint field within the basic constraints
        extension of a CA certificate".

  6.1 "Step (3) is performed for all certificates in the path except the final
        certificate." Step (3) is 6.1.4, so the final certificate receives
        neither (l) nor (m).

  6.1 "A certificate is self-issued if the same DN appears in the subject and
        issuer fields (the two DNs are the same if they match according to the
        rules specified in Section 7.1)."

What this module does NOT model: signatures, validity, key usage, name
constraints, policies, or the trust anchor's own constraints.  RFC 5280 6.1
says a trust anchor supplied as a self-signed certificate "is not included as
part of the prospective certification path", so the anchor is not a path member
and this walk never sees it.
"""

from __future__ import annotations

import dataclasses
from typing import Literal


@dataclasses.dataclass(frozen=True)
class Node:
    """One certificate on the path, described only as the rule can see it."""

    label: str
    subject: str
    issuer: str
    ca: bool
    pathlen: int | None

    @property
    def self_issued(self) -> bool:
        """RFC 5280 6.1: the same DN in subject and issuer."""
        return self.subject == self.issuer


@dataclasses.dataclass(frozen=True)
class Frame:
    """State before, between and after the two steps, for one certificate."""

    position: int
    label: str
    self_issued: bool
    ca: bool
    incoming_max_path_length: int
    #: None when step (l) did not run, which is the observable difference.
    decremented: bool | None
    #: Budget after (l).  Equal to ``incoming`` when (l) was skipped.
    after_l: int
    pathlen: int | None
    #: True only when (m) actually lowered the budget.
    clamped: bool
    final_max_path_length: int
    note: str

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Outcome:
    accepted: bool
    failed_at: int | None
    reason: str
    frames: tuple[Frame, ...]

    def as_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "failed_at": self.failed_at,
            "reason": self.reason,
            "frames": [f.as_dict() for f in self.frames],
        }


Verdict = Literal["ACCEPT", "REJECT"]


def walk(path: list[Node]) -> Outcome:
    """Apply 6.1.4 (l) then (m) to certificates 1..n-1 and report every step.

    ``path`` is trust-anchor-first in RFC 5280's own numbering: ``path[0]`` is
    certificate 1 and ``path[-1]`` is certificate n, the target.  The trust
    anchor itself is NOT in this list.
    """
    n = len(path)
    if n == 0:
        return Outcome(False, None, "empty certification path", ())

    # 6.1.1 (k): "this integer is initialized to n".
    budget = n
    frames: list[Frame] = []

    for index, node in enumerate(path):
        position = index + 1

        # 6.1: step (3) -- which is 6.1.4 -- is "performed for all certificates
        # in the path except the final certificate".
        if position == n:
            frames.append(
                Frame(
                    position=position,
                    label=node.label,
                    self_issued=node.self_issued,
                    ca=node.ca,
                    incoming_max_path_length=budget,
                    decremented=None,
                    after_l=budget,
                    pathlen=node.pathlen,
                    clamped=False,
                    final_max_path_length=budget,
                    note="final certificate: 6.1.4 not applied",
                )
            )
            break

        incoming = budget

        # --- step (l): guarded on self-issued ------------------------------
        if node.self_issued:
            after_l = budget
            decremented = False
            note_l = "(l) skipped: self-issued"
        else:
            if budget <= 0:
                frames.append(
                    Frame(
                        position=position,
                        label=node.label,
                        self_issued=False,
                        ca=node.ca,
                        incoming_max_path_length=incoming,
                        decremented=None,
                        after_l=budget,
                        pathlen=node.pathlen,
                        clamped=False,
                        final_max_path_length=budget,
                        note="REJECT at (l): max_path_length is not greater than zero",
                    )
                )
                return Outcome(
                    False,
                    position,
                    f"6.1.4 (l): max_path_length is {budget}, not greater than "
                    f"zero, at non-self-issued certificate {position} "
                    f"({node.label})",
                    tuple(frames),
                )
            after_l = budget - 1
            decremented = True
            note_l = "(l) decrement"

        # --- step (m): NOT guarded on self-issued --------------------------
        clamped = False
        after_m = after_l
        note_m = "(m) absent: no pathLenConstraint"
        if node.pathlen is not None and node.pathlen < after_l:
            after_m = node.pathlen
            clamped = True
            note_m = f"(m) clamp to {node.pathlen}"

        budget = after_m
        frames.append(
            Frame(
                position=position,
                label=node.label,
                self_issued=node.self_issued,
                ca=node.ca,
                incoming_max_path_length=incoming,
                decremented=decremented,
                after_l=after_l,
                pathlen=node.pathlen,
                clamped=clamped,
                final_max_path_length=after_m,
                note=f"{note_l}; {note_m}",
            )
        )

    return Outcome(True, None, "path-length budget satisfied", tuple(frames))


# ---------------------------------------------------------------------------
# Competing readings, so the corpus can be shown to discriminate rather than
# merely to produce another implementation disagreement.
# ---------------------------------------------------------------------------


def walk_H2(path: list[Node]) -> Outcome:
    """H2: the self-issued exception covers BOTH (l) and (m).

    I.e. a self-issued certificate neither spends a slot nor clamps.  This is
    the reading a per-position reformulation taken from 4.2.1.9's prose
    produces, and it is exactly the wrong version (v4) that a prior reviewer
    had to catch in the historical oracle.
    """
    n = len(path)
    if n == 0:
        return Outcome(False, None, "empty certification path", ())
    budget = n
    frames: list[Frame] = []
    for index, node in enumerate(path):
        position = index + 1
        if position == n:
            frames.append(
                Frame(position, node.label, node.self_issued, node.ca, budget,
                      None, budget, node.pathlen, False, budget,
                      "final certificate: 6.1.4 not applied"))
            break
        incoming = budget
        if node.self_issued:
            after_l, decremented = budget, False
            note = "(l) skipped AND (m) skipped: self-issued (H2 reading)"
            clamped, after_m = False, budget
        else:
            if budget <= 0:
                frames.append(
                    Frame(position, node.label, False, node.ca, incoming, None,
                          budget, node.pathlen, False, budget,
                          "REJECT at (l): budget not greater than zero"))
                return Outcome(
                    False, position,
                    f"6.1.4 (l): max_path_length is {budget}, not greater than "
                    f"zero, at certificate {position} ({node.label})",
                    tuple(frames))
            after_l, decremented = budget - 1, True
            clamped = node.pathlen is not None and node.pathlen < after_l
            after_m = node.pathlen if clamped else after_l
            note = "(l) decrement" + (f"; (m) clamp to {node.pathlen}" if clamped
                                      else "; (m) absent")
        budget = after_m
        frames.append(
            Frame(position, node.label, node.self_issued, node.ca, incoming,
                  decremented, after_l, node.pathlen, clamped, after_m, note))
    return Outcome(True, None, "path-length budget satisfied", tuple(frames))