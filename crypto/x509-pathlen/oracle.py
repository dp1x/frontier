"""The Frontier oracle for RFC 5280 pathLenConstraint semantics.

This module implements ONLY the path-length part of RFC 5280 section 6.1.  It is
deliberately tiny and auditable line-by-line; it is NOT an X.509 validator.  It
does not check signatures, validity windows, key usage, name constraints or
policies -- those are separate obligations and conflating them is exactly how a
pathLen observation becomes uninterpretable.

Normative basis
---------------
Every line below is traceable to text read directly from the authoritative RFC
Editor plain text of RFC 5280 (May 2008, Standards Track):

  R = RFC 5280, 352580 bytes,
      SHA-256 A2F2628C0A83B873FC4786ABD921F9B2C02395954B655D190BF16B831633345D

  [A] 6.1.1, R lines 4100-4108:
        "A certificate is self-issued if the same DN appears in the subject and
         issuer fields (the two DNs are the same if they match according to the
         rules specified in Section 7.1). ... However, a CA may issue a
         certificate to itself to support key rollover or changes in certificate
         policies.  These self-issued certificates are not counted when
         evaluating path length or name constraints."

  [B] 6.1.1 (k), R lines 4431-4434:
        "max_path_length: this integer is initialized to n, is decremented for
         each non-self-issued certificate in the path, and may be reduced to the
         value in the path length constraint field within the basic constraints
         extension of a CA certificate."

  [C] 6.1.1, R lines 4112-4115 (THE CORRECTIVE CLAUSE):
        "This section presents the algorithm in four basic steps: (1)
         initialization, (2) basic certificate processing, (3) preparation for the
         next certificate, and (4) wrap-up.  Steps (1) and (4) are performed
         exactly once.  Step (2) is performed for all certificates in the path.
         Step (3) is performed for all certificates in the path EXCEPT THE FINAL
         CERTIFICATE."

  [D] 6.1.4 (l), R lines 4835-4838:
        "If the certificate was not self-issued, verify that max_path_length is
         greater than zero and decrement max_path_length by 1."

  [E] 6.1.4 (m), R lines 4840-4842:
        "If pathLenConstraint is present in the certificate and is less than
         max_path_length, set max_path_length to the value of pathLenConstraint."

  [F] 6.1, the (a)-(d) list at R lines 4060-4069: a prospective certification
      path is a sequence of n certificates where certificate 1 is issued by the
      trust anchor and certificate n is the certificate to be validated.

  [G] 6.1, R lines 4076-4078: when the trust anchor is provided as a self-signed
      certificate it "is not included as part of the prospective certification
      path".

  [H] 4.2.1.9, R lines 2160-2171: "it gives the maximum number of non-self-issued
      intermediate certificates that may follow this certificate in a valid
      certification path. (Note: The last certificate in the certification path
      is not an intermediate certificate, and is not included in this limit.
      Usually, the last certificate is an end entity certificate, but it can be a
      CA certificate.)"

  [I] 6.1, R lines 3997-4000: "A conforming implementation MUST include an X.509
      path processing procedure that is functionally equivalent to the external
      behavior of this algorithm."

What the oracle models, and the correction that produced it
---------------------------------------------------------
RFC 5280's algorithm is a single forward walk over certificates 1..n,
trust-anchor first.  This oracle reproduces that walk and nothing else.

**Correction (2026-10-04).** The first version of this oracle applied 6.1.4
(l) and (m) to every certificate including the final one.  That is wrong, and
the error was caught by re-reading [C] rather than by a failing test: step (3)
is 6.1.4, and [C] restricts step (3) to certificates 1..n-1.  The final
certificate therefore contributes NOTHING to path-length processing -- it is
neither counted, nor does its own pathLenConstraint bind anything, nor is its
self-issued status relevant.

This matters decisively.  A path of n certificates with all intermediates
non-self-issued runs the budget n -> n-1 -> ... -> 1 over certificates 1..n-1,
leaving exactly enough headroom for the (n-2) intermediates that follow
certificate 1 -- which is precisely [H]'s "maximum number of non-self-issued
intermediate certificates that may follow this certificate".  Applying 6.1.4 to
the final certificate as well makes the budget one too tight and rejects legal
chains whose final certificate is a CA certificate.

The self-issued exemption, [D], is a filter on which certificates decrement the
budget.  [E] carries NO self-issued condition, so a self-issued intermediate
still imposes its own pathLenConstraint on what follows it.

Where the RFC leaves freedom
----------------------------
[F] requires only (a)-(d); 6.1 states that obtaining the sequence of
certificates is "outside the scope of this specification", and nothing requires
a *minimal* or *shortest* path.  So :func:`validate_path` judges ONE given path,
and :func:`exists_valid_path` separately asks whether ANY path through the graph
is valid -- which is what [I]'s "functionally equivalent to the external behavior"
actually turns on.
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class CertFacts:
    """The facts the path-length rule is allowed to look at.

    Deliberately minimal.  ``pathlen`` is ``None`` when the pathLenConstraint
    field is absent; the oracle must not be able to distinguish an absent
    extension from an absent field, because RFC 5280 4.2.1.9 gives
    pathLenConstraint meaning only when cA is asserted and says nothing about
    what an absent field means in a non-CA certificate.
    """

    subject: str
    issuer: str
    ca: bool
    pathlen: int | None
    #: Set by the harness when the BasicConstraints extension is absent
    #: entirely.  RFC 5280 6.1.4 (k) treats such a certificate as not a CA,
    #: which is a DIFFERENT rule from path length; the oracle reports it in
    #: ``other_defects`` so the two are never conflated.
    basic_constraints_present: bool = True

    @property
    def self_issued(self) -> bool:
        """RFC 5280 6.1.1 [A]: same DN in subject and issuer."""
        return self.subject == self.issuer


@dataclasses.dataclass
class Step:
    index: int
    label: str
    self_issued: bool
    action: str
    max_path_length_after: int


@dataclasses.dataclass
class Verdict:
    accepted: bool
    reason: str
    trace: list[Step]
    #: Non-path-length defects observed, kept separate from the path-length
    #: verdict so a chain with an unrelated defect is never reported as a
    #: pathLen failure.
    other_defects: list[str] = dataclasses.field(default_factory=list)


def validate_path(path: list[CertFacts]) -> Verdict:
    """Apply RFC 5280 6.1's path-length rules to ONE prospective certification path.

    ``path`` is ordered trust-anchor first, so ``path[0]`` is certificate 1 and
    ``path[-1]`` is certificate n (the target).  The trust anchor is NOT in this
    list -- see [G].

    This is a LITERAL transcription of the 6.1 walk, not a reformulation of it.
    Four earlier versions of this function were wrong, and three of them were
    wrong because they re-expressed the rule in a "cleaner" form:

      v1  Applied 6.1.4 to the final certificate, rejecting legal pathlen:0
          penultimate chains.  Caught by the corpus.
      v2  Replaced (l)'s budget test with a pre-decrement threshold, rejecting
          `pathLen 1 -> 2` increases.  Caught by the corpus.
      v3  Computed a per-position check but never gated the verdict on it, so
          every case accepted.  Caught by the corpus.
      v4  Replaced the walk with 4.2.1.9's prose formulation -- "at most
          c.pathlen non-self-issued certificates may FOLLOW c" -- guarded on c
          being non-self-issued.  Found by REV-1, the independent reviewer, and
          NOT catchable by the corpus.

    v4 is the instructive one.  The two formulations DISAGREE, and the RFC
    contains both, so a reformulation is not a neutral simplification:

      * 6.1.4 (l) is guarded on "the certificate was not self-issued" -- it
        governs which certificates consume budget.
      * 6.1.4 (m) carries NO self-issued guard -- a self-issued intermediate
        still imposes its own pathLenConstraint on what follows it.

    Any per-position rule that skips the check for a self-issued certificate
    therefore silently drops (m)'s effect for exactly the certificates where it
    bites.  Transcribing the walk avoids having to notice that.

    Ordering: RFC 5280 lists (l) at offset 4836 and (m) at offset 4840, and
    6.1.4 executes its steps in that order.  An earlier version applied (m)
    first; REV-1 enumerated the disagreement exhaustively to depth 5 (37,100
    chains, all in the over-strict direction).
    """
    n = len(path)
    if n == 0:
        return Verdict(False, "empty certification path", [])

    trace: list[Step] = []
    other_defects: list[str] = []

    # [B]: max_path_length is initialised to n.
    max_path_length = n

    # [C]: step (3) is 6.1.4, and 6.1 says step (3) "is performed for all
    # certificates in the path except the final certificate".  So the walk below
    # covers certificates 1..n-1 and the target is never touched.
    for index, cert in enumerate(path):
        position = index + 1
        label = cert.subject

        if position == n:
            trace.append(Step(position, label, cert.self_issued,
                              "6.1 [C]: final certificate - 6.1.4 not applied",
                              max_path_length))
            break

        # 6.1.4 (k) is a CA-ness rule, not a path-length rule.  Recorded
        # separately so it can never be mistaken for one.
        if not (cert.ca and cert.basic_constraints_present):
            other_defects.append(
                f"cert {position} ({label}) issues a following certificate "
                "but is not a CA"
            )

        # [D] 6.1.4 (l), FIRST and guarded: "If the certificate was not
        # self-issued, verify that max_path_length is greater than zero and
        # decrement max_path_length by 1."
        if not cert.self_issued:
            if max_path_length <= 0:
                trace.append(Step(position, label, cert.self_issued,
                                  "REJECT: 6.1.4 (l) budget not greater than zero",
                                  max_path_length))
                return Verdict(
                    False,
                    f"6.1.4 (l): max_path_length is {max_path_length} (not "
                    f"greater than zero) at non-self-issued certificate "
                    f"{position} ({label})",
                    trace,
                    other_defects,
                )
            max_path_length -= 1
            action = "6.1.4 (l) decrement"
        else:
            action = "6.1.4 (l) skipped: self-issued, not counted"

        # [E] 6.1.4 (m), SECOND and UNGUARDED: "If pathLenConstraint is present
        # in the certificate and is less than max_path_length, set
        # max_path_length to the value of pathLenConstraint."  No self-issued
        # condition, so this also runs for a self-issued intermediate.
        if cert.pathlen is not None and cert.pathlen < max_path_length:
            max_path_length = cert.pathlen
            action += f"; 6.1.4 (m) clamp to {cert.pathlen}"

        trace.append(Step(position, label, cert.self_issued, action,
                          max_path_length))

    return Verdict(True, "path-length budget satisfied", trace, other_defects)


def exists_valid_path(graph: dict[str, CertFacts], target: str,
                      anchor_subject: str) -> tuple[bool, list[str]]:
    """Does ANY path from the anchor to ``target`` satisfy the path-length rules?

    RFC 5280 6.1 states that obtaining the sequence of certificates "is outside
    the scope of this specification", so a conforming implementation gets to
    choose.  The validation obligation in 6.1 then applies to the path it chose.
    This helper answers the path-construction question separately from the
    path-validation question, rather than assuming a single supplied chain is
    canonical.

    ``graph`` maps subject DN -> certificate facts.  ``anchor_subject`` is the
    trust anchor's DN; the anchor itself is not a path member [G].
    """
    reasons: list[str] = []
    found = False

    def walk(current: str, path: list[CertFacts], seen: frozenset[str]) -> None:
        nonlocal found
        if found:
            return
        if current == target and path:
            verdict = validate_path(path)
            reasons.append(verdict.reason)
            if verdict.accepted:
                found = True
            return
        for subject in sorted(graph):
            if subject in seen or graph[subject].issuer != current:
                continue
            walk(subject, [*path, graph[subject]], seen | {subject})

    walk(anchor_subject, [], frozenset({anchor_subject}))
    return found, reasons
