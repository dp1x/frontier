"""Tests for the Frontier pathLen oracle.

These lock down the two properties the mission depends on:

  1. The oracle reproduces RFC 5280 6.1's accept/reject decisions on hand-worked
     cases, including the case where the FINAL certificate is a CA certificate.
  2. Each discriminating pair differs in exactly one observable, and the
     self-issued variable changes the verdict.

Every expected value here is derived from RFC 5280 and is annotated with the
clause it comes from, so a reader can check the test rather than trust it.
RFC 5280 plain text, SHA-256
A2F2628C0A83B873FC4786ABD921F9B2C02395954B655D190BF16B831633345D.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "crypto" / "x509-pathlen"))

from oracle import CertFacts, validate_path  # noqa: E402

ROOT = "CN=Root"


def ca(subject: str, issuer: str, pathlen: int | None) -> CertFacts:
    return CertFacts(subject=subject, issuer=issuer, ca=True, pathlen=pathlen)


def ee(subject: str, issuer: str) -> CertFacts:
    return CertFacts(subject=subject, issuer=issuer, ca=False, pathlen=None)


def accepted(path: list[CertFacts]) -> bool:
    return validate_path(path).accepted


class TestFinalCertificateIsNotCounted:
    """RFC 5280 6.1: step (3) runs 'for all certificates in the path except the
    final certificate'.  RFC 5280 4.2.1.9: 'The last certificate in the
    certification path is not an intermediate certificate, and is not included
    in this limit.'"""

    def test_pathlen0_intermediate_with_ee_target_is_legal(self):
        # root -> ICA(0) -> EE
        assert accepted([ca("ICA", ROOT, 0), ee("EE", "ICA")])

    def test_pathlen0_intermediate_with_ca_target_is_legal(self):
        # root -> ICA(0) -> ICA(0) as the TARGET.  The final certificate is not
        # an intermediate, so it is not counted against ICA's constraint.
        assert accepted([ca("ICA", ROOT, 0), ca("ICA2", "ICA", 0)])

    def test_final_certificate_pathlen_is_not_itself_enforced(self):
        # The final certificate's own pathLenConstraint is never read: 6.1.4
        # does not run for it.  A pathlen:0 target is therefore irrelevant.
        path = [ca("ICA", ROOT, None), ca("TARGET", "ICA", 0)]
        assert accepted(path)

    def test_a_ca_after_pathlen0_is_still_a_violation(self):
        # root -> ICA(0) -> ICA(0) -> EE.  The ICA(0) in the middle is NOT the
        # final certificate, so it does count.
        path = [ca("ICA", ROOT, 0), ca("ICA2", "ICA", 0), ee("EE", "ICA2")]
        assert not accepted(path)


class TestSelfIssued:
    """RFC 5280 6.1.1: 'These self-issued certificates are not counted when
    evaluating path length'.  6.1.4 (l) conditions the decrement on
    'not self-issued'; 6.1.4 (m) carries no such condition, so a self-issued
    certificate still imposes its own pathLenConstraint."""

    def test_self_issued_intermediate_does_not_consume_budget(self):
        # root -> ICA(1) -> ICA(1 self-issued) -> EE
        path = [ca("ICA", ROOT, 1), ca("ICA", "ICA", 1), ee("EE", "ICA")]
        assert accepted(path)

    def test_non_self_issued_twin_is_also_legal_when_only_an_ee_follows(self):
        # Identical to the self-issued case except the middle certificate has
        # its own DN.  This is ACCEPTED too, and that is the point: with only an
        # EE following, nothing non-self-issued follows ICA(1), so the
        # self-issued exemption has nothing to act on.  A chain of this shape
        # does NOT discriminate the contested rule -- see
        # test_non_self_issued_twin_is_rejected_when_an_intermediate_follows.
        path = [ca("ICA", ROOT, 1), ca("ICA-alt", "ICA", 1), ee("EE", "ICA-alt")]
        assert accepted(path)

    def test_non_self_issued_twin_is_rejected_when_an_intermediate_follows(self):
        # The discriminating shape: an intermediate, not just an EE, follows the
        # middle certificate.  Now ICA(1) is followed by one non-self-issued
        # intermediate, which its constraint forbids.
        path = [ca("ICA", ROOT, 1), ca("ICA-alt", "ICA", 1),
                ca("ICA2", "ICA-alt", 0), ee("EE", "ICA2")]
        assert not accepted(path)

    def test_self_issued_twin_of_that_chain_is_accepted(self):
        path = [ca("ICA", ROOT, 1), ca("ICA", "ICA", 1),
                ca("ICA2", "ICA", 0), ee("EE", "ICA2")]
        assert accepted(path)

    def test_self_issued_certificate_still_imposes_its_own_constraint(self):
        # root -> ICA(1) -> ICA(0 self-issued) -> ICA(0) -> ICA(0) -> EE.
        # The self-issued certificate's pathLenConstraint=0 still binds the
        # intermediates that follow it, because 6.1.4 (m) carries no
        # self-issued condition.  TWO intermediates follow it, so 0 is
        # exceeded -- a single following EE would not be, since the final
        # certificate is not counted.
        path = [ca("ICA", ROOT, 1), ca("ICA", "ICA", 0),
                ca("ICA2", "ICA", 0), ca("ICA3", "ICA2", 0),
                ee("EE", "ICA3")]
        assert not accepted(path)

    def test_self_issued_pathlen0_blocks_any_following_intermediate(self):
        # root -> ICA(1) -> ICA(0 SELF-ISSUED) -> ICA(0) -> EE.
        #
        # Traced literally against 6.1.4, n = 4:
        #   i=1 ICA(1), not self-issued: mpl 4 -> 3, clamp min(3,1) = 1
        #   i=2 ICA(0), SELF-ISSUED: (l) skipped, then (m) clamp min(1,0) = 0
        #   i=3 ICA2(0), not self-issued: mpl is 0, which is NOT greater than
        #       zero, so (l) fails
        # => REJECT
        #
        # The subtlety this pins down: (m) carries NO self-issued condition, so
        # a self-issued certificate's OWN pathLenConstraint still clamps the
        # budget. An earlier formulation of the oracle skipped the check
        # entirely for self-issued certificates and wrongly ACCEPTed this.
        path = [ca("ICA", ROOT, 1), ca("ICA", "ICA", 0),
                ca("ICA2", "ICA", 0), ee("EE", "ICA2")]
        assert not accepted(path)

    def test_self_issued_without_a_constraint_does_not_block(self):
        # The same shape but the self-issued certificate carries NO
        # pathLenConstraint, so (m) does not clamp and one intermediate may
        # follow. This is the real-world key-rollover shape and it is ACCEPT.
        #
        #   i=1 ICA(1): mpl 4 -> 3, clamp to 1
        #   i=2 ICA, SELF-ISSUED, no pathLen: (l) skipped, (m) no-op -> mpl 1
        #   i=3 ICA2(0): mpl 1 > 0, so 1 -> 0, clamp min(0,0) = 0
        #   i=4 EE: final certificate, 6.1.4 not applied
        # => ACCEPT
        path = [ca("ICA", ROOT, 1), ca("ICA", "ICA", None),
                ca("ICA2", "ICA", 0), ee("EE", "ICA2")]
        assert accepted(path)


class TestPathLenIncrease:
    """A later certificate's larger pathLenConstraint cannot rescue a path an
    earlier, smaller constraint forbids: the budget is a running minimum, so it
    is monotonically non-increasing."""

    def test_increase_is_allowed_when_within_the_earlier_limit(self):
        # root -> ICA(1) -> ICA(2) -> EE
        path = [ca("ICA", ROOT, 1), ca("ICA2", "ICA", 2), ee("EE", "ICA2")]
        assert accepted(path)

    def test_increase_cannot_rescue(self):
        # root -> ICA(0) -> ICA(9) -> EE.  ICA(0) forbids any intermediate.
        path = [ca("ICA", ROOT, 0), ca("ICA2", "ICA", 9), ee("EE", "ICA2")]
        assert not accepted(path)


class TestAbsentConstraint:
    """RFC 5280 4.2.1.9: 'Where pathLenConstraint does not appear, no limit is
    imposed.'"""

    def test_absent_constraint_imposes_no_limit(self):
        path = [ca("ICA", ROOT, None), ca("A", "ICA", None),
                ca("B", "A", None), ee("EE", "B")]
        assert accepted(path)

    def test_later_constraint_still_applies(self):
        path = [ca("ICA", ROOT, None), ca("A", "ICA", None),
                ca("B", "A", 0), ca("C", "B", None), ee("EE", "C")]
        assert not accepted(path)


class TestTrustAnchor:
    """RFC 5280 6.1: when the trust anchor is provided as a self-signed
    certificate it 'is not included as part of the prospective certification
    path', so its own pathLenConstraint binds nothing."""

    def test_anchor_constraint_is_not_part_of_the_path(self):
        # The oracle never receives the anchor, so this is a statement about
        # the harness contract: validate_path's first element is certificate 1,
        # not the trust anchor.
        path = [ca("ICA", ROOT, None), ee("EE", "ICA")]
        assert accepted(path)


class TestTraceIntegrity:
    def test_trace_records_every_certificate(self):
        path = [ca("ICA", ROOT, 1), ca("ICA", "ICA", 1), ee("EE", "ICA")]
        verdict = validate_path(path)
        assert len(verdict.trace) == 3

    def test_final_certificate_is_marked_as_excluded(self):
        path = [ca("ICA", ROOT, 1), ee("EE", "ICA")]
        verdict = validate_path(path)
        assert "final certificate" in verdict.trace[-1].action

    def test_self_issued_is_flagged_in_the_trace(self):
        path = [ca("ICA", ROOT, 1), ca("ICA", "ICA", 1), ee("EE", "ICA")]
        verdict = validate_path(path)
        assert verdict.trace[1].self_issued is True

    def test_empty_path_is_rejected(self):
        assert not accepted([])

    def test_ca_lacking_basic_constraints_is_reported_separately(self):
        # 6.1.4 (k) is a CA-ness rule, not a path-length rule; the oracle must
        # not fold it into the path-length verdict.
        bad = CertFacts(subject="ICA", issuer=ROOT, ca=True, pathlen=0,
                        basic_constraints_present=False)
        verdict = validate_path([bad, ee("EE", "ICA")])
        assert verdict.other_defects
        assert verdict.accepted  # the path-length budget is still satisfied


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
