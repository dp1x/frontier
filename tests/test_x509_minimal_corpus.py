"""Regression tests for the minimal cleanroom pathLen counterfactual.

These are not decoration. The corpus this file guards produced THREE confident,
wrong matrices before its harness was correct, and each defect would have
"discovered" an implementation bug that did not exist:

  1. certificates signed by a key no path member held -> both cores reported
     "signature does not match" on all four self-issued cells;
  2. self-issued certificates that were ALSO self-signed -> conflated the two
     axes the experiment exists to separate;
  3. the self-issued DN colliding with the trust anchor's -> both cores failed
     on the signature while the corpus looked perfect.

Every test below asserts one of those properties, so a future edit that
reintroduces any of them fails loudly instead of producing a plausible matrix.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1] / "crypto" / "x509-pathlen"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from minimal_chain import Cert, build, verify_der_claims  # noqa: E402
from minimal_oracle import Node, walk, walk_H2  # noqa: E402


@pytest.fixture(scope="module")
def corpus():
    forge, certs, cases = build()
    return forge, certs, cases


def _nodes(certs: dict[str, Cert], path: tuple[str, ...]) -> list[Node]:
    return [
        Node(label=c.label, subject=c.subject, issuer=c.issuer,
             ca=c.ca, pathlen=c.pathlen)
        for c in (certs[label] for label in path)
    ]


# ---------------------------------------------------------------------------
# Structural soundness: the three defects
# ---------------------------------------------------------------------------


def test_every_chain_is_structurally_valid(corpus):
    """Chain integrity, CA status and signature relationships, from the DER.

    `verify_der_claims` re-parses each certificate and checks RFC 5280 6.1(a)-(c)
    plus every signature relationship. It returned a non-empty problem list on
    each of the three historical defects, so this test is the one that would
    have caught them.
    """
    _, certs, cases = corpus
    assert verify_der_claims(certs, cases) == []


def test_self_issued_certificates_are_not_self_signed(corpus):
    """The self-issued axis must not be contaminated by the self-signed one.

    A self-issued certificate in the key-rollover shape carries a NEW key and is
    signed by a predecessor bearing the same DN. If it also verifies with its own
    key then the issuer and subject share a key, which is a different experiment.
    """
    _, certs, _ = corpus
    self_issued = [c for c in certs.values() if c.self_issued]
    assert self_issued, "the corpus must contain self-issued certificates"

    anchors = {"anchor"}
    for c in self_issued:
        if c.label in anchors:
            # A trust anchor is self-signed and self-issued by nature, and
            # RFC 5280 6.1 excludes it from the path entirely.
            assert c.self_signed
            continue
        assert not c.self_signed, (
            f"{c.label} is self-issued AND self-signed; the corpus needs the "
            "key-rollover shape so the two axes stay separable"
        )


def test_self_issued_dn_never_collides_with_the_trust_anchor(corpus):
    """The self-issued DN must not also be the anchor's DN.

    This is the defect that made both cores report a signature failure. If a
    self-issued certificate's subject DN equals the anchor's, then any
    certificate issued beneath it names the ANCHOR's DN as its issuer, and two
    certificates match that DN. A path builder that tries the anchor first then
    fails on the signature -- an H4 path-construction failure masquerading as an
    implementation behaviour.
    """
    _, certs, cases = corpus
    anchors = {certs[c.anchor].subject for c in cases}
    for label, c in certs.items():
        if c.self_issued and label not in {"anchor"}:
            assert c.subject not in anchors, (
                f"{label} is self-issued with subject {c.subject!r}, which is "
                f"also a trust anchor DN; this makes the chain ambiguous"
            )


def test_every_self_issued_certificate_is_actually_signed(corpus):
    """A self-issued certificate must be signed by its predecessor's key.

    Naming a non-existent issuer produces a certificate signed by nothing at
    all, which every validator rejects for a signature reason. That is a harness
    defect, not a path-length result.
    """
    _, certs, _ = corpus
    from cryptography.hazmat.primitives.asymmetric import ec

    for label, c in certs.items():
        if label == "anchor" or not c.self_issued:
            continue
        signers = []
        for other_label, other in certs.items():
            if other_label == label or other.subject != c.issuer:
                continue
            try:
                other.cert.public_key().verify(
                    c.cert.signature,
                    c.cert.tbs_certificate_bytes,
                    ec.ECDSA(c.cert.signature_hash_algorithm),
                )
            except Exception:  # noqa: BLE001 - wrong candidate
                continue
            signers.append(other_label)
        assert signers, (
            f"{label} is self-issued but is signed by no certificate in the "
            "corpus; it would be rejected for a signature reason"
        )


# ---------------------------------------------------------------------------
# The two oracles must agree, and H2 must be genuinely different
# ---------------------------------------------------------------------------


def test_the_two_oracles_agree_on_every_case(corpus):
    """The historical oracle and the fresh one must reach the same verdicts.

    `oracle.py` carries four documented wrong versions, so agreement between it
    and an independently-styled reimplementation is evidence that neither is
    wrong in the way the other is wrong. A disagreement must stop the experiment
    rather than be resolved by picking a side.
    """
    sys.path.insert(0, str(HERE))
    from oracle import CertFacts, validate_path

    _, certs, cases = corpus
    for case in cases:
        fresh = walk(_nodes(certs, case.path))
        legacy = validate_path([
            CertFacts(subject=c.subject, issuer=c.issuer, ca=c.ca,
                      pathlen=c.pathlen,
                      basic_constraints_present=c.basic_constraints_present)
            for c in (certs[label] for label in case.path)
        ])
        assert fresh.accepted == legacy.accepted, (
            f"{case.case_id}: the two oracles disagree "
            f"(fresh={fresh.accepted}, legacy={legacy.accepted})"
        )


def test_h2_is_not_vacuous(corpus):
    """H2 must actually differ from H1 somewhere, or the corpus proves nothing.

    This is the discriminating-power check as an assertion. If a future edit
    made H1 and H2 identical, every case would pass while the experiment
    silently stopped being able to distinguish the readings.
    """
    _, certs, cases = corpus
    discriminating = [
        case.case_id
        for case in cases
        if walk(_nodes(certs, case.path)).accepted
        != walk_H2(_nodes(certs, case.path)).accepted
    ]
    assert discriminating, (
        "H1 and H2 now agree on every case; the corpus no longer discriminates "
        "and cannot support a claim about which reading is correct"
    )


def test_the_isolating_case_exists_and_isolates(corpus):
    """Family C must contain the isolating case the hypothesis named.

    Under H1 both members reject; under H2 only the non-self-issued member
    rejects. That asymmetry IS the experiment.
    """
    _, certs, cases = corpus
    by_id = {c.case_id: c for c in cases}
    assert "C2_si_pl0" in by_id, "the isolating self-issued case is missing"

    si = by_id["C2_si_pl0"]
    ns = by_id["C1_ns_pl0"]
    assert len(si.path) == len(ns.path), (
        f"the isolating pair must be matched in depth: {len(si.path)} vs {len(ns.path)}"
    )

    # The variable sits at position 2 (0-indexed 2? no -- index 2 is C_si/C_c,
    # because both paths are ancestor, predecessor, variable, child, EE).
    # Locate it by self-issued status rather than hard-coding a position, so the
    # test keeps working if the family is reshaped.
    si_pos = [i for i, lbl in enumerate(si.path) if certs[lbl].self_issued]
    ns_pos = [i for i, lbl in enumerate(ns.path) if certs[lbl].self_issued]
    assert len(si_pos) == 1, "the self-issued member must have exactly one"
    assert ns_pos == [], "the control member must have none"
    pos = si_pos[0]

    # The variable is self-issued status and nothing else observable.
    si_var = certs[si.path[pos]]
    ns_var = certs[ns.path[pos]]
    assert si_var.self_issued and not ns_var.self_issued
    assert si_var.ca == ns_var.ca
    assert si_var.pathlen == ns_var.pathlen
    assert si_var.key_cert_sign == ns_var.key_cert_sign
    assert si_var.basic_constraints_present == ns_var.basic_constraints_present


# ---------------------------------------------------------------------------
# The step-(l) / step-(m) state machine
# ---------------------------------------------------------------------------


def test_self_issued_skips_the_decrement_but_still_clamps(corpus):
    """The H1 mechanism, asserted directly on the trace.

    A self-issued CA must leave max_path_length untouched by step (l) and still
    have step (m) lower it. If either half changed, the experiment would no
    longer be testing the asymmetry it was built for.
    """
    _, certs, _ = corpus
    frames = walk(_nodes(certs, ("c_anc", "C_si", "C_d_si", "C_ee_si"))).frames
    si_frame = next(f for f in frames if f.label == "C_si")

    assert si_frame.self_issued
    assert si_frame.decremented is False, "step (l) must not fire for self-issued"
    assert si_frame.after_l == si_frame.incoming_max_path_length
    assert si_frame.clamped is True, "step (m) must still apply"
    assert si_frame.final_max_path_length == si_frame.pathlen


def test_the_final_certificate_is_never_touched(corpus):
    """RFC 5280 6.1 restricts step (3) to certificates 1..n-1.

    The final certificate contributes nothing: not a decrement, not a clamp.
    """
    _, certs, _ = corpus
    outcome = walk(_nodes(certs, ("c_anc", "C_si", "C_d_si", "C_ee_si")))
    final = outcome.frames[-1]
    assert final.decremented is None
    assert final.clamped is False
    assert final.after_l == final.incoming_max_path_length