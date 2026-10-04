"""The Frontier-controlled minimal pathLen corpus.

Every case is built from :class:`chainforge.CertSpec` values that differ from a
neighbouring case in exactly ONE semantic variable wherever that is possible.
The corpus deliberately does NOT copy x509-limbo's chains: those are used only
as an experimental substrate by a separate phase.

Axes covered, and why each is present:

* ``pathlen`` absent vs 0 vs positive -- the three distinct states of the
  BasicConstraints field.
* EE vs CA as the FINAL certificate -- RFC 5280 6.1 restricts step (3) to
  certificates 1..n-1, and 4.2.1.9 says the last certificate "is not an
  intermediate certificate, and is not included in this limit".
* self-issued vs non-self-issued -- the contested variable.
* TWO discriminating pairs at matched depth and matched pathLen values, one of
  which puts the variable on the certificate whose constraint actually decides.
* pathLen that appears to increase along a path (1 then 2).
* a constrained trust anchor -- tests whether the anchor's own pathLen applies.
* BasicConstraints non-critical, keyCertSign absent -- controls so a pathLen
  outcome cannot be attributed to them.

Structural invariants (all enforced by ``gen_corpus.py``, not assumed)
---------------------------------------------------------------------
``I1`` Chain integrity.  Every path satisfies RFC 5280 6.1(a)-(c): certificate 1
     is issued by the named trust anchor, and the subject of certificate x is
     the issuer of certificate x+1.  This invariant was added after two earlier
     versions of this corpus had 6.1(a) violations, which made every
     path-length observation on those chains uninterpretable.

``I2`` DN uniqueness modulo issuance.  Two certificates may share a subject DN
     only if one issues the other, and then they must differ in serial number
     (RFC 5280 6.1: "A certificate MUST NOT appear more than once in a
     prospective certification path").  Sharing a DN *is* self-issuance when the
     DN belongs to the issuer, so the rule is "shared DN implies a real
     issuer relationship", not "no shared DNs".

``I3`` Pair isolation.  The members of each discriminating pair differ in
     exactly one observable: whether the designated certificate's subject DN
     equals its issuer's DN.

A caution that cost real time here: ``CertSpec.issuer_cn`` holds a corpus
*LABEL*, while self-issued status is a statement about the issuer's *common
name*.  Conflating the two makes "is this self-issued?" ambiguous.  Every
self-issued certificate therefore is issued by a certificate whose label and
common name are both spelled out explicitly.
"""

from __future__ import annotations

import dataclasses

from chainforge import CertSpec


@dataclasses.dataclass(frozen=True)
class Case:
    """One test case: an ordered path plus its trust anchor.

    ``path`` is ordered TRUST-ANCHOR-FIRST, matching RFC 5280's own numbering
    (certificate 1 is closest to the trust anchor, certificate n is the target).
    ``expect`` is deliberately unused: the Frontier oracle fills the outcome in
    from the normative rule, never from x509-limbo and never from one
    implementation's behaviour.
    """

    case_id: str
    description: str
    anchor: str
    path: tuple[str, ...]
    isolates: str
    notes: str = ""


#: Corpus labels for the trust anchors.  ``root`` is unconstrained;
#: ``root_pl0`` carries a pathlen:0 constraint of its own so the "does the
#: anchor's constraint apply?" axis can be exercised.
ROOT = "root"
ROOT_CONSTRAINED = "root_pl0"


def _specs() -> dict[str, CertSpec]:
    # label                 label        common name        ca  pathlen issuer label
    return {
        # ---- trust anchors (never part of a certification path) ------------
        ROOT: CertSpec(ROOT, "Frontier Test Root", True, None, None),
        ROOT_CONSTRAINED: CertSpec(ROOT_CONSTRAINED, "Frontier Root pl0", True, 0, None),

        # ---- depth-1 intermediates under the unconstrained root -------------
        "ica0": CertSpec("ica0", "ICA-A pl0", True, 0, ROOT),
        "ica1": CertSpec("ica1", "ICA-B pl1", True, 1, ROOT),
        # A second CA with the SAME pathLen:1 as ica1 but a distinct DN, so the
        # two discriminating pairs differ only in their pathLen values and not
        # in their overall shape.
        "ica1b": CertSpec("ica1b", "ICA-B2 pl1", True, 1, ROOT),
        "ica2": CertSpec("ica2", "ICA-C pl2", True, 2, ROOT),
        "ica_nolen": CertSpec("ica_nolen", "ICA-D nolen", True, None, ROOT),

        # ---- depth-2 intermediates -----------------------------------------
        # Each carries its OWN DN, because a certificate cannot issue two
        # certificates that both bear its own DN and differ only in serial:
        # the chain would then be ambiguous (RFC 5280 6.1 forbids one
        # certificate appearing twice in a path).
        "icb0_under_ica1": CertSpec("icb0_under_ica1", "ICB-G pl0", True, 0, "ica1"),
        "icb2_under_ica1": CertSpec("icb2_under_ica1", "ICB-I pl2", True, 2, "ica1"),
        "icb0_under_ica0": CertSpec("icb0_under_ica0", "ICB-K pl0", True, 0, "ica0",
                                    ca_target_needs_san=True),
        "icb_under_nolen": CertSpec("icb_under_nolen", "ICB-L nolen", True, None,
                                    "ica_nolen"),
        "icb0_under_nolen": CertSpec("icb0_under_nolen", "ICB-M pl0", True, 0,
                                     "icb_under_nolen"),
        # Children of the pair members.  A certificate CANNOT issue two
        # certificates bearing its own DN, so the self-issued and non-self-issued
        # twins need SEPARATE but otherwise identical children.
        "icd0_under_si0": CertSpec("icd0_under_si0", "ICD-A pl0", True, 0,
                                   "si0_under_ica1"),
        "icd0_under_ns0": CertSpec("icd0_under_ns0", "ICD-B pl0", True, 0,
                                   "ns0_under_ica1"),
        "icd0_under_si1": CertSpec("icd0_under_si1", "ICD-C pl0", True, 0,
                                   "si1_under_ica1b", ca_target_needs_san=True),
        "icd0_under_ns1": CertSpec("icd0_under_ns1", "ICD-D pl0", True, 0,
                                   "ns1_under_ica1b"),
        "icd0_under_icb0_ica1": CertSpec("icd0_under_icb0_ica1", "ICD-G pl0", True, 0,
                                         "icb0_under_ica1"),
        # Child of a CA issued by the constrained trust anchor.
        "ice_under_root_pl0": CertSpec("ice_under_root_pl0", "ICE-A", True, None,
                                       ROOT_CONSTRAINED),

        # ---- SELF-ISSUED certificates --------------------------------------
        # subject DN == issuer's DN, signed by the issuer's key: the key-rollover
        # shape RFC 5280 6.1.1 describes.  NOT self-signed.  Only ONE of these
        # may bear a given issuer's DN, because two certificates with the same
        # subject AND the same issuer would make "which one is self-issued?"
        # ambiguous.  So si0_under_ica1 carries ica1's DN (and is used by the
        # pair that needs it); the others get distinct subjects.
        "si0_under_ica1": CertSpec("si0_under_ica1", "ICA-B pl1", True, 0, "ica1"),
        "si1_under_ica1b": CertSpec("si1_under_ica1b", "ICA-B2 pl1", True, 1, "ica1b"),

        # ---- NOT self-issued twins ------------------------------------------
        # Same issuing CA, same key, same pathLen, same position -- but a
        # distinct subject DN.  These are the member-A halves of both pairs.
        "ns0_under_ica1": CertSpec("ns0_under_ica1", "ICA-B pl1 alt", True, 0, "ica1"),
        "ns1_under_ica1b": CertSpec("ns1_under_ica1b", "ICA-B2 pl1 alt", True, 1,
                                    "ica1b"),

        "si2_under_ica2": CertSpec("si2_under_ica2", "ICA-C pl2", True, 2, "ica2"),
        "icd0_under_si2": CertSpec("icd0_under_si2", "ICD-F pl0", True, 0,
                                   "si2_under_ica2"),
        "ee_under_icd0_under_si2": CertSpec("ee_under_icd0_under_si2", "EE-23", False,
                                            None, "icd0_under_si2",
                                            eku_server_auth=True),
        # ---- confounder controls --------------------------------------------
        "ica0_nokcs": CertSpec("ica0_nokcs", "ICA-E pl0 no keyCertSign", True, 0, ROOT,
                               key_cert_sign=False),
        "icb_under_nokcs": CertSpec("icb_under_nokcs", "ICB-N", True, None, "ica0_nokcs"),
        "ica0_noncrit": CertSpec("ica0_noncrit", "ICA-F pl0 BC noncritical", True, 0,
                                 ROOT, basic_constraints_critical=False),
        "icb_under_noncrit": CertSpec("icb_under_noncrit", "ICB-O", True, None,
                                      "ica0_noncrit"),

        # ---- end entities ----------------------------------------------------
        "ee_under_ica0": CertSpec("ee_under_ica0", "EE-1", False, None, "ica0",
                                  eku_server_auth=True),
        "ee_under_ica1": CertSpec("ee_under_ica1", "EE-2", False, None, "ica1",
                                  eku_server_auth=True),
        "ee_under_ica2": CertSpec("ee_under_ica2", "EE-3", False, None, "ica2",
                                  eku_server_auth=True),
        "ee_under_icb2_under_ica1": CertSpec("ee_under_icb2_under_ica1", "EE-6",
                                             False, None, "icb2_under_ica1",
                                             eku_server_auth=True),
        "ee_under_icb0_under_ica0": CertSpec("ee_under_icb0_under_ica0", "EE-8",
                                             False, None, "icb0_under_ica0",
                                             eku_server_auth=True),
        "ee_under_icd0_under_si0": CertSpec("ee_under_icd0_under_si0", "EE-15", False,
                                            None, "icd0_under_si0",
                                            eku_server_auth=True),
        "ee_under_icd0_under_si1": CertSpec("ee_under_icd0_under_si1", "EE-17", False,
                                            None, "icd0_under_si1",
                                            eku_server_auth=True),
        "ee_under_icd0_under_ns0": CertSpec("ee_under_icd0_under_ns0", "EE-16", False,
                                            None, "icd0_under_ns0",
                                            eku_server_auth=True),
        "ee_under_icd0_under_ns1": CertSpec("ee_under_icd0_under_ns1", "EE-18", False,
                                            None, "icd0_under_ns1",
                                            eku_server_auth=True),
        "ee_under_icd0_under_icb0_ica1": CertSpec("ee_under_icd0_under_icb0_ica1",
                                                   "EE-21", False, None,
                                                   "icd0_under_icb0_ica1",
                                                   eku_server_auth=True),
        "ee_under_ice_root_pl0": CertSpec("ee_under_ice_root_pl0", "EE-22", False, None,
                                          "ice_under_root_pl0",
                                          eku_server_auth=True),
        "ee_under_icb_under_nolen": CertSpec("ee_under_icb_under_nolen", "EE-9",
                                             False, None, "icb_under_nolen",
                                             eku_server_auth=True),
        "ee_under_icb0_under_nolen": CertSpec("ee_under_icb0_under_nolen", "EE-10",
                                              False, None, "icb0_under_nolen",
                                              eku_server_auth=True),
        "ee_under_si0_under_ica1": CertSpec("ee_under_si0_under_ica1", "EE-11", False,
                                            None, "si0_under_ica1",
                                            eku_server_auth=True),
        "ee_under_icb_under_nokcs": CertSpec("ee_under_icb_under_nokcs", "EE-13", False,
                                             None, "icb_under_nokcs",
                                             eku_server_auth=True),
        "ee_under_icb_under_noncrit": CertSpec("ee_under_icb_under_noncrit", "EE-14",
                                               False, None, "icb_under_noncrit",
                                               eku_server_auth=True),
    }


CASES: tuple[Case, ...] = (
    # ---- controls: ordinary pathLen, EE target ---------------------------
    Case("c01_pl0_ee", "root -> ICA(pl0) -> EE. Nothing may follow the pathlen:0 "
          "CA, and an EE follows it.",
          ROOT, ("ica0", "ee_under_ica0"), "baseline: pathlen=0 with an EE target"),

    Case("c02_pl1_ee", "root -> ICA(pl1) -> EE.", ROOT,
         ("ica1", "ee_under_ica1"), "baseline: pathlen=1 with an EE target"),

    Case("c03_pl2_ee", "root -> ICA(pl2) -> EE.", ROOT,
         ("ica2", "ee_under_ica2"), "baseline: pathlen=2 with an EE target"),

    # ---- the final certificate IS a CA certificate ------------------------
    Case("c04_pl0_ca_target", "root -> ICA(pl0) -> ICA(pl0) as TARGET. RFC 5280 6.1 "
          "restricts step (3) to certificates 1..n-1, and 4.2.1.9 says the last "
          "certificate is not included in the limit.",
          ROOT, ("ica0", "icb0_under_ica0"), "final certificate is a CA certificate"),

    # ---- straightforward violation ----------------------------------------
    Case("c05_pl0_violation", "root -> ICA(pl0) -> ICA(pl0) -> EE. A CA follows a "
          "pathlen:0 CA.", ROOT,
         ("ica0", "icb0_under_ica0", "ee_under_icb0_under_ica0"),
         "plain pathLen violation"),

    Case("c06_pl1_too_long", "root -> ICA(1) -> ICA(0) -> ICA(0) -> EE. Violates "
          "the second intermediate's pathlen:0.", ROOT,
         ("ica1", "icb0_under_ica1", "icd0_under_icb0_ica1",
          "ee_under_icd0_under_icb0_ica1"),
         "violation at depth 2"),

    # ---- pathLen that appears to increase along the path -------------------
    Case("c07_pathlen_increase", "root -> ICA(1) -> ICA(2) -> EE. The second "
          "intermediate's pathlen:2 exceeds the first's pathlen:1.", ROOT,
         ("ica1", "icb2_under_ica1", "ee_under_icb2_under_ica1"),
          "pathLen increase along the path"),

    Case("c08_nolen_then_pl0", "root -> ICA(nolen) -> ICA(0) -> EE.", ROOT,
         ("ica_nolen", "icb_under_nolen", "ee_under_icb_under_nolen"),
         "absent pathLen imposes no limit"),

    Case("c09_nolen_then_violation", "root -> ICA(nolen) -> ICA(0) -> ICA(0) -> EE. "
          "Only the second intermediate constrains.", ROOT,
         ("ica_nolen", "icb_under_nolen", "icb0_under_nolen",
          "ee_under_icb0_under_nolen"),
         "violation only where a pathLen is actually present"),

    # ---- PAIR 1 (mirrors the x509-limbo chain shape) ----------------------
    # 4 certificates, pathLen values (1, 1, 0), variable on the middle
    # certificate.  Both members reject, for different reasons -- which is the
    # point: this shape does not discriminate the self-issued reading.
    Case("c10_pair1_nonself", "root -> ICA(1) -> ICA(1, NOT self-issued) -> "
          "ICA(0) -> EE. The middle certificate is issued by the first ICA with "
          "its key but carries its own subject DN.", ROOT,
         ("ica1b", "ns1_under_ica1b", "icd0_under_ns1", "ee_under_icd0_under_ns1"),
          "pair 1, member A: middle certificate not self-issued"),

    Case("c11_pair1_selfissued", "root -> ICA(1) -> ICA(1 SELF-ISSUED) -> ICA(0) -> "
          "EE. Identical to c10 except the middle certificate's subject equals "
          "its issuer.", ROOT,
         ("ica1b", "si1_under_ica1b", "icd0_under_si1", "ee_under_icd0_under_si1"),
          "pair 1, member B: middle certificate self-issued"),

    # ---- PAIR 2 (the sharp one) -------------------------------------------
    # Same depth, same pathLen values (1, 0, 0), but the variable sits on the
    # pathlen:0 certificate -- the one whose constraint actually decides.  The
    # two members are therefore predicted to DIFFER, unlike pair 1.
    Case("c12_pair2_nonself", "root -> ICA(1) -> ICA(0, NOT self-issued) -> "
          "ICA(0) -> EE.", ROOT,
         ("ica1", "ns0_under_ica1", "icd0_under_ns0", "ee_under_icd0_under_ns0"),
          "pair 2, member A: the pathlen:0 certificate is not self-issued"),

    Case("c13_pair2_selfissued", "root -> ICA(1) -> ICA(0 SELF-ISSUED) -> ICA(0) "
          "-> EE. Identical to c12 except the constrained certificate's subject "
          "equals its issuer.", ROOT,
         ("ica1", "si0_under_ica1", "icd0_under_si0", "ee_under_icd0_under_si0"),
          "pair 2, member B: the pathlen:0 certificate is self-issued"),

    # ---- self-issued variants ---------------------------------------------
    Case("c14_selfissued_pl0_ee", "root -> ICA(pl1) -> ICA(pl0 SELF-ISSUED) -> EE. "
          "The self-issued certificate's own pathlen:0 still binds, because "
          "6.1.4 (m) carries no self-issued condition.", ROOT,
         ("ica1", "si0_under_ica1", "ee_under_si0_under_ica1"),
          "self-issued intermediate with pathlen:0, EE target"),

    Case("c15_selfissued_pl1_ca_target", "root -> ICA(1) -> ICA(1 SELF-ISSUED) -> "
          "ICA as TARGET. Tests whether the self-issued certificate's own "
          "pathlen:1 applies when the only certificate that follows it is the "
          "target.", ROOT,
         ("ica1b", "si1_under_ica1b", "icd0_under_si1"),
          "self-issued intermediate, CA certificate as target"),

    Case("c16_downstream_does_not_rescue", "root -> ICA(0) -> ICA(0, NOT "
          "self-issued) -> EE. The first intermediate is pathlen:0 and a CA "
          "follows it; nothing downstream can rescue that.", ROOT,
         ("ica0", "icb0_under_ica0", "ee_under_icb0_under_ica0"),
          "a downstream certificate does not rescue an earlier violation"),

    Case("c20_slot_sensitivity_pl2", "root -> ICA(2) -> ICA(2 SELF-ISSUED) -> "
          "ICA(0) -> EE. Same shape as c11 but the first intermediate has "
          "pathlen:2, so one extra slot is available. Together with c11 this "
          "locates the boundary at which the self-issued exemption stops "
          "mattering.", ROOT,
         ("ica2", "si2_under_ica2", "icd0_under_si2", "ee_under_icd0_under_si2"),
          "slot sensitivity: does the self-issued exemption free a slot?"),

    # ---- constrained trust anchor ------------------------------------------
    Case("c17_anchor_constrained", "root(pl0) -> ICA -> EE. The anchor is the trust "
          "anchor and 6.1 says it is not part of the path, so its own pathlen:0 "
          "constrains nothing.", ROOT_CONSTRAINED,
         ("ice_under_root_pl0", "ee_under_ice_root_pl0"), "trust-anchor pathLen placement"),

    # ---- confounder controls ----------------------------------------------
    Case("c18_keycertsign_control", "Intermediate without keyCertSign. Any "
          "rejection must be attributable to key usage, not path length.",
          ROOT, ("ica0_nokcs", "icb_under_nokcs", "ee_under_icb_under_nokcs"),
          "control: keyCertSign absent"),

    Case("c19_bc_noncritical_control", "BasicConstraints present but non-critical "
          "on a signing CA.", ROOT,
         ("ica0_noncrit", "icb_under_noncrit", "ee_under_icb_under_noncrit"),
          "control: BasicConstraints non-critical"),
)


def build_all(forge) -> dict[str, object]:
    """Materialise every certificate referenced by :data:`CASES`.

    Issuance is dependency-ordered: a certificate is issued after the
    certificate it names as ``issuer_cn``.  Dict insertion order happens to work
    for the shallow cases but silently breaks for any label added out of order,
    so the ordering is derived rather than assumed.
    """
    specs = _specs()
    issued: dict[str, object] = {}
    remaining = dict(specs)
    while remaining:
        ready = [
            label for label, spec in remaining.items()
            if spec.issuer_cn is None or spec.issuer_cn in issued
        ]
        if not ready:
            missing = ", ".join(
                f"{label} needs {spec.issuer_cn}"
                for label, spec in remaining.items()
                if spec.issuer_cn is not None and spec.issuer_cn not in specs
            )
            raise KeyError(f"unresolvable issuer labels: {missing or remaining}")
        for label in ready:
            issued[label] = forge.issue(remaining.pop(label))
    return issued
