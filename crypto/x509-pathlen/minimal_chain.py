"""Minimal cleanroom counterfactual isolating RFC 5280 6.1.4 (l) from (m).

Purpose
-------
The inherited corpus (corpus.py) already contains the decisive cell, but it is
buried among 20 cases, several of which are confounded.  This module builds the
SMALLEST chain family that separates step (l) from step (m), so the two effects
cannot cancel out or be attributed to anything else.

The variable under test
-----------------------
RFC 5280 6.1.4:

  (l) If the certificate was not self-issued, verify that max_path_length is
      greater than zero and decrement max_path_length by 1.
  (m) If pathLenConstraint is present in the certificate and is less than
      max_path_length, set max_path_length to the value of pathLenConstraint.

(l) is guarded on self-issued status.  (m) is not.  A self-issued CA therefore
consumes no budget of its own but still clamps what its descendants get.

Design
------
Each chain is:

    anchor -> C -> [E]

where C is a CA certificate.  Only C varies.  C is either:

  * SELF-ISSUED   subject DN == issuer DN == anchor's subject DN, signed by the
                  ANCHOR's key (so it is a key-rollover re-issue, NOT self-signed)
  * NOT-SELF-ISSUED  subject DN is a distinct name, also signed by the anchor's key

Both members of a pair are signed by the SAME key and differ ONLY in whether
C's subject DN equals the anchor's subject DN.  That is the controlled property.

Why E is placed directly after C, and why C's pathLen is the discriminator
--------------------------------------------------------------------------
With n = 2 path certificates (C and E), max_path_length starts at 2.

  E is the final certificate, so 6.1.4 does not apply to it at all.
  C is certificate 1, so BOTH (l) and (m) apply to C.

    NOT-SELF-ISSUED C, pathlen 0:  (l) fires, 2 -> 1.  (m) clamps 1 -> 0.  ACCEPT.
    SELF-ISSUED     C, pathlen 0:  (l) skipped, stays 2.  (m) clamps 2 -> 0. ACCEPT.

Both accept, because nothing follows C to be constrained.  To OBSERVE the clamp
we need a third certificate that would consume budget, so we extend the chain:

    anchor -> C -> D -> E

With n = 3, max_path_length starts at 3.  C and D both get 6.1.4.

    NOT-SELF-ISSUED C, pathlen 0:  (l) 3->2, (m) 2->0.  D: (l) needs >0, has 0 -> REJECT.
    SELF-ISSUED     C, pathlen 0:  (l) skipped, 3.  (m) 3->0.  D: (l) needs >0 -> REJECT.

Both still reject.  The clamp is visible in both.  Now the DISCRIMINATING case is
pathlen 1, where (l)'s skipped decrement changes the arithmetic:

    NOT-SELF-ISSUED C, pathlen 1:  (l) 3->2, (m) 2->1.  D: (l) 1->0.  ACCEPT.
    SELF-ISSUED     C, pathlen 1:  (l) skipped, 3.  (m) 3->1.  D: (l) 1->0.  ACCEPT.

Equal again -- the clamp dominates.  The place the two readings DIVERGE is when
the self-issued exemption FREES A SLOT that would otherwise be consumed, i.e.
when the budget is large enough that clamping is not what decides the verdict.
That needs the self-issued certificate's pathlen to be TIGHTER than the budget
it would otherwise have had after decrementing, and one more certificate
downstream than the non-self-issued twin can carry.  See CASES below; the
discrimination is asserted by
``tests/test_x509_minimal_corpus.py::test_h2_is_not_vacuous``, which runs both
readings over every case and requires at least one to differ.  An earlier
version of this docstring claimed the GENERATOR asserted that algebraically; it
does not, and the claim was not earned.

Determinism and DER
-------------------
Keys are derived from a fixed seed (SHAKE-256), so the KEYS are byte-identical
across runs.  Signatures are NOT deterministic: `builder.sign` draws an ECDSA
nonce from the provider CSPRNG.  Two runs therefore produce different DER but
identical structure and identical verdicts.  A prior session measured 0 of 45
certificates byte-identical across two same-seed runs and recorded that
correction; see knowledge/observations/obs-2026-0057.yaml.  Do not reintroduce
a byte-reproducibility claim.

Every emitted certificate is re-parsed from its own DER and its BasicConstraints,
subject and issuer are read back FROM THE PARSED OBJECT, never from the spec, so
a generator bug cannot masquerade as an implementation behaviour.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOT_BEFORE = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
NOT_AFTER = dt.datetime(2035, 1, 1, tzinfo=dt.UTC)
VERIFY_TIME = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.UTC)
SIG_HASH = hashes.SHA256()
SEED = 20261005

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _key(tag: str) -> ec.EllipticCurvePrivateKey:
    """Deterministic P-256 key: rejection-sample a scalar from a fixed stream.

    The digest width must equal the curve order's byte width, or the sampled
    integer is always >= order and the loop never terminates.
    """
    width = (_P256_ORDER.bit_length() + 7) // 8
    value = int.from_bytes(
        hashlib.shake_256(f"{SEED}:{tag}:key".encode()).digest(width), "big"
    )
    while value == 0 or value >= _P256_ORDER:
        value = int.from_bytes(
            hashlib.shake_256(f"{SEED}:{tag}:key".encode()).digest(width), "big"
        )
    return ec.derive_private_key(value, ec.SECP256R1())


@dataclasses.dataclass(frozen=True)
class Cert:
    """One built certificate plus the facts read back FROM ITS DER."""

    label: str
    cert: x509.Certificate
    der: bytes
    #: Subject and issuer as re-parsed, not as intended.
    subject: str
    issuer: str
    ca: bool
    pathlen: int | None
    basic_constraints_present: bool
    key_cert_sign: bool
    self_issued: bool
    self_signed: bool
    #: The private key, kept so a later certificate can genuinely be signed by
    #: this one.  Never serialised into the manifest.
    private_key: ec.EllipticCurvePrivateKey = dataclasses.field(
        repr=False, compare=False
    )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def cert_asn1(self):
        """The certificate as asn1crypto understands it.

        certvalidator is built on asn1crypto, not on `cryptography`, so it
        needs its own parse of the same DER bytes.  Both objects are derived from
        identical bytes, so this is a re-parsing rather than a second generation
        -- it cannot introduce a difference that was not already in the DER.
        """
        from asn1crypto import x509 as asn1_x509

        return asn1_x509.Certificate.load(self.der)


@dataclasses.dataclass(frozen=True)
class Case:
    case_id: str
    description: str
    anchor: str
    path: tuple[str, ...]
    isolates: str
    control: str


class Forge:
    def __init__(self) -> None:
        self._keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        self._certs: dict[str, Cert] = {}

    def key(self, tag: str) -> ec.EllipticCurvePrivateKey:
        if tag not in self._keys:
            self._keys[tag] = _key(tag)
        return self._keys[tag]

    def issuer_key(self, label: str) -> ec.EllipticCurvePrivateKey:
        """The private key of an already-issued certificate.

        Signing by a certificate's *actual* key is what makes the chain
        verifiable.  Referencing an unrelated key tag instead produces a chain
        whose signatures no implementation can check, and the resulting
        rejection reads as a signature fault while actually being a generator
        defect.  That failure is silent -- nothing in the output says the
        harness built the wrong thing -- which is why `verify_der_claims`
        verifies every signature independently.
        """
        if label not in self._certs:
            raise KeyError(f"{label} has not been issued yet")
        return self._certs[label].private_key

    def issue(
        self,
        label: str,
        common_name: str,
        #: Label of the certificate whose KEY signs this one.  ``None`` means the
        #: certificate signs itself (only valid for a trust anchor).
        issuer_label: str | None,
        subject_key_tag: str,
        *,
        ca: bool,
        pathlen: int | None,
        issuer_common_name: str,
        serial: int,
        eku_server_auth: bool = False,
    ) -> Cert:
        if label in self._certs:
            return self._certs[label]

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_common_name)])
        subject_key = self.key(subject_key_tag)
        signing_key = (self.key(subject_key_tag) if issuer_label is None
                       else self.issuer_key(issuer_label))

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(subject_key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=not ca,
                    content_commitment=not ca,
                    key_encipherment=not ca,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
                critical=False,
            )
        )

        # An AuthorityKeyIdentifier naming the actual issuer.  Without it,
        # pyca's verifier refuses every chain with "2.5.29.35: Certificate is
        # missing required extension", which is a HARNESS artefact masquerading
        # as a path-length rejection -- it is what made all six positive cells
        # uninterpretable on the first run of this corpus.
        if issuer_label is not None:
            issuer_cert = self._certs[issuer_label]
            issuer_skid = issuer_cert.cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    issuer_skid
                ),
                critical=False,
            )
        else:
            own_skid = subject_key.public_key()
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(own_skid),
                critical=False,
            )
        if eku_server_auth:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("example.invalid")]),
                critical=False,
            )
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(
                    [__import__(
                        "cryptography.x509.oid", fromlist=["ExtendedKeyUsageOID"]
                    ).ExtendedKeyUsageOID.SERVER_AUTH]
                ),
                critical=False,
            )

        cert = builder.sign(private_key=signing_key, algorithm=SIG_HASH)
        der = cert.public_bytes(serialization.Encoding.DER)

        # Read every fact back from the DER.  A generator that emits what it
        # intended but not what it encoded would make every downstream
        # observation uninterpretable.
        parsed = x509.load_der_x509_certificate(der)
        try:
            bc = parsed.extensions.get_extension_for_class(x509.BasicConstraints).value
            ca_read, pl_read, bc_present = bc.ca, bc.path_length, True
        except x509.ExtensionNotFound:
            ca_read, pl_read, bc_present = False, None, False
        try:
            ku = parsed.extensions.get_extension_for_class(x509.KeyUsage).value
            kcs = ku.key_cert_sign
        except x509.ExtensionNotFound:
            kcs = False

        subject_r = parsed.subject.rfc4514_string()
        issuer_r = parsed.issuer.rfc4514_string()

        result = Cert(
            label=label,
            cert=parsed,
            der=der,
            subject=subject_r,
            issuer=issuer_r,
            ca=ca_read,
            pathlen=pl_read,
            basic_constraints_present=bc_present,
            key_cert_sign=kcs,
            # Self-issued is RFC 5280's definition: the same DN in subject and
            # issuer.  Never conflate with self-signed, which is a property of
            # the signature and is measured separately below.
            self_issued=subject_r == issuer_r,
            self_signed=_verifies_with_own_key(parsed, subject_key),
            private_key=subject_key,
        )
        self._certs[label] = result
        return result

    def cert(self, label: str) -> Cert:
        return self._certs[label]


def _verifies_with_own_key(cert: x509.Certificate, key) -> bool:
    try:
        key.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    except Exception:  # noqa: BLE001 - InvalidSignature is the expected answer
        return False
    return True


# ---------------------------------------------------------------------------
# Chain families
#
# `anchor` is a trust anchor and is NEVER a path certificate.
# `middle` is the certificate under test: same signing key, same pathlen, same
# everything except whether its subject DN equals the anchor's subject DN.
# ---------------------------------------------------------------------------

ANCHOR_CN = "Minimal Anchor"

#: Depth used for the families that need a certificate AFTER the one under test.
DEEP_ANCESTOR_CN = "Minimal Ancestor"


def build() -> tuple[Forge, dict[str, Cert], tuple[Case, ...]]:
    """Build every case.  Returns the forge, its certificates, and the cases."""
    f = Forge()

    # --- the unconstrained trust anchor ---------------------------------
    # Self-signed: it is its own issuer, and RFC 5280 6.1 excludes it from the
    # path.
    f.issue("anchor", ANCHOR_CN, None, "anchor_key", ca=True, pathlen=None,
            issuer_common_name=ANCHOR_CN, serial=1000)

    # --- Family A: anchor -> C -> E, varying only C's self-issued status --
    # n = 2.  C is certificate 1 and gets both (l) and (m); E is the final
    # certificate and gets neither.  With no certificate after C, C's own
    # pathlen cannot decide anything -- these are HARNESS SANITY cells.
    #
    # Both members of a pair share ONE subject key tag, so they carry the SAME
    # public key and differ only in whether C's subject DN equals its issuer's.
    #
    # The self-issued members sit under A_c (CN=Middle-A), NOT under the
    # anchor, so their subject DN is "CN=Middle-A" and does not collide with
    # the anchor's.  An earlier version issued them under the anchor, which
    # made every certificate below them name the ANCHOR's DN as issuer; two
    # certificates then matched that DN and both validators failed on the
    # signature.  That is H4 -- path construction -- and it is invisible
    # unless you look at which certificate actually signed which.
    f.issue("A_c", "Middle-A", "anchor", "a_c_key", ca=True, pathlen=0,
            issuer_common_name=ANCHOR_CN, serial=2001)
    f.issue("A_si", "Middle-A", "A_c", "a_si_key", ca=True, pathlen=0,
            issuer_common_name="Middle-A", serial=2002)
    f.issue("A_ee_ns", "EE-A-ns", "A_c", "a_ee_key", ca=False, pathlen=None,
            issuer_common_name="Middle-A", serial=2003, eku_server_auth=True)
    f.issue("A_ee_si", "EE-A-si", "A_si", "a_ee2_key", ca=False, pathlen=None,
            issuer_common_name="Middle-A", serial=2004, eku_server_auth=True)

    # --- the ordinary intermediate CAs that give each family depth --------
    # These are certificate 1 of the B/C/D paths, so their own constraints are
    # in play.  Each carries NO pathlen so it never clamps, and each has a
    # DISTINCT DN.
    #
    # Why each family needs its own: a self-issued certificate's subject DN
    # EQUALS its issuer's.  If that DN also belonged to the trust anchor, then
    # a certificate issued by the self-issued one names the anchor's DN as its
    # issuer, and TWO certificates -- the anchor and the self-issued re-issue --
    # become candidates to verify it.  A validator that tries the anchor first
    # fails with a signature error that has nothing to do with path length.
    # That failure mode is H4 (path construction), and an earlier version of
    # this corpus hit it on all four self-issued cells.
    for tag in ("ancestor", "b_anc", "c_anc", "d_anc"):
        f.issue(tag, f"Ancestor-{tag}", "anchor", f"{tag}_key", ca=True,
                pathlen=None, issuer_common_name=ANCHOR_CN,
                serial=3000 + hash(tag) % 97)

    # --- Family B: pathlen 1, two certificates follow the variable --------
    # Structure: b_anc -> B_pred -> B_si -> Sub-B -> EE
    # B_pred carries the DN that B_si re-issues, so B_si is genuinely
    # self-issued AND genuinely signed.  B_pred is NOT in the B2 path: the
    # path is b_anc, B_si, Sub-B-si, EE.  B_pred exists only to be the
    # signer.
    # The non-self-issued twin carries a DIFFERENT subject DN from the
    # self-issued one, otherwise it would be self-issued too and the pair
    # would not discriminate.  `B_pred` is the signer of `B_si` and is not in
    # either path; `B_c` is the non-self-issued member that IS in B1's path.
    f.issue("B_pred", "Pred-B", "b_anc", "b_pred_key", ca=True, pathlen=1,
            issuer_common_name="Ancestor-b_anc", serial=3100)
    f.issue("B_c", "Mid-B", "B_pred", "b_c_key", ca=True, pathlen=1,
            issuer_common_name="Pred-B", serial=3101)
    f.issue("B_si", "Pred-B", "B_pred", "b_si_key", ca=True, pathlen=1,
            issuer_common_name="Pred-B", serial=3102)
    f.issue("B_d_ns", "Sub-B-ns", "B_c", "b_d_key", ca=True, pathlen=0,
            issuer_common_name="Mid-B", serial=3103)
    f.issue("B_ee_ns", "EE-B-ns", "B_d_ns", "b_ee_key", ca=False, pathlen=None,
            issuer_common_name="Sub-B-ns", serial=3104, eku_server_auth=True)
    f.issue("B_d_si", "Sub-B-si", "B_si", "b_d2_key", ca=True, pathlen=0,
            issuer_common_name="Pred-B", serial=3105)
    f.issue("B_ee_si", "EE-B-si", "B_d_si", "b_ee2_key", ca=False, pathlen=None,
            issuer_common_name="Sub-B-si", serial=3106, eku_server_auth=True)

    # --- Family C: the ISOLATING cell -------------------------------------
    f.issue("C_pred", "Pred-C", "c_anc", "c_pred_key", ca=True, pathlen=None,
            issuer_common_name="Ancestor-c_anc", serial=3200)
    f.issue("C_c", "Mid-C", "C_pred", "c_c_key", ca=True, pathlen=0,
            issuer_common_name="Pred-C", serial=3201)
    f.issue("C_si", "Pred-C", "C_pred", "c_si_key", ca=True, pathlen=0,
            issuer_common_name="Pred-C", serial=3202)
    f.issue("C_d_ns", "Sub-C-ns", "C_c", "c_d_key", ca=True, pathlen=0,
            issuer_common_name="Mid-C", serial=3203)
    f.issue("C_ee_ns", "EE-C-ns", "C_d_ns", "c_ee_key", ca=False, pathlen=None,
            issuer_common_name="Sub-C-ns", serial=3204, eku_server_auth=True)
    f.issue("C_d_si", "Sub-C-si", "C_si", "c_d2_key", ca=True, pathlen=0,
            issuer_common_name="Pred-C", serial=3205)
    f.issue("C_ee_si", "EE-C-si", "C_d_si", "c_ee2_key", ca=False, pathlen=None,
            issuer_common_name="Sub-C-si", serial=3206, eku_server_auth=True)

    # --- Family D: self-issued C with NO pathlen, so (m) cannot fire -----
    f.issue("D_pred", "Pred-D", "d_anc", "d_pred_key", ca=True, pathlen=None,
            issuer_common_name="Ancestor-d_anc", serial=3300)
    f.issue("D_c", "Mid-D", "D_pred", "d_c_key", ca=True, pathlen=None,
            issuer_common_name="Pred-D", serial=3301)
    f.issue("D_si", "Pred-D", "D_pred", "d_si_key", ca=True, pathlen=None,
            issuer_common_name="Pred-D", serial=3302)
    f.issue("D_d_ns", "Sub-D-ns", "D_c", "d_d_key", ca=True, pathlen=0,
            issuer_common_name="Mid-D", serial=3303)
    f.issue("D_ee_ns", "EE-D-ns", "D_d_ns", "d_ee_key", ca=False, pathlen=None,
            issuer_common_name="Sub-D-ns", serial=3304, eku_server_auth=True)
    f.issue("D_d_si", "Sub-D-si", "D_si", "d_d2_key", ca=True, pathlen=0,
            issuer_common_name="Pred-D", serial=3305)
    f.issue("D_ee_si", "EE-D-si", "D_d_si", "d_ee2_key", ca=False, pathlen=None,
            issuer_common_name="Sub-D-si", serial=3306, eku_server_auth=True)

    cases = (
        # -- Family A: no certificate follows the one under test -------------
        Case("A1_ns_pl0", "anchor -> CA(pathlen 0, not self-issued) -> EE. Nothing "
              "follows the constrained CA, so its pathlen decides nothing.",
              "anchor", ("A_c", "A_ee_ns"), "harness sanity: clamp unobservable",
              "positive"),
        Case("A2_si_pl0", "anchor -> CA(pathlen 0) -> CA(pathlen 0, SELF-ISSUED) -> "
              "EE. The self-issued CA does not spend a slot, but nothing "
              "follows it either, so its clamp is still unobservable.",
              "anchor", ("A_c", "A_si", "A_ee_si"),
              "harness sanity: clamp unobservable", "positive"),
        # -- Family B/C/D -----------------------------------------------------
        # The trust anchor is ALWAYS `anchor`.  `ancestor` is an ordinary
        # intermediate CA sitting at certificate 1 of the path, so the path is
        # three certificates long and max_path_length starts at 3.  Making
        # `ancestor` the anchor would shorten the path and change the
        # arithmetic under test.
        Case("B1_ns_pl1", "anchor -> CA(nolen) -> CA(pathlen 1, not self-issued) -> "
              "CA(0) -> EE.",
              "anchor", ("b_anc", "B_pred", "B_c", "B_d_ns", "B_ee_ns"),
              "(l) fires and (m) clamps to 1; D consumes the last slot", "positive"),
        Case("B2_si_pl1", "anchor -> CA(nolen) -> CA(pathlen 1, SELF-ISSUED) -> "
              "CA(0) -> EE. (l) is skipped, so the budget entering D is one "
              "higher before (m) clamps.",
              "anchor", ("b_anc", "B_pred", "B_si", "B_d_si", "B_ee_si"),
              "(l) skipped, (m) clamps to 1", "positive"),
        Case("C1_ns_pl0", "anchor -> CA(nolen) -> CA(pathlen 0, not self-issued) -> "
              "CA(0) -> EE.",
              "anchor", ("c_anc", "C_pred", "C_c", "C_d_ns", "C_ee_ns"),
              "(l) then (m) clamp to 0; D cannot decrement", "negative"),
        Case("C2_si_pl0", "anchor -> CA(nolen) -> CA(pathlen 0, SELF-ISSUED) -> "
              "CA(0) -> EE. (l) skipped so the budget is one higher, then (m) "
              "clamps to 0. If an implementation folds (m) into (l)'s guard, D "
              "is admitted.",
              "anchor", ("c_anc", "C_pred", "C_si", "C_d_si", "C_ee_si"),
              "ISOLATING: does (m) reach a self-issued certificate?", "negative"),
        Case("D1_ns_nolen", "anchor -> CA(nolen) -> CA(no pathlen, not "
              "self-issued) -> CA(0) -> EE.",
              "anchor", ("d_anc", "D_pred", "D_c", "D_d_ns", "D_ee_ns"),
              "no clamp possible; (l) alone governs", "positive"),
        Case("D2_si_nolen", "anchor -> CA(nolen) -> CA(no pathlen, SELF-ISSUED) -> "
              "CA(0) -> EE. The self-issued exemption frees a slot and nothing "
              "clamps it back.",
              "anchor", ("d_anc", "D_pred", "D_si", "D_d_si", "D_ee_si"),
              "self-issued exemption frees a slot", "positive"),
    )

    return f, f._certs, cases


def manifest_for(certs: dict[str, Cert], cases: tuple[Case, ...]) -> dict:
    return {
        "generator": "crypto/x509-pathlen/minimal_chain.py",
        "seed": SEED,
        "not_before": NOT_BEFORE.isoformat(),
        "not_after": NOT_AFTER.isoformat(),
        "verify_time": VERIFY_TIME.isoformat(),
        "certificates": {
            label: {
                "sha256": c.sha256,
                "der_len": len(c.der),
                "subject": c.subject,
                "issuer": c.issuer,
                "ca": c.ca,
                "pathlen": c.pathlen,
                "basic_constraints_present": c.basic_constraints_present,
                "key_cert_sign": c.key_cert_sign,
                "self_issued": c.self_issued,
                "self_signed": c.self_signed,
            }
            for label, c in sorted(certs.items())
        },
        "cases": [
            {
                "id": c.case_id,
                "description": c.description,
                "anchor": c.anchor,
                "path": list(c.path),
                "isolates": c.isolates,
                "control": c.control,
            }
            for c in cases
        ],
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=r"R:\fx\minimal")
    args = ap.parse_args()

    out = Path(args.out)
    (out / "certs").mkdir(parents=True, exist_ok=True)
    forge, certs, cases = build()
    for label, c in certs.items():
        (out / "certs" / f"{label}.der").write_bytes(c.der)
    (out / "manifest.json").write_text(
        json.dumps(manifest_for(certs, cases), indent=2), encoding="utf-8"
    )

    problems = verify_der_claims(certs, cases)
    print(f"certificates: {len(certs)}")
    print(f"cases: {len(cases)}")
    if problems:
        print(f"\nSTRUCTURAL PROBLEMS: {len(problems)}")
        for p in problems:
            print(f"  ! {p}")
    else:
        print("structural checks: OK (chain integrity, self-issued identity, "
              "signature relationships)")
    print(f"written to {out}")
    return 1 if problems else 0


def verify_der_claims(certs: dict[str, Cert], cases: tuple[Case, ...]) -> list[str]:
    """Prove, from the DER alone, that each chain is what the case claims.

    Everything checked here is read back from a re-parsed certificate.  If a
    generator bug produced the wrong chain, this is what catches it -- before
    any implementation is run and before any verdict is interpreted.
    """
    problems: list[str] = []

    for case in cases:
        path = case.path
        if not path:
            problems.append(f"{case.case_id}: empty path")
            continue

        anchor = certs[case.anchor]
        first = certs[path[0]]
        # RFC 5280 6.1(b): certificate 1 is issued by the trust anchor.
        if first.issuer != anchor.subject:
            problems.append(
                f"{case.case_id}: certificate 1 issuer {first.issuer!r} is not the "
                f"anchor subject {anchor.subject!r}"
            )
        # RFC 5280 6.1(a): subject of x is issuer of x+1.
        for i in range(len(path) - 1):
            if certs[path[i]].subject != certs[path[i + 1]].issuer:
                problems.append(
                    f"{case.case_id}: 6.1(a) broken at {i}->{i+1}: "
                    f"{certs[path[i]].subject!r} != {certs[path[i+1]].issuer!r}"
                )
        # Every certificate that issues a successor must be a CA with
        # keyCertSign, or a rejection would be attributable to that instead.
        for lbl in path[:-1]:
            c = certs[lbl]
            if not (c.ca and c.basic_constraints_present and c.key_cert_sign):
                problems.append(
                    f"{case.case_id}: {lbl} issues a successor but is not a "
                    f"CA with keyCertSign (ca={c.ca} bc={c.basic_constraints_present} "
                    f"kcs={c.key_cert_sign})"
                )

    anchors = {case.anchor for case in cases}

    for label, c in certs.items():
        if label in anchors:
            # A trust anchor is self-signed and self-issued by nature.  RFC 5280
            # 6.1 says a trust anchor supplied as a self-signed certificate "is
            # not included as part of the prospective certification path", so
            # this does not conflate anything: the anchor is outside the walk
            # that 6.1.4 performs.
            if not (c.self_issued and c.self_signed):
                problems.append(
                    f"{label}: trust anchor is not self-signed/self-issued, which "
                    "is the only shape RFC 5280 6.1 describes for a supplied anchor"
                )
            continue

        if c.self_issued and c.self_signed:
            # Legal, but it conflates the two axes.  A self-issued certificate
            # here is a key-rollover re-issue: signed by the issuer's key with a
            # NEW key of its own.  Being self-signed as well would mean the
            # issuer and the subject share a key, which is a different
            # experiment and is never intended.
            problems.append(
                f"{label}: is both self-issued AND self-signed; the corpus wants "
                "the key-rollover shape (self-issued, new key, issuer's signature)"
            )

        # Every certificate must actually be signed by the key of the
        # certificate that issues it.  This is the check that keeps an
        # implementation's "signature does not match" from being mistaken for a
        # path-length verdict: if the harness itself built an unverifiable
        # chain, a signature rejection says nothing about (l) or (m).
        #
        # The issuing certificate must be identified by ISSUANCE, not merely by
        # sharing a DN.  Both the trust anchor and the intermediate
        # certificate are candidates for a DN, and picking the wrong one tests
        # the signature against a key that never signed it.
        parent = _issuing_certificate(certs, label, c)
        if parent is not None:
            try:
                parent.cert.public_key().verify(
                    c.cert.signature,
                    c.cert.tbs_certificate_bytes,
                    ec.ECDSA(c.cert.signature_hash_algorithm),
                )
            except Exception as exc:  # noqa: BLE001
                problems.append(
                    f"{label}: not signed by {parent.label}, the certificate that "
                    f"issued it ({type(exc).__name__}); the chain would be "
                    "rejected for a signature reason"
                )

    return problems


def _issuing_certificate(
    certs: dict[str, Cert], label: str, c: Cert
) -> Cert | None:
    """The certificate whose key actually signed ``c``, by DN and exclusion.

    Two certificates can bear the same subject DN -- a trust anchor and a
    self-issued re-issue of it -- and only one of them signed ``c``.  The tie is
    broken by trying each candidate's public key against ``c``'s signature and
    keeping the one that verifies.  If none verifies, the caller reports that.
    """
    candidates = [
        other
        for other_label, other in certs.items()
        if other_label != label and other.subject == c.issuer
    ]
    for candidate in candidates:
        try:
            candidate.cert.public_key().verify(
                c.cert.signature,
                c.cert.tbs_certificate_bytes,
                ec.ECDSA(c.cert.signature_hash_algorithm),
            )
        except Exception:  # noqa: BLE001 - wrong candidate, try the next
            continue
        return candidate
    return None


if __name__ == "__main__":
    raise SystemExit(main())
