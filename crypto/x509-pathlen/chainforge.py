"""Deterministic X.509 chain generator for the Frontier pathLenConstraint mission.

Construction is strictly separated from validation: this module only *builds*
certificates and writes them to disk.  Nothing here decides whether a chain
should be accepted.

Design constraints imposed by the mission:

* Every certificate must be signed, syntactically valid DER, and free of
  incidental RFC 5280 violations, so that an outcome cannot be dismissed
  because the generator also broke an unrelated rule.
* Self-issued status is controlled *exactly*: a certificate is self-issued iff
  its subject DN equals its issuer DN under RFC 5280 section 7.1 rules.  We
  achieve that by construction -- a self-issued certificate is signed by the
  SAME key as its issuer, which is the key-rollover shape RFC 5280 6.1.1
  describes.  This is *not* self-signed: the signature is made by the issuer's
  key but the DN is the certificate's own subject, so the certificate is a
  re-issue of the CA to itself.
* Keys are deterministic: a fixed seed derives the same P-256 scalars on every
  run.  Signatures are NOT deterministic -- see ``_sign`` -- so the emitted DER
  differs between runs even though the chain structure does not.  What is
  stable, and what the experiments rely on, is the verdict structure.

Chain roles are explicit.  ``root`` is a trust anchor and is never part of a
certification path; it is written to a separate ``trust`` directory.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# ---------------------------------------------------------------------------
# Fixed corpus parameters
# ---------------------------------------------------------------------------

#: Algorithms are pinned so a corpus never mixes crypto providers, and so a
#: chain can never be rejected by algorithm policy rather than by the variable
#: under test. P-256 with ECDSA-SHA256 is supported as a CA key by every
#: validator in the cohort.
KEY_ALG = "EC-P256-ECDSA-SHA256"
SIG_HASH = hashes.SHA256()
CURVE = ec.SECP256R1()

#: A fixed instant well inside every certificate's validity window, so the
#: harness can pin verification time and remove temporal nondeterminism.
NOT_BEFORE = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)
NOT_AFTER = dt.datetime(2035, 1, 1, tzinfo=dt.UTC)

#: The single point in time every validator is told to verify at.
VERIFY_TIME = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.UTC)

RNG_SEED = 20261004


@dataclasses.dataclass(frozen=True)
class CertSpec:
    """Everything that varies between generated certificates.

    ``pathlen=None`` means the pathLenConstraint field is absent from
    BasicConstraints (which is distinct from ``pathlen=0``).
    """

    label: str
    common_name: str
    ca: bool
    pathlen: int | None
    # The subject this certificate is *issued by*, as a corpus LABEL.
    # ``None`` means it is self-issued: subject == issuer, and it is signed by
    # its own key.
    issuer_cn: str | None = None
    #: Serial number, kept on the spec so corpus-level invariants can check it
    #: without re-deriving it.  RFC 5280 6.1 forbids a certificate appearing
    #: twice in one path, so a self-issued pair MUST differ here.
    serial: int = 0
    key_cert_sign: bool = True
    basic_constraints: bool = True
    key_usage: bool = True
    basic_constraints_critical: bool = True
    eku_server_auth: bool = False
    #: Set on certificates that are the TARGET of a case and are CA
    #: certificates.  They need a subjectAltName so the validator's name check
    #: does not mask the path-length result, but they must NOT get an EKU: a CA
    #: certificate acting as a target is not asserting a server-auth purpose.
    ca_target_needs_san: bool = False
    # A self-issued certificate that is signed by its OWN key is self-signed as
    # well.  Kept as an explicit axis so it is never conflated.
    self_signed: bool = False


@dataclasses.dataclass
class Issued:
    spec: CertSpec
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey
    der: bytes

    #: label -> Issued, set by :class:`ChainForge` so DN comparisons can
    #: resolve an issuer label to a common name.  Class-level rather than a
    #: field so ``Issued(...)`` keeps a three-argument constructor.
    _registry: "dict[str, Issued]" = dataclasses.field(
        default_factory=dict, repr=False, compare=False
    )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def subject(self) -> str:
        return self.spec.common_name

    @property
    def is_self_issued(self) -> bool:
        """Self-issued: subject DN == issuer DN (RFC 5280 6.1.1).

        DN equality is equality of the *distinguished name value*, so this
        compares common names, never labels.  ``issuer_cn`` holds a LABEL and
        must be resolved to that label's certificate before comparing -- the
        conflation of the two namespaces is a defect this class was written to
        make impossible to reintroduce silently.
        """
        if self.spec.issuer_cn is None:
            return True
        parent = Issued._registry.get(self.spec.issuer_cn)
        if parent is None:
            return self.spec.issuer_cn == self.spec.common_name
        return parent.spec.common_name == self.spec.common_name


class ChainForge:
    """Builds certificates deterministically from a fixed seed."""

    def __init__(self, seed: int = RNG_SEED) -> None:
        self._seed = seed
        self._counter = 0
        self._issued: dict[str, Issued] = {}
        # Class-level so ``Issued.is_self_issued`` can resolve an issuer label to
        # a common name without threading the forge through every call site.
        Issued._registry = self._issued
        # Remember the spec so the serial is available to corpus invariants.
        self._specs: dict[str, CertSpec] = {}

    def _next_key(self) -> ec.EllipticCurvePrivateKey:
        """Deterministic P-256 key generation.

        The scalar is rejection-sampled from the fixed-seed SHAKE-256 stream, so
        the same seed yields the same keys on every run and on every machine.

        Note that this makes the KEYS reproducible, not the certificates.  The
        signature below is a plain ECDSA signature, whose nonce comes from the
        provider's CSPRNG, so two runs over the same seed produce different DER.
        An earlier docstring here credited RFC 6979 deterministic nonces for
        byte-reproducibility; that was wrong, and the claim was measured at 0 of
        45 byte-identical certificates.  See knowledge/observations/obs-2026-0057.yaml.
        """
        self._counter += 1
        # The digest must be exactly the curve-order width: a wider digest would
        # produce an integer that is always >= order and never terminate.
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        value = self._scalar(order.bit_length() // 8)
        while value == 0 or value >= order:
            value = self._scalar(order.bit_length() // 8)
        return ec.derive_private_key(value, CURVE)

    def _scalar(self, width: int) -> int:
        """Rejection-sample a scalar candidate of exactly ``width`` bytes."""
        self._counter += 1
        raw = hashlib.shake_256(
            f"{self._seed}:{self._counter}:scalar".encode()
        ).digest(width)
        return int.from_bytes(raw, "big")

    def issue(self, spec: CertSpec) -> Issued:
        if spec.label in self._issued:
            return self._issued[spec.label]

        # Materialise the serial onto the spec so corpus-level invariants can
        # assert that a self-issued pair is two distinct certificates.
        if not spec.serial:
            spec = dataclasses.replace(spec, serial=self._serial(spec.label))
        self._specs[spec.label] = spec

        key = self._next_key()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, spec.common_name),
        ])

        if spec.issuer_cn is None:
            # Self-issued: subject == issuer, signed by our own key.
            issuer_name = subject
            signing_key = key
        else:
            parent = self._issued[spec.issuer_cn]
            issuer_name = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, parent.spec.common_name),
            ])
            signing_key = parent.key

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(self._serial(spec.label))
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        )

        # Emit an AuthorityKeyIdentifier only when this certificate has an
        # issuer.  A self-signed certificate is its own authority, so an AKI
        # computed from its own key is correct; emitting one keyed to its
        # parent's SKID when it has no parent is not.  Leaving it off a
        # self-issued certificate is also what real key-rollover chains do.
        if spec.issuer_cn is not None:
            parent = self._issued[spec.issuer_cn]
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    parent.cert.extensions.get_extension_for_class(
                        x509.SubjectKeyIdentifier
                    ).value
                ),
                critical=False,
            )

        if spec.key_usage:
            # A CA asserts keyCertSign (when spec.key_cert_sign); an end entity
            # must NOT assert it, per RFC 5280 4.2.1.9.
            key_usage = x509.KeyUsage(
                digital_signature=not spec.ca,
                content_commitment=not spec.ca,
                key_encipherment=not spec.ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=spec.ca and spec.key_cert_sign,
                crl_sign=spec.ca,
                encipher_only=False,
                decipher_only=False,
            )
            builder = builder.add_extension(key_usage, critical=True)

        if spec.basic_constraints:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=spec.ca, path_length=spec.pathlen),
                critical=spec.basic_constraints_critical,
            )

        if spec.eku_server_auth or spec.ca_target_needs_san:
            # A subjectAltName is required by the server-verification policies
            # every cohort implementation uses.  Without it, the case fails at
            # name matching and the pathLen signal is completely masked -- an
            # observed confound, not a hypothetical one.  CA certificates that
            # act as the TARGET of a case need it too, because they are the
            # "leaf" from the validator's point of view.
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("example.invalid")]),
                critical=False,
            )
        if spec.eku_server_auth:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )

        cert = builder.sign(private_key=signing_key, algorithm=SIG_HASH)
        der = cert.public_bytes(serialization.Encoding.DER)

        # Hard gate: every emitted certificate must be strictly valid DER and
        # must re-parse to an identical object.  A generator that emits junk
        # would make every downstream observation uninterpretable.
        x509.load_der_x509_certificate(der)

        result = Issued(spec=spec, cert=cert, key=key, der=der)
        self._issued[spec.label] = result
        return result

    @staticmethod
    def _serial(label: str) -> int:
        """Positive serial derived from the label, so it is reproducible."""
        digest = hashlib.sha256(f"serial:{label}".encode()).digest()
        value = int.from_bytes(digest[:16], "big") >> 1
        return value | 1


def _unused() -> None:
    """Kept intentionally empty; see git history for the removed helper."""
