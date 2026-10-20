from __future__ import annotations

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

OUT = Path(r"R:\x509-selfissued")

def key(tag: str) -> ec.EllipticCurvePrivateKey:
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    width = (order.bit_length() + 7) // 8
    val = int.from_bytes(hashlib.shake_256(f"x509-selfissued:{tag}".encode()).digest(width), "big")
    while val == 0 or val >= order:
        val = int.from_bytes(hashlib.shake_256(f"x509-selfissued:{tag}:retry".encode()).digest(width), "big")
    return ec.derive_private_key(val, ec.SECP256R1())

def issue(subject_cn, issuer_cn, signing_key, subject_key, ca, pathlen, serial, san=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    )
    # AKI
    # For self-signed anchor, issuer is itself; create AKI from own key.
    # We'll handle AKI after we have issuer cert; for simplicity, if issuer_cn == subject_cn and same key, use from_issuer_public_key.
    # But for issued certs, caller will set AKI separately. We'll instead build AKI here based on a flag.
    cert = builder.sign(private_key=signing_key, algorithm=hashes.SHA256())
    return cert

# We'll instead create a helper class to manage AKI by issuer cert.
class Issuer:
    pass

def make_cert(subject_cn, issuer_cn, signing_key, subject_key, ca, pathlen, serial, issuer_cert=None, san=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
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
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
    )
    if issuer_cert is not None:
        issuer_skid = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_skid),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(subject_key.public_key()),
            critical=False,
        )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("example.invalid")]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = builder.sign(private_key=signing_key, algorithm=hashes.SHA256())
    return cert

def dump(cert, path_prefix):
    der = cert.public_bytes(serialization.Encoding.DER)
    Path(path_prefix + ".der").write_bytes(der)
    Path(path_prefix + ".pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    parsed = x509.load_der_x509_certificate(der)
    bc = parsed.extensions.get_extension_for_class(x509.BasicConstraints).value
    print(f"{path_prefix}: subject={parsed.subject.rfc4514_string()} issuer={parsed.issuer.rfc4514_string()} ca={bc.ca} pathlen={bc.path_length}")
    return parsed, der

# Keys
kR = key("R"); kC0 = key("C0"); kC2 = key("C2")
kS_none = key("S_none"); kS0 = key("S0"); kS1 = key("S1")
kIC = key("IC"); kIS0 = key("IS0"); kIS1 = key("IS1"); kEE = key("EE")

# R anchor
R = make_cert("Root", "Root", kR, kR, True, None, 1000, None)
dump(R, str(OUT / "certs" / "R"))

# C0 (pathlen 0) issued by R
C0 = make_cert("CA-A", "Root", kR, kC0, True, 0, 2000, R)
dump(C0, str(OUT / "certs" / "C0"))

# C2 (pathlen 2) issued by R
C2 = make_cert("CA-A", "Root", kR, kC2, True, 2, 2001, R)
dump(C2, str(OUT / "certs" / "C2"))

# I_C issued by C0
IC = make_cert("ICA-C", "CA-A", kC0, kIC, True, 0, 3000, C0)
dump(IC, str(OUT / "certs" / "IC"))

# S_none issued by C0, self-issued subject=issuer=CA-A, no pathlen
S_none = make_cert("CA-A", "CA-A", kC0, kS_none, True, None, 4000, C0)
dump(S_none, str(OUT / "certs" / "S_none"))

# S0 issued by C2, pathlen 0
S0 = make_cert("CA-A", "CA-A", kC2, kS0, True, 0, 4001, C2)
dump(S0, str(OUT / "certs" / "S0"))

# S1 issued by C2, pathlen 1
S1 = make_cert("CA-A", "CA-A", kC2, kS1, True, 1, 4002, C2)
dump(S1, str(OUT / "certs" / "S1"))

# I_S for S0
IS0 = make_cert("ICA-S", "CA-A", kS0, kIS0, True, 0, 5000, S0)
dump(IS0, str(OUT / "certs" / "IS0"))

# I_S for S1 (same key? use new key)
kIS1 = key("IS1")
IS1 = make_cert("ICA-S", "CA-A", kS1, kIS1, True, 0, 5001, S1)
dump(IS1, str(OUT / "certs" / "IS1"))

# EEs
EE_T1 = make_cert("EE-T1", "CA-A", kC0, kEE, False, None, 6000, C0, san=True)
dump(EE_T1, str(OUT / "certs" / "EE_T1"))
# T2 EE issued by IC
kEE2 = key("EE2")
EE_T2 = make_cert("EE-T2", "ICA-C", kIC, kEE2, False, None, 6001, IC, san=True)
dump(EE_T2, str(OUT / "certs" / "EE_T2"))
# T3 EE issued by S_none
kEE3 = key("EE3")
EE_T3 = make_cert("EE-T3", "CA-A", kS_none, kEE3, False, None, 6002, S_none, san=True)
dump(EE_T3, str(OUT / "certs" / "EE_T3"))
# T4/T5 EE issued by IS0/IS1
kEE4 = key("EE4")
EE_T4 = make_cert("EE-T4", "ICA-S", kIS0, kEE4, False, None, 6003, IS0, san=True)
dump(EE_T4, str(OUT / "certs" / "EE_T4"))
kEE5 = key("EE5")
EE_T5 = make_cert("EE-T5", "ICA-S", kIS1, kEE5, False, None, 6004, IS1, san=True)
dump(EE_T5, str(OUT / "certs" / "EE_T5"))

print("done")
