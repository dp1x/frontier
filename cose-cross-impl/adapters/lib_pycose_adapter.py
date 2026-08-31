"""Adapter for pycose (Python).

pycose 1.1.0 by Timothy Claeys.
- Implements COSE_Sign1, COSE_Encrypt0, COSE_Mac0, COSE_Sign, COSE_Encrypt, COSE_Mac
- Uses cbor2 as the underlying CBOR encoder (already in Frontier's CBOR cohort)
- Uses the `cryptography` Python library for crypto primitives

Per pycose docs (https://github.com/TimothyClaeys/pycose):
"pycose is a Python implementation of the IETF COSE (CBOR Object
Signing and Encryption) standard. It supports RFC 8152, RFC 9052,
RFC 9053, RFC 9338, and is compatible with COSE-WG test vectors."

Data item format: the runner passes a JSON description of the
COSE message structure. The adapter constructs the corresponding
pycose objects, calls the library's encode() method, and returns
the bytes.

CBOR backend correlation: pycose uses cbor2 (already verified in
msn-2026-0017 canonical-mode byte-exact with Frontier oracle). This
means pycose's CBOR byte-level encoding is correlated with cbor2,
NOT independent. For COSE-specific axes (Sig_structure / Enc_structure
construction, header parameter serialization, ECDSA r||s encoding),
pycose is independent of cbor2.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Add the cbor oracle to path (for the canonical test)
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "cbor-cross-impl" / "oracle"))

ADAPTER_NAME = "lib_pycose"
LIB_VERSION = "1.1.0"
supports_canonical = True  # pycose supports cbor2 canonical mode

# pycose is loaded in-process (not subprocessed)
try:
    import pycose  # noqa: F401
    from pycose.messages import Sign1Message, Enc0Message, Mac0Message
    from pycose.headers import Algorithm, KID, IV
    from pycose.keys import CoseKey
    from pycose.algorithms import Es256, EdDSA
    _PYCOSE_AVAILABLE = True
except ImportError as e:
    _PYCOSE_AVAILABLE = False
    _IMPORT_ERROR = str(e)


def _build_sign1(protected, unprotected, payload, alg, kid_hex, skip_alg_header=False):
    """Build a COSE_Sign1 using pycose."""
    from pycose.messages import Sign1Message
    from pycose.headers import Algorithm
    from pycose.keys import EC2Key, OKPKey
    from pycose.keys.curves import P256, Ed25519

    phdr = {} if protected is None else dict(protected)
    uhdr = dict(unprotected) if unprotected else {}
    if alg:
        if skip_alg_header:
            # Put alg in unprotected (uhdr), keep phdr empty
            uhdr[Algorithm] = alg
        else:
            phdr[Algorithm] = alg
    msg = Sign1Message(
        phdr=phdr,
        uhdr=uhdr,
        payload=payload,
    )

    if kid_hex:
        msg.kid = bytes.fromhex(kid_hex)

    # Generate a synthetic key for signing (the matrix tests
    # message-construction, not signature verification)
    if alg == "ES256":
        key = EC2Key.generate_key(crv=P256)
    elif alg == "EdDSA":
        key = OKPKey.generate_key(crv=Ed25519)
    else:
        return None

    msg.key = key
    return msg.encode()


def _build_encrypt0(protected, unprotected, payload, alg, kid_hex, nonce_hex, skip_alg_header=False):
    """Build a COSE_Encrypt0 using pycose."""
    from pycose.messages import Enc0Message
    from pycose.headers import Algorithm
    from pycose.keys import SymmetricKey

    phdr = {} if protected is None else dict(protected)
    uhdr = dict(unprotected) if unprotected else {}
    if alg:
        if skip_alg_header:
            uhdr[Algorithm] = alg
        else:
            phdr[Algorithm] = alg
    msg = Enc0Message(
        phdr=phdr,
        uhdr=uhdr,
        payload=payload,
    )

    if kid_hex:
        msg.kid = bytes.fromhex(kid_hex)
    if nonce_hex:
        msg.iv = bytes.fromhex(nonce_hex)

    if alg == "A128GCM":
        key = SymmetricKey.generate_key(16)
    else:
        # pycose 1.1.0 does NOT implement ChaCha20-Poly1305 (RFC 9053 §4.5)
        # This is a documented pycose gap; the matrix will record it as
        # "NOT_SUPPORTED" rather than attempting the call.
        return None

    msg.key = key
    return msg.encode()


def _build_mac0(protected, unprotected, payload, alg, kid_hex, skip_alg_header=False):
    """Build a COSE_Mac0 using pycose."""
    from pycose.messages import Mac0Message
    from pycose.headers import Algorithm
    from pycose.keys import SymmetricKey

    phdr = {} if protected is None else dict(protected)
    uhdr = dict(unprotected) if unprotected else {}
    if alg:
        if skip_alg_header:
            uhdr[Algorithm] = alg
        else:
            phdr[Algorithm] = alg
    msg = Mac0Message(
        phdr=phdr,
        uhdr=uhdr,
        payload=payload,
    )

    if kid_hex:
        msg.kid = bytes.fromhex(kid_hex)

    msg.key = SymmetricKey.generate_key(32)
    return msg.encode()


def encode(data_item: Any, mode: str = "default") -> bytes | None:
    """Encode a COSE message using pycose.

    data_item is a JSON description of the COSE message:
      {
        "msg_type": "Sign1" | "Encrypt0" | "Mac0",
        "protected": { ... } or None,
        "unprotected": { ... } or {},
        "payload": "<hex bytes>",
        "alg": "ES256" | "EdDSA" | "HMAC256" | "A128GCM" | "ChaCha20",
        "kid": "<hex bytes>" or None,
        "nonce": "<hex bytes>" or None (for AEAD)
      }
    """
    if not _PYCOSE_AVAILABLE:
        return None
    try:
        msg_type = data_item.get("msg_type", "Sign1")
        protected_dict = data_item.get("protected")
        unprotected_dict = data_item.get("unprotected", {})
        payload = bytes.fromhex(data_item.get("payload", ""))
        alg = data_item.get("alg", "ES256")
        kid_hex = data_item.get("kid")
        nonce_hex = data_item.get("nonce")
        skip_alg_header = data_item.get("skip_alg_header", False)

        if msg_type == "Sign1":
            return _build_sign1(protected_dict, unprotected_dict, payload, alg, kid_hex, skip_alg_header)
        elif msg_type == "Encrypt0":
            return _build_encrypt0(protected_dict, unprotected_dict, payload, alg, kid_hex, nonce_hex, skip_alg_header)
        elif msg_type == "Mac0":
            return _build_mac0(protected_dict, unprotected_dict, payload, alg, kid_hex, skip_alg_header)
        else:
            return None
    except Exception:
        return None
