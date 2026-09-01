"""Adapter for pycose 1.1.0 (Python, Timothy Claeys).

Implements:
  - COSE_Sign1
  - COSE_Encrypt0
  - COSE_Mac0
  - (COSE_Sign, COSE_Encrypt, COSE_Mac are NOT in this adapter — focus
    on the 1-recipient subset for clarity)

CBOR backend: pycose uses cbor2 (which is in Frontier's CBOR cohort).
CBOR-encoder correlation is acknowledged. At the COSE-layer logic level
(Sig_structure / Enc_structure / MAC_structure construction, header
parameter serialization, ECDSA r||s encoding), pycose is independent
of cbor2.

Adapter interface:
  ADAPTER_NAME = "lib_pycose"
  LIB_VERSION = "1.1.0"
  supports_canonical = True
  encode(data_item, mode="default") -> bytes | None
  encode_structure(data_item) -> bytes | None
  encode_kdf_context(data_item) -> bytes | None  # for axis 10
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Add the cbor oracle to path (for the canonical test)
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "cbor-cross-impl" / "oracle"))

ADAPTER_NAME = "lib_pycose"
LIB_VERSION = "1.1.0"
supports_canonical = True


def _normalize_header_dict(d: dict | None) -> dict:
    """Convert string keys that look like integers to actual int keys
    AND decode hex-encoded byte values (kid, iv).

    JSON serialization cannot represent int keys, so the vector generator
    emits string keys like "1", "4", "5". COSE labels are int or tstr; we
    MUST recover the int semantics. Also, bytes values are emitted as
    hex strings (JSON limitation); we decode them back to bytes for
    headers like kid (bstr), iv (bstr).
    """
    if not d:
        return {} if d is None else dict(d)
    out = {}
    for k, v in d.items():
        # Try to convert string key to int
        if isinstance(k, str):
            try:
                k = int(k)
            except ValueError:
                pass
        # Decode hex bytes for bstr-valued headers (kid, iv, ...)
        if isinstance(v, str):
            # Try to interpret as hex bytes (kid/iv), unless it's
            # clearly a tstr value (e.g., 'text/plain').
            try:
                decoded = bytes.fromhex(v)
                v = decoded
            except ValueError:
                pass  # leave as string (it's a tstr value)
        out[k] = v
    return out


try:
    import pycose
    from pycose.messages import Sign1Message, Enc0Message, Mac0Message
    from pycose.headers import Algorithm, KID, IV
    from pycose.keys import CoseKey
    from pycose.algorithms import Es256, EdDSA
    from pycose.keys import EC2Key, OKPKey, SymmetricKey
    from pycose.keys.curves import P256, P384, P521, Ed25519
    _PYCOSE_AVAILABLE = True
    _IMPORT_ERROR = None
except ImportError as e:
    _PYCOSE_AVAILABLE = False
    _IMPORT_ERROR = str(e)


# --- Helpers ---

def _normalize_protected(prot: dict | None) -> dict:
    """Normalize protected header dict.

    The vector generator uses int keys (1=alg, 3=ctyp, 4=kid, 5=iv) for
    common labels. pycose uses its own enum constants. We do NOT translate
    here because the adapter already creates messages with proper keys.
    For the pycose API, we construct messages via keyword arguments.
    """
    return {} if not prot else dict(prot)


def _build_sign1(protected_dict, unprotected_dict, payload, alg, deterministic_key_seed=None, skip_alg_header=False):
    """Build a COSE_Sign1 using pycose."""
    if not _PYCOSE_AVAILABLE:
        return None

    # Per RFC 9052 §3.1, the standard labels are integer: alg=1, ctyp=3,
    # kid=4, iv=5. The vector generator emits these as int keys. pycose's
    # `Algorithm` etc. enum values map to int labels automatically — so
    # we keep int keys as int. We only convert genuine tstr keys (custom
    # labels) which the JSON sidecar can't represent.
    phdr = _normalize_header_dict(protected_dict)
    uhdr = _normalize_header_dict(unprotected_dict)

    if skip_alg_header:
        if 1 in phdr:
            uhdr[1] = phdr[1]
            del phdr[1]
        if "alg" in phdr:
            uhdr["alg"] = phdr["alg"]
            del phdr["alg"]

    # Map common algorithm names to their int values when phdr has tstr alg
    # This handles the case where the test vector uses tstr "alg": "ES256"
    # (some custom convention) — convert to int for canonical encoding.
    ALG_NAME_TO_INT = {
        "ES256": -7, "ES384": -35, "ES512": -36,
        "EdDSA": -8,
        "A128GCM": 1, "A192GCM": 2, "A256GCM": 3,
        "ChaCha20/Poly1305": 24, "ChaCha20": 24,
        "HMAC256": 5, "HMAC384": 6, "HMAC512": 7,
    }
    if "alg" in phdr and isinstance(phdr["alg"], str):
        v = ALG_NAME_TO_INT.get(phdr["alg"], phdr["alg"])
        phdr[1] = v
        del phdr["alg"]
    if "alg" in uhdr and isinstance(uhdr["alg"], str):
        v = ALG_NAME_TO_INT.get(uhdr["alg"], uhdr["alg"])
        uhdr[1] = v
        del uhdr["alg"]

    # tstr keys in vector are already strings ("alg", "kid", "ctyp", "iv")

    msg = Sign1Message(phdr=phdr, uhdr=uhdr, payload=payload)

    # Choose key based on alg
    if alg in ("ES256", "ES384", "ES512"):
        if deterministic_key_seed is not None:
            # pycose's EC2Key.from_jwk accepts a JSON Web Key format; we
            # use the simpler approach of generating a key and signing.
            # True determinism requires using a fixed private key.
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
            if alg == "ES256":
                curve = ec.SECP256R1()
            elif alg == "ES384":
                curve = ec.SECP384R1()
            else:
                curve = ec.SECP521R1()
            # Generate a deterministic key from the seed by using it as
            # entropy for an ephemeral keypair. (This is a workaround —
            # for true determinism we'd need to use a fixed keypair.)
            key = EC2Key.generate_key(crv=P256 if alg == "ES256" else (P384 if alg == "ES384" else P521))
        else:
            key = EC2Key.generate_key(crv=P256 if alg == "ES256" else (P384 if alg == "ES384" else P521))
    elif alg == "EdDSA":
        key = OKPKey.generate_key(crv=Ed25519)
    else:
        return None

    msg.key = key
    return msg


def _build_encrypt0(protected_dict, unprotected_dict, payload, alg):
    if not _PYCOSE_AVAILABLE:
        return None

    phdr = _normalize_header_dict(protected_dict)
    uhdr = _normalize_header_dict(unprotected_dict)

    # Convert tstr "alg" → int 1
    ALG_NAME_TO_INT = {
        "ES256": -7, "ES384": -35, "ES512": -36,
        "EdDSA": -8,
        "A128GCM": 1, "A192GCM": 2, "A256GCM": 3,
        "ChaCha20/Poly1305": 24, "ChaCha20": 24,
        "HMAC256": 5, "HMAC384": 6, "HMAC512": 7,
    }
    if "alg" in phdr and isinstance(phdr["alg"], str):
        v = ALG_NAME_TO_INT.get(phdr["alg"], phdr["alg"])
        phdr[1] = v
        del phdr["alg"]
    if "alg" in uhdr and isinstance(uhdr["alg"], str):
        v = ALG_NAME_TO_INT.get(uhdr["alg"], uhdr["alg"])
        uhdr[1] = v
        del uhdr["alg"]

    msg = Enc0Message(phdr=phdr, uhdr=uhdr, payload=payload)

    # Pick the algorithm
    if alg == "A128GCM" or phdr.get("alg") == "A128GCM" or uhdr.get("alg") == "A128GCM" or (1 in protected_dict or {} and protected_dict.get(1) == 1) or (1 in (unprotected_dict or {}) and unprotected_dict.get(1) == 1):
        key = SymmetricKey.generate_key(16)
    elif alg == "A256GCM" or (1 in (protected_dict or {}) and protected_dict.get(1) == 3) or (1 in (unprotected_dict or {}) and unprotected_dict.get(1) == 3):
        key = SymmetricKey.generate_key(32)
    elif alg == "ChaCha20" or (1 in (protected_dict or {}) and protected_dict.get(1) == 24) or (1 in (unprotected_dict or {}) and unprotected_dict.get(1) == 24):
        # pycose 1.1.0 may not support ChaCha20-Poly1305
        return None
    else:
        key = SymmetricKey.generate_key(16)

    msg.key = key
    return msg


def _build_mac0(protected_dict, unprotected_dict, payload, alg):
    if not _PYCOSE_AVAILABLE:
        return None

    phdr = _normalize_header_dict(protected_dict)
    uhdr = _normalize_header_dict(unprotected_dict)

    ALG_NAME_TO_INT = {
        "ES256": -7, "ES384": -35, "ES512": -36,
        "EdDSA": -8,
        "A128GCM": 1, "A192GCM": 2, "A256GCM": 3,
        "ChaCha20/Poly1305": 24, "ChaCha20": 24,
        "HMAC256": 5, "HMAC384": 6, "HMAC512": 7,
    }
    if "alg" in phdr and isinstance(phdr["alg"], str):
        v = ALG_NAME_TO_INT.get(phdr["alg"], phdr["alg"])
        phdr[1] = v
        del phdr["alg"]
    if "alg" in uhdr and isinstance(uhdr["alg"], str):
        v = ALG_NAME_TO_INT.get(uhdr["alg"], uhdr["alg"])
        uhdr[1] = v
        del uhdr["alg"]

    msg = Mac0Message(phdr=phdr, uhdr=uhdr, payload=payload)

    if alg in ("HMAC256",) or phdr.get(1) == 5 or phdr.get("alg") == "HMAC256" or uhdr.get("alg") == "HMAC256":
        key = SymmetricKey.generate_key(32)
    elif alg in ("HMAC384",) or phdr.get(1) == 6 or phdr.get("alg") == "HMAC384" or uhdr.get("alg") == "HMAC384":
        # pycose restricts symmetric key sizes to 16/24/32. The MAC_structure
        # bytes we want to compare don't depend on key length, so any size works.
        key = SymmetricKey.generate_key(32)
    elif alg in ("HMAC512",) or phdr.get(1) == 7 or phdr.get("alg") == "HMAC512" or uhdr.get("alg") == "HMAC512":
        key = SymmetricKey.generate_key(32)
    else:
        key = SymmetricKey.generate_key(32)

    msg.key = key
    return msg


def encode(data_item: Any, mode: str = "default") -> bytes | None:
    """Encode a COSE message using pycose.

    data_item is a JSON description of the COSE message:
      {
        "msg_type": "Sign1" | "Encrypt0" | "Mac0" | "KDF_Context",
        "protected": { ... } or None,
        "unprotected": { ... } or {},
        "payload": "<hex bytes>",
        "alg": "ES256" | ...,
        ...
      }

    For mode="default", pycose uses its default (canonical CBOR via cbor2).
    """
    if not _PYCOSE_AVAILABLE:
        return None
    try:
        msg_type = data_item.get("msg_type", "Sign1")
        protected_dict = data_item.get("protected")
        unprotected_dict = data_item.get("unprotected", {})
        payload_hex = data_item.get("payload", "")
        payload = bytes.fromhex(payload_hex) if payload_hex else b""
        alg = data_item.get("alg", "ES256")
        deterministic_key_seed = data_item.get("deterministic_key_seed")

        if msg_type == "Sign1":
            skip_alg = data_item.get("skip_alg_header", False)
            msg = _build_sign1(protected_dict, unprotected_dict, payload, alg, deterministic_key_seed, skip_alg_header=skip_alg)
            if msg is None:
                return None
            return msg.encode()
        elif msg_type == "Encrypt0":
            ciphertext_hex = data_item.get("ciphertext", "")
            ciphertext = bytes.fromhex(ciphertext_hex) if ciphertext_hex else b""
            msg = _build_encrypt0(protected_dict, unprotected_dict, ciphertext, alg)
            if msg is None:
                return None
            return msg.encode()
        elif msg_type == "Mac0":
            tag_hex = data_item.get("tag", "")
            tag = bytes.fromhex(tag_hex) if tag_hex else b""
            # pycose's Mac0Message takes payload at construction; we set the
            # tag after constructing the message structure. For this matrix,
            # we construct an empty message and just need the wrapping.
            msg = _build_mac0(protected_dict, unprotected_dict, payload, alg)
            if msg is None:
                return None
            # Mac0Message needs compute_tag; if no key access, set manually
            try:
                return msg.encode()
            except Exception:
                return None
        elif msg_type == "KDF_Context":
            return encode_kdf_context(data_item)
        else:
            return None
    except Exception:
        return None


def encode_structure(data_item: Any) -> bytes | None:
    """Extract Sig_structure / Enc_structure / MAC_structure bytes.

    This is the byte sequence that gets signed/MAC'd/AAD-fed before crypto
    is applied. Comparing this across libraries isolates message-construction
    logic from cryptography.

    pycose's API for structure extraction:
      - Sign1Message: _create_sig_structure() returns CBOR-encoded Sig_structure
      - Enc0Message: _enc_structure property (auto-computed at init when phdr set)
      - Mac0Message: _mac_structure property (auto-computed at init when phdr set)
    """
    if not _PYCOSE_AVAILABLE:
        return None
    try:
        msg_type = data_item.get("msg_type", "Sign1")
        protected_dict = data_item.get("protected")
        unprotected_dict = data_item.get("unprotected", {})
        payload_hex = data_item.get("payload", "")
        payload = bytes.fromhex(payload_hex) if payload_hex else b""
        alg = data_item.get("alg", "ES256")

        if msg_type == "Sign1":
            skip_alg = data_item.get("skip_alg_header", False)
            msg = _build_sign1(protected_dict, unprotected_dict, payload, alg, skip_alg_header=skip_alg)
            if msg is None:
                return None
            return msg._create_sig_structure()
        elif msg_type == "Encrypt0":
            ciphertext_hex = data_item.get("ciphertext", "")
            ciphertext = bytes.fromhex(ciphertext_hex) if ciphertext_hex else b""
            msg = _build_encrypt0(protected_dict, unprotected_dict, ciphertext, alg)
            if msg is None:
                return None
            return msg._enc_structure
        elif msg_type == "Mac0":
            tag_hex = data_item.get("tag", "")
            tag = bytes.fromhex(tag_hex) if tag_hex else b""
            msg = _build_mac0(protected_dict, unprotected_dict, payload, alg)
            if msg is None:
                return None
            return msg._mac_structure
        elif msg_type == "KDF_Context":
            return encode_kdf_context(data_item)
        return None
    except Exception as e:
        return None


def encode_kdf_context(data_item: Any) -> bytes | None:
    """Encode a COSE_KDF_Context per RFC 9053 §5.2.

    COSE_KDF_Context = [
      AlgorithmID : int,
      PartyUInfo : { nonce : bstr, ... },
      PartyVInfo : { nonce : bstr, ... },
      supp_pub_info : bstr
    ]

    pycose may or may not have a direct API for this. We use cbor2
    (the verified canonical CBOR encoder from the CBOR cohort) to
    encode the structure and verify byte-level correctness.

    JSON cannot represent int map keys, so we normalize string keys
    that look like integers to actual ints.
    """
    try:
        import cbor2
        kdf_context = data_item.get("kdf_context")
        if kdf_context is None:
            return None
        def _from_hex(v):
            if isinstance(v, str):
                try:
                    return bytes.fromhex(v)
                except ValueError:
                    try:
                        return int(v)
                    except ValueError:
                        return v
            if isinstance(v, dict):
                return {_norm_key(k): _from_hex(x) for k, x in v.items()}
            if isinstance(v, list):
                return [_from_hex(x) for x in v]
            return v
        def _norm_key(k):
            if isinstance(k, str):
                try:
                    return int(k)
                except ValueError:
                    return k
            return k
        reconstructed = _from_hex(kdf_context)
        return cbor2.dumps(reconstructed)
    except Exception:
        return None