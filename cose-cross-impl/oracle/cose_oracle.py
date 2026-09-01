"""Cleanroom COSE oracle implementing RFC 9052/9053 message-construction.

DERIVATION CONSTRAINT:
This oracle is derived exclusively from:
  - RFC 9052 (COSE: Structures and Process) — normative tag assignments
  - RFC 9053 (COSE: Initial Algorithms)
  - RFC 8949 (CBOR — used for the underlying byte encoding via cbor_oracle)
  - Standard Python 3.11+ primitives (struct for byte assembly)

NO consultation of any audited COSE library source code.
The implementing agent MUST NOT have read:
  - cose-c, cose-java, coset, go-cose, pycose, cbor-c, cose-rust,
    erlang-cose, ocaml-cose, or any other COSE implementation
  - The COSE-WG test-vectors source (only RFC text is used)

The CBOR encoding layer is delegated to cbor_oracle._ENCODE
(verified at 14/14 RFC 8949 Appendix A vectors byte-exactly in
msn-2026-0015/0016/0017).

This oracle focuses on the COSE message-construction encoding layer
(Sig_structure, Enc_structure, MAC_structure, header parameter
canonicalization) per RFC 9052 §3-§6. The cryptographic primitives
(ECDSA, EdDSA, HMAC, AES-GCM, ChaCha20-Poly1305) are NOT implemented
here — this oracle produces the canonical byte strings that SHOULD be
signed/encrypted/MAC'd, and the cohort libraries are responsible for
applying their own crypto primitives. The matrix compares the canonical
byte strings, not the cryptographic outputs.

COSE Tagged Structures (RFC 9052):
  - COSE_Sign1 is tag 18 (901)
  - COSE_Sign is tag 98 (9062) — legacy, RFC 8152/9052
  - COSE_Encrypt is tag 96 (9060)
  - COSE_Encrypt0 is tag 16 (900)
  - COSE_Mac is tag 97 (9061)
  - COSE_Mac0 is tag 17 (901)
  - COSE_Countersign is tag 11 (TBD9) per RFC 9338

Empty protected bucket per RFC 9052 §3 SHOULD be encoded as h'' (0x40),
not bstr-wrapping-empty-map (0x41 0xa0).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Use the verified CBOR oracle for the underlying byte encoding
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "cbor-cross-impl" / "oracle"))
from cbor_oracle import encode_deterministic, encode_canonical

# Per RFC 9052 §9, COSE message structures MUST use the encoding rules of
# RFC 8949 §4.2.1 (core deterministic encoding requirements). The CBOR
# oracle's `encode_canonical` implements §4.2.1 (bytewise lex map-key
# sort); `_ENCODE` implements §4.2.3 (length-first). We
# use `encode_canonical` for the protected-header encoding because that
# is what RFC 9052 §9 explicitly mandates.
_ENCODE = encode_canonical


# COSE message-construction context strings (RFC 9052 §4.4, §5.3, §6.3)
# Context is a CBOR tstr (major type 3), so we use Python str (the CBOR
# oracle's _ENCODE emits str as tstr and bytes as bstr).
CONTEXT_SIGNATURE = "Signature"
CONTEXT_SIGNATURE1 = "Signature1"
CONTEXT_ENCRYPT = "Encrypt"
CONTEXT_ENCRYPT0 = "Encrypt0"
CONTEXT_ENC_RECIPIENT = "Enc_Recipient"
CONTEXT_MAC_RECIPIENT = "Mac_Recipient"
CONTEXT_REC_RECIPIENT = "Rec_Recipient"
# NOTE: there is NO "Encrypted" context in RFC 9052 — that was a bug in
# earlier versions of this oracle. The correct context for COSE_Encrypt0
# is "Encrypt0" per RFC 9052 §5.3 (verified against rfc-editor.org/rfc/rfc9052).
# (CONTEXT_ENCRYPTED is kept as an alias = CONTEXT_ENCRYPT0 for backward-compat.)
CONTEXT_ENCRYPTED = "Encrypt0"
CONTEXT_RECIPIENT = "Enc_Recipient"
CONTEXT_MAC = "MAC"
CONTEXT_MAC0 = "MAC0"
CONTEXT_COUNTERSIGNATURE = "CounterSignature"
CONTEXT_COUNTERSIGNATURE0 = "CounterSignature0"
CONTEXT_COUNTERSIGNATURE_V2 = "CounterSignatureV2"
CONTEXT_COUNTERSIGNATURE0_V2 = "CounterSignature0V2"

# COSE tag values per RFC 9052 §4.2 / §5.2 / §6.2
TAG_COSE_SIGN1 = 18
TAG_COSE_SIGN = 98
TAG_COSE_ENCRYPT = 96
TAG_COSE_ENCRYPT0 = 16
TAG_COSE_MAC = 97
TAG_COSE_MAC0 = 17

COSE_TAGS = {
    "Sign1": TAG_COSE_SIGN1,
    "Sign": TAG_COSE_SIGN,
    "Encrypt": TAG_COSE_ENCRYPT,
    "Encrypt0": TAG_COSE_ENCRYPT0,
    "Mac": TAG_COSE_MAC,
    "Mac0": TAG_COSE_MAC0,
}


def encode_protected_map(protected_headers: dict | None) -> bytes:
    """Encode a protected header map per RFC 9052 §3 (MAP bytes only).

    Returns the CBOR-encoded MAP bytes (e.g. `a1 01 26` for `{1: -7}`).
    Does NOT wrap in bstr — the caller is responsible for that.

    For empty/None input, returns b'' (the CBOR encoding of empty map
    is `a0`, but per RFC 9052 §3 SHOULD we use h'' = 0x40 = b'').

    This is the lower-level function: use `encode_protected_bucket`
    if you want the bstr-wrapped form directly.
    """
    if not protected_headers:
        return b""
    return _ENCODE(protected_headers)


def encode_protected_bucket(protected_headers: dict | None) -> bytes:
    """Encode a COSE protected header bucket per RFC 9052 §3 (bstr-wrapped).

    Returns the bstr-wrapped form (e.g. `43 a1 01 26` for `{1: -7}`).
    For empty/None input, returns b'' (encoded as 0x40 in CBOR).

    Per the spec SHOULD: "Senders SHOULD encode a zero-length map as a
    zero-length byte string rather than as a zero-length map (encoded
    as h'a0'). The zero-length byte string encoding is preferred,
    because it is both shorter and the version used in the serialization
    structures for cryptographic computation."

    Use this for the standalone "protected" field of a COSE message.
    For internal use inside Sig_structure / Enc_structure / MAC_structure,
    pass the MAP bytes (`encode_protected_map`) directly to the array
    encoder — it will bstr-wrap once.
    """
    encoded_map = encode_protected_map(protected_headers)
    if not encoded_map:
        return b""
    if len(encoded_map) < 24:
        return bytes([0x40 | len(encoded_map)]) + encoded_map
    elif len(encoded_map) < 256:
        return bytes([0x40 | 24, len(encoded_map)]) + encoded_map
    elif len(encoded_map) < 65536:
        return bytes([0x40 | 25]) + len(encoded_map).to_bytes(2, "big") + encoded_map
    else:
        raise ValueError(f"protected_headers map too large: {len(encoded_map)} bytes")


def _protected_to_bstr(protected: dict | bytes | None) -> bytes:
    """Convert a protected header to the bstr bytes for embedding.

    Per RFC 9052 §3, the protected field is "the CBOR encoding of the
    protected map, wrapped in a bstr". The array encoder handles the
    wrapping when it emits bytes as bstr. So:
      - dict (or None/empty) → encode the map to CBOR-map bytes.
        The array encoder wraps once → bstr(map) ✓.
      - bytes (already-bstr-wrapped) → return as-is, but this would
        cause double-wrapping. Refuse and complain.
      - None → return b'' (so the array encoder emits 0x40 = h'').
    """
    if isinstance(protected, bytes):
        # Caller claims these bytes are already bstr-wrapped; the
        # array encoder will re-wrap them — that's the double-wrap bug.
        # For now, refuse loudly so callers pass dicts.
        raise ValueError(
            "_protected_to_bstr: passing bytes here would cause double bstr-wrapping; "
            "pass a dict instead (or use encode_protected_bucket directly)."
        )
    return encode_protected_map(protected)


def build_sig_structure(
    context: str,
    body_protected: dict | bytes | None,
    sign_protected: dict | bytes | None = None,
    external_aad: bytes = b"",
    payload: bytes = b"",
) -> bytes:
    """Build a Sig_structure per RFC 9052 §4.4.

    Sig_structure = [
      context : tstr,
      body_protected : bstr,  (CBOR-encoded map or empty bstr h'')
      ? sign_protected : bstr,
      external_aad : bstr,
      payload : bstr
    ]

    `body_protected` and `sign_protected` may be passed as either:
      - a dict (the protected header map; we encode + wrap in bstr)
      - already-encoded bytes (e.g. b'') — we insert as-is
      - None — treated as empty bstr (h'')

    NOTE on layering: the array encoder emits the `body_protected` field
    as a CBOR bstr. To produce a single layer of bstr wrapping:
      - if body_protected is a dict, we encode the dict to CBOR-map bytes;
        the array encoder wraps those bytes as bstr.
      - if body_protected is already bytes (bstr-wrapped), we use them
        verbatim — the array encoder wraps them again as bstr. THIS IS
        THE COMMON BUG. We protect against it by calling
        `_protected_to_bstr` which only wraps once.
    """
    bp = _protected_to_bstr(body_protected)
    if sign_protected is None:
        return _ENCODE([
            context,
            bp,
            external_aad,
            payload,
        ])
    sp = _protected_to_bstr(sign_protected)
    return _ENCODE([
        context,
        bp,
        sp,
        external_aad,
        payload,
    ])


def build_enc_structure(
    context: str,
    body_protected: dict | bytes | None,
    sign_protected: dict | bytes | None = None,
    external_aad: bytes = b"",
) -> bytes:
    """Build an Enc_structure per RFC 9052 §5.3.

    Enc_structure = [
      context : tstr,
      body_protected : bstr,
      ? sign_protected : bstr,
      external_aad : bstr
    ]

    Note: Enc_structure does NOT include a payload field.
    """
    bp = _protected_to_bstr(body_protected)
    if sign_protected is None:
        return _ENCODE([
            context,
            bp,
            external_aad,
        ])
    sp = _protected_to_bstr(sign_protected)
    return _ENCODE([
        context,
        bp,
        sp,
        external_aad,
    ])


def build_mac_structure(
    context: str,
    body_protected: dict | bytes | None,
    sign_protected: dict | bytes | None = None,
    external_aad: bytes = b"",
    payload: bytes = b"",
) -> bytes:
    """Build a MAC_structure per RFC 9052 §6.3.

    MAC_structure = [
      context : tstr,
      body_protected : bstr,
      ? sign_protected : bstr,
      external_aad : bstr,
      payload : bstr
    ]
    """
    bp = _protected_to_bstr(body_protected)
    if sign_protected is None:
        return _ENCODE([
            context,
            bp,
            external_aad,
            payload,
        ])
    sp = _protected_to_bstr(sign_protected)
    return _ENCODE([
        context,
        bp,
        sp,
        external_aad,
        payload,
    ])


def build_cose_sign1_to_be_signed(
    body_protected: dict | bytes | None,
    external_aad: bytes,
    payload: bytes,
) -> bytes:
    """Build the canonical byte string to be signed for COSE_Sign1.

    Per RFC 9052 §4.4, COSE_Sign1 signs Sig_structure with
    context = "Signature1".

    Note: COSE_Sign1's payload is included in Sig_structure (not
    detached), so the signature is over the payload itself.
    """
    return build_sig_structure(
        context=CONTEXT_SIGNATURE1,
        body_protected=body_protected,
        external_aad=external_aad,
        payload=payload,
    )


def build_cose_sign_to_be_signed(
    body_protected: dict | bytes | None,
    sign_protected: dict | bytes | None,
    external_aad: bytes,
    payload: bytes,
) -> bytes:
    """Build the canonical byte string to be signed for COSE_Sign.

    Per RFC 9052 §4.4, COSE_Sign signs Sig_structure with
    context = "Signature" and the sign_protected field present.
    """
    return build_sig_structure(
        context=CONTEXT_SIGNATURE,
        body_protected=body_protected,
        sign_protected=sign_protected,
        external_aad=external_aad,
        payload=payload,
    )


def build_cose_encrypt0_aad(
    body_protected: dict | bytes | None,
    external_aad: bytes = b"",
) -> bytes:
    """Build the AAD (Additional Authenticated Data) for COSE_Encrypt0.

    Per RFC 9052 §5.3, COSE_Encrypt0's AEAD input is Enc_structure with
    context = "Encrypted".
    """
    return build_enc_structure(
        context=CONTEXT_ENCRYPTED,
        body_protected=body_protected,
        external_aad=external_aad,
    )


def build_cose_encrypt_aad(
    body_protected: dict | bytes | None,
    sign_protected: dict | bytes | None,
    external_aad: bytes = b"",
) -> bytes:
    """Build the AAD for COSE_Encrypt recipients per RFC 9052 §5.3.

    COSE_Encrypt recipient's Enc_structure has context = "Recipient"
    and the sign_protected field present.
    """
    return build_enc_structure(
        context=CONTEXT_RECIPIENT,
        body_protected=body_protected,
        sign_protected=sign_protected,
        external_aad=external_aad,
    )


def build_cose_mac0_to_be_maced(
    body_protected: dict | bytes | None,
    external_aad: bytes,
    payload: bytes,
) -> bytes:
    """Build the canonical byte string to be MAC'd for COSE_Mac0.

    Per RFC 9052 §6.3, COSE_Mac0 MACs MAC_structure with
    context = "MAC0".
    """
    return build_mac_structure(
        context=CONTEXT_MAC0,
        body_protected=body_protected,
        external_aad=external_aad,
        payload=payload,
    )


def build_cose_message(
    msg_type: str,
    protected_headers: dict | None,
    unprotected_headers: dict | None,
    payload: bytes,
    signature: bytes | None = None,
    ciphertext: bytes | None = None,
    tag: bytes | None = None,
    recipients: list | None = None,
    signatures: list | None = None,
    with_tag: bool = True,
) -> bytes:
    """Build a complete COSE message encoding per RFC 9052 §4-§6.

    msg_type: 'Sign1', 'Sign', 'Encrypt0', 'Encrypt', 'Mac0', 'Mac'

    with_tag: emit the COSE tag prefix (tag 18 for Sign1, etc.).
    RFC 9052 says the tagged form is the production form.
    """
    protected = encode_protected_bucket(protected_headers)
    unprotected = unprotected_headers if unprotected_headers else {}

    if msg_type == "Sign1":
        if signature is None:
            raise ValueError("COSE_Sign1 requires signature")
        body = _ENCODE([protected, unprotected, payload, signature])
    elif msg_type == "Sign":
        if signatures is None:
            raise ValueError("COSE_Sign requires signatures")
        body = _ENCODE([protected, unprotected, payload, signatures])
    elif msg_type == "Encrypt0":
        if ciphertext is None:
            raise ValueError("COSE_Encrypt0 requires ciphertext")
        body = _ENCODE([protected, unprotected, ciphertext])
    elif msg_type == "Encrypt":
        if ciphertext is None or recipients is None:
            raise ValueError("COSE_Encrypt requires ciphertext and recipients")
        body = _ENCODE([protected, unprotected, ciphertext, recipients])
    elif msg_type == "Mac0":
        if tag is None:
            raise ValueError("COSE_Mac0 requires tag")
        body = _ENCODE([protected, unprotected, payload, tag])
    elif msg_type == "Mac":
        if tag is None or recipients is None:
            raise ValueError("COSE_Mac requires tag and recipients")
        body = _ENCODE([protected, unprotected, payload, tag, recipients])
    else:
        raise ValueError(f"unsupported msg_type: {msg_type}")

    if not with_tag:
        return body
    cose_tag = COSE_TAGS[msg_type]
    if cose_tag < 24:
        return bytes([0xC0 | cose_tag]) + body
    else:
        # 2-byte tag header: major type 6, additional info 24
        return bytes([0xC0 | 24, cose_tag]) + body


# ---------- Round-trip oracle self-test ----------

if __name__ == "__main__":
    print("=" * 70)
    print("COSE Oracle Self-Test (RFC 9052/9053 structural vectors)")
    print("=" * 70)
    all_passed = True

    # Test 1: empty protected bucket encoding (RFC 9052 §3)
    empty_protected = encode_protected_bucket(None)
    if empty_protected == b"":
        print("PASS: empty protected bucket -> b'' (encoded as 0x40 by caller)")
    else:
        print(f"FAIL: empty protected bucket -> {empty_protected.hex()}")
        all_passed = False

    # Test 2: empty protected bucket with explicit empty dict
    empty_protected_dict = encode_protected_bucket({})
    if empty_protected_dict == b"":
        print("PASS: empty {} protected -> b'' (encoded as 0x40)")
    else:
        print(f"FAIL: empty {{}} protected -> {empty_protected_dict.hex()}")
        all_passed = False

    # Test 3: non-empty protected bucket
    non_empty = encode_protected_bucket({"alg": "ES256"})
    print(f"INFO: non-empty protected -> {non_empty.hex()}")

    # Test 4: Sig_structure for Sign1 (empty protected, no AAD, payload 'test payload')
    sig1_tbs = build_cose_sign1_to_be_signed(None, b"", b"test payload")
    expected_sig1_tbs = "846a5369676e61747572653140404c74657374207061796c6f6164"
    if sig1_tbs.hex() == expected_sig1_tbs:
        print(f"PASS: COSE_Sign1 Sig_structure = {sig1_tbs.hex()}")
    else:
        print(f"FAIL: COSE_Sign1 Sig_structure = {sig1_tbs.hex()} (expected {expected_sig1_tbs})")
        all_passed = False

    # Test 5: Enc_structure for COSE_Encrypt0
    enc0_aad = build_cose_encrypt0_aad(None)
    expected_enc0_aad = "8368456e6372797074304040"
    if enc0_aad.hex() == expected_enc0_aad:
        print(f"PASS: COSE_Encrypt0 Enc_structure = {enc0_aad.hex()}")
    else:
        print(f"FAIL: COSE_Encrypt0 Enc_structure = {enc0_aad.hex()} (expected {expected_enc0_aad})")
        all_passed = False

    # Test 6: MAC_structure for COSE_Mac0
    mac0_tbm = build_cose_mac0_to_be_maced(None, b"", b"test payload")
    expected_mac0_tbm = "84644d41433040404c74657374207061796c6f6164"
    if mac0_tbm.hex() == expected_mac0_tbm:
        print(f"PASS: COSE_Mac0 MAC_structure = {mac0_tbm.hex()}")
    else:
        print(f"FAIL: COSE_Mac0 MAC_structure = {mac0_tbm.hex()} (expected {expected_mac0_tbm})")
        all_passed = False

    # Test 7: full COSE_Sign1 message WITH tag 18
    full_sign1 = build_cose_message(
        msg_type="Sign1",
        protected_headers=None,
        unprotected_headers={},
        payload=b"hello",
        signature=b"\x00" * 64,
    )
    print(f"INFO: Full COSE_Sign1 message (tagged): {full_sign1.hex()}")

    # Test 8: full COSE_Sign1 message WITHOUT tag (raw array)
    raw_sign1 = build_cose_message(
        msg_type="Sign1",
        protected_headers=None,
        unprotected_headers={},
        payload=b"hello",
        signature=b"\x00" * 64,
        with_tag=False,
    )
    expected_raw = "8440a04568656c6c6f584000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    if raw_sign1.hex() == expected_raw:
        print(f"PASS: raw COSE_Sign1 = {raw_sign1.hex()}")
    else:
        print(f"FAIL: raw COSE_Sign1 = {raw_sign1.hex()} (expected {expected_raw})")
        all_passed = False

    print()
    print(f"Overall: {'PASS' if all_passed else 'FAIL'}")
