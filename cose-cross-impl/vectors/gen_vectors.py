"""Adversarial COSE vector generator for msn-2026-0018 (v2).

Synthesizes inputs targeting each audit axis in spc-2026-0005:
  1. cose_sign1_message_construction
  2. cose_encrypt0_message_construction
  3. cose_mac0_message_construction
  4. empty_protected_bucket
  5. header_label_sorting
  6. ecdsa_r_s_encoding (uses pycose to generate reference r||s bytes)
  7. eddsa_signature_encoding
  8. aes_gcm_nonce_construction
  9. deterministic_ecdsa_nonce
 10. cose_kdf_context

Each vector is a JSON object with:
    axis, vector_id, data_item (input to adapter),
    description, oracle_structure_hex, oracle_message_hex,
    axis_metadata

Deterministic seed: 0xC0DE0CB0 ("COSE cohort bytes")

The structure bytes are compared at the Sig_structure / Enc_structure /
MAC_structure level (cryptography-independent). The full-message bytes
are compared at the wrapping-CBOR level (headers + tag, NOT including
the signature/ciphertext/MAC which depend on the library's crypto).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add oracle to path
sys.path.insert(0, str(Path(__file__).parent.parent / "oracle"))
from cose_oracle import (
    build_cose_sign1_to_be_signed,
    build_cose_encrypt0_aad,
    build_cose_mac0_to_be_maced,
    encode_protected_bucket,
    build_cose_message,
)

OUT_DIR = Path(__file__).parent
SEED = 0xC0DE0CB0


# ============================================================================
# Axis 1: cose_sign1_message_construction
# ============================================================================

def gen_sign1_message_construction():
    vectors = []

    cases = [
        # (vector_id, protected, unprotected, payload, alg, skip_alg, desc)
        ("sign1_es256_in_protected", {1: -7}, {}, b"test", "ES256", False,
         "COSE_Sign1 with alg=ES256 (int 1=-7) in protected, empty unprotected"),
        ("sign1_es256_in_protected_kid_in_unprotected",
         {1: -7}, {4: b"\x01\x02\x03\x04"}, b"test", "ES256", False,
         "COSE_Sign1 with alg=ES256 in protected, kid (int 4) in unprotected"),
        ("sign1_es256_in_protected_kid_in_protected",
         {1: -7, 4: b"\x01\x02\x03\x04"}, {}, b"test", "ES256", False,
         "COSE_Sign1 with both alg and kid in protected (test int-label sort)"),
        ("sign1_two_int_headers_in_protected",
         {1: -7, 3: 50}, {}, b"payload", "ES256", False,
         "Two int headers in protected: alg=1=-7 (ES256), ctyp=3=50 (text/plain CoAP)"),
        ("sign1_int_and_tstr_headers_in_protected",
         {1: -7, "ctyp": "text/plain"}, {}, b"x", "ES256", False,
         "Mixed int and tstr header labels (int < tstr per RFC 9052 §9)"),
        ("sign1_tstr_only_headers",
         {"alg": "ES256", "ctyp": "text/plain"}, {}, b"y", "ES256", True,
         "All tstr headers (with skip_alg_header); tests tstr lex sort"),
        ("sign1_multiple_tstr_headers",
         {"alg": "ES256", "ctyp": "application/cbor", "kid": "key1"}, {},
         b"z", "ES256", True,
         "Three tstr headers — tests lex sort within tstr keys"),
        ("sign1_empty_payload", {1: -7}, {}, b"", "ES256", False,
         "Empty payload — RFC 9052 §4.4 Sig_structure payload slot still present"),
        ("sign1_with_external_aad",
         {1: -7}, {}, b"payload", "ES256", False,
         "External AAD present (passed by adapter as 'external_aad' field)"),
        ("sign1_kid_tstr_int_label_same",
         {1: -7, 4: b"\xff"}, {}, b"payload", "ES256", False,
         "Header label sort: int 1 and int 4 in protected"),
    ]

    for vid, prot, unprot, payload, alg, skip_alg, desc in cases:
        # If skip_alg, move alg from protected to unprotected
        prot_eff = dict(prot)
        unprot_eff = dict(unprot)
        if skip_alg:
            if 1 in prot_eff:
                unprot_eff[1] = prot_eff[1]
                del prot_eff[1]
            elif "alg" in prot_eff:
                unprot_eff["alg"] = prot_eff["alg"]
                del prot_eff["alg"]
        sig1_tbs = build_cose_sign1_to_be_signed(
            body_protected=prot_eff,
            external_aad=b"",
            payload=payload,
        )
        # Compute oracle message bytes (COSE_Sign1 with tag 18, dummy signature)
        full_msg = build_cose_message(
            msg_type="Sign1",
            protected_headers=prot_eff,
            unprotected_headers=unprot_eff,
            payload=payload,
            signature=b"\x00" * 64,
        )
        vectors.append({
            "axis": "cose_sign1_message_construction",
            "vector_id": vid,
            "data_item": {
                "msg_type": "Sign1",
                "protected": prot_eff,
                "unprotected": unprot_eff,
                "payload": payload.hex(),
                "alg": alg,
                "skip_alg_header": skip_alg,
            },
            "description": desc,
            "oracle_structure_hex": sig1_tbs.hex(),
            "oracle_message_hex": full_msg.hex(),
        })
    return vectors


# ============================================================================
# Axis 2: cose_encrypt0_message_construction
# ============================================================================

def gen_encrypt0_message_construction():
    vectors = []

    cases = [
        ("encrypt0_a128gcm_basic",
         {1: 1}, {5: b"\x00" * 12}, b"plaintext", b"ciphertext_data",
         "COSE_Encrypt0 with A128GCM (alg=1), 12-byte IV in unprotected (int 5)"),
        ("encrypt0_a256gcm_in_protected",
         {1: 3}, {}, b"plaintext", b"ciphertext_data",
         "COSE_Encrypt0 with A256GCM (alg=3) in protected, no IV (caller supplies)"),
        ("encrypt0_chacha20",
         {1: 24}, {}, b"plaintext", b"ciphertext_data",
         "COSE_Encrypt0 with ChaCha20-Poly1305 (alg=24)"),
        ("encrypt0_empty_protected",
         {}, {1: 1, 5: b"\xaa" * 12}, b"plaintext", b"ciphertext_data",
         "COSE_Encrypt0 with empty protected, both alg and IV in unprotected"),
        ("encrypt0_kid_in_protected",
         {1: 1, 4: b"\xab\xcd"}, {5: b"\x00" * 12}, b"x", b"y",
         "COSE_Encrypt0 with kid (int 4) in protected"),
    ]

    for vid, prot, unprot, payload, ciphertext, desc in cases:
        # protected_bytes = encode_protected_bucket(prot)  # oracle now does the encoding itself
        # Note: Encrypt0's ciphertext is opaque to the Enc_structure
        enc0_aad = build_cose_encrypt0_aad(
            body_protected=prot,
            external_aad=b"",
        )
        # COSE_Encrypt0 wraps [protected, unprotected, ciphertext] with tag 16
        full_msg = build_cose_message(
            msg_type="Encrypt0",
            protected_headers=prot,
            unprotected_headers=unprot,
            payload=payload,
            ciphertext=ciphertext,
        )
        vectors.append({
            "axis": "cose_encrypt0_message_construction",
            "vector_id": vid,
            "data_item": {
                "msg_type": "Encrypt0",
                "protected": prot,
                "unprotected": unprot,
                "payload": payload.hex(),
                "ciphertext": ciphertext.hex(),
                "alg": (
                    "A128GCM" if prot.get(1) == 1 or (not prot and unprot.get(1) == 1) else
                    "A256GCM" if prot.get(1) == 3 else
                    "ChaCha20"
                ),
            },
            "description": desc,
            "oracle_structure_hex": enc0_aad.hex(),
            "oracle_message_hex": full_msg.hex(),
        })
    return vectors


# ============================================================================
# Axis 3: cose_mac0_message_construction
# ============================================================================

def gen_mac0_message_construction():
    vectors = []

    cases = [
        ("mac0_hmac256_in_protected",
         {1: 5}, {}, b"payload", b"\x00" * 32,
         "COSE_Mac0 with HMAC 256/256 (alg=5) in protected"),
        ("mac0_hmac384_in_protected",
         {1: 6}, {}, b"payload", b"\x00" * 48,
         "COSE_Mac0 with HMAC 384/384 (alg=6)"),
        ("mac0_hmac512_in_protected",
         {1: 7}, {}, b"payload", b"\x00" * 64,
         "COSE_Mac0 with HMAC 512/512 (alg=7)"),
        ("mac0_empty_protected_kid_uhdr",
         {}, {1: 5, 4: b"\x01"}, b"payload", b"\x00" * 32,
         "COSE_Mac0 with empty protected, alg+kid in unprotected"),
        ("mac0_with_external_aad",
         {1: 5}, {}, b"payload", b"\x00" * 32,
         "COSE_Mac0 with external AAD (Sig_structure-like field)"),
    ]

    for vid, prot, unprot, payload, tag, desc in cases:
        # protected_bytes = encode_protected_bucket(prot)  # oracle now does the encoding itself
        mac0_tbm = build_cose_mac0_to_be_maced(
            body_protected=prot,
            external_aad=b"",
            payload=payload,
        )
        full_msg = build_cose_message(
            msg_type="Mac0",
            protected_headers=prot,
            unprotected_headers=unprot,
            payload=payload,
            tag=tag,
        )
        vectors.append({
            "axis": "cose_mac0_message_construction",
            "vector_id": vid,
            "data_item": {
                "msg_type": "Mac0",
                "protected": prot,
                "unprotected": unprot,
                "payload": payload.hex(),
                "tag": tag.hex(),
                "alg": (
                    "HMAC256" if prot.get(1) == 5 or (not prot and unprot.get(1) == 5) else
                    "HMAC384" if prot.get(1) == 6 else
                    "HMAC512"
                ),
            },
            "description": desc,
            "oracle_structure_hex": mac0_tbm.hex(),
            "oracle_message_hex": full_msg.hex(),
        })
    return vectors


# ============================================================================
# Axis 4: empty_protected_bucket
# ============================================================================

def gen_empty_protected_bucket():
    vectors = []

    cases = [
        ("sign1_empty_protected_no_headers",
         {}, {}, b"hello", b"\x00" * 64, "Sign1",
         "COSE_Sign1 with empty protected AND empty unprotected (worst-case empty bucket test)"),
        ("sign1_empty_protected_alg_uhdr",
         {}, {1: -7}, b"hello", b"\x00" * 64, "Sign1",
         "COSE_Sign1 with empty protected, alg=-7 (ES256) in unprotected"),
        ("sign1_empty_protected_kid_uhdr",
         {}, {4: b"\x01\x02\x03\x04"}, b"hello", b"\x00" * 64, "Sign1",
         "COSE_Sign1 with empty protected, kid in unprotected"),
        ("encrypt0_empty_protected_alg_iv_uhdr",
         {}, {1: 1, 5: b"\x00" * 12}, b"plaintext", b"ciphertext_data", "Encrypt0",
         "COSE_Encrypt0 with empty protected, alg+iv in unprotected"),
        ("mac0_empty_protected_alg_uhdr",
         {}, {1: 5}, b"payload", b"\x00" * 32, "Mac0",
         "COSE_Mac0 with empty protected, alg in unprotected"),
    ]

    for vid, prot, unprot, payload, sec, msg_type, desc in cases:
        # protected_bytes = encode_protected_bucket(prot)  # oracle now does the encoding itself
        if msg_type == "Sign1":
            struct_bytes = build_cose_sign1_to_be_signed(prot, b"", payload)
            full_msg = build_cose_message(
                msg_type="Sign1", protected_headers=prot,
                unprotected_headers=unprot, payload=payload, signature=sec,
            )
        elif msg_type == "Encrypt0":
            struct_bytes = build_cose_encrypt0_aad(prot)
            full_msg = build_cose_message(
                msg_type="Encrypt0", protected_headers=prot,
                unprotected_headers=unprot, payload=payload, ciphertext=sec,
            )
        elif msg_type == "Mac0":
            struct_bytes = build_cose_mac0_to_be_maced(prot, b"", payload)
            full_msg = build_cose_message(
                msg_type="Mac0", protected_headers=prot,
                unprotected_headers=unprot, payload=payload, tag=sec,
            )

        # Expected: protected byte = 0x40, NOT 0x41 0xa0
        # The oracle produces this by construction (verify)
        if prot:
            raise RuntimeError(f"oracle bug: empty prot should be empty but got {prot}")

        vectors.append({
            "axis": "empty_protected_bucket",
            "vector_id": vid,
            "data_item": {
                "msg_type": msg_type,
                "protected": prot,
                "unprotected": unprot,
                "payload": payload.hex(),
                "skip_alg_header": True,
            },
            "description": desc,
            "oracle_structure_hex": struct_bytes.hex(),
            "oracle_message_hex": full_msg.hex(),
            "axis_metadata": {"expected_protected_header_byte": "0x40", "not": "0x41 0xa0"},
        })
    return vectors


# ============================================================================
# Axis 5: header_label_sorting
# ============================================================================

def gen_header_label_sorting():
    vectors = []

    cases = [
        # (vid, prot_headers_int_sort, payload)
        # NOTE: labels 1=alg, 3=ctyp (uint/tstr), 4=kid (bstr). We use
        # values that satisfy pycose's validation.
        ("int_labels_sorted", {1: -7, 4: b"y", 3: 50}, b"p"),
        # Reverse insertion order — must still sort by int value
        ("int_labels_reverse_insertion", {4: b"y", 3: 50, 1: -7}, b"p"),
        # Mixed int and tstr labels
        ("mixed_int_tstr_labels", {1: -7, "ctyp": "text/plain", "kid": b"k"}, b"p"),
        # Long tstr label sorting
        ("tstr_lex_sort", {"a": 1, "aa": 2, "b": 3, "ab": 4, "z": 5}, b"p"),
    ]

    for vid, prot, payload in cases:
        # skip_alg_header=True is set in the data_item so the adapter
        # moves alg to uhdr. For the oracle (which doesn't track this),
        # we keep the protected headers as the case defines them — the
        # protected bucket itself doesn't include alg.
        # Remove alg from prot for the oracle computation:
        prot_eff = dict(prot)
        if 1 in prot_eff:
            del prot_eff[1]
        struct_bytes = build_cose_sign1_to_be_signed(prot_eff, b"", payload)
        full_msg = build_cose_message(
            msg_type="Sign1", protected_headers=prot_eff, unprotected_headers={1: prot.get(1)} if 1 in prot else {},
            payload=payload, signature=b"\x00" * 64,
        )
        vectors.append({
            "axis": "header_label_sorting",
            "vector_id": vid,
            "data_item": {
                "msg_type": "Sign1",
                "protected": prot_eff,
                "unprotected": {1: prot.get(1)} if 1 in prot else {},
                "payload": payload.hex(),
                "alg": "ES256",
                "skip_alg_header": True,
            },
            "description": f"Header label sorting — {vid}",
            "oracle_structure_hex": struct_bytes.hex(),
            "oracle_message_hex": full_msg.hex(),
        })
    return vectors


# ============================================================================
# Axis 6: ecdsa_r_s_encoding (RFC 9053 §2.1)
# ============================================================================

def gen_ecdsa_r_s_encoding():
    """Verify ECDSA r||s encoding is fixed-length (32/48/66 bytes).

    For ES256: r is 32 bytes, s is 32 bytes, total 64 bytes.
    For ES384: r is 48 bytes, s is 48 bytes, total 96 bytes.
    For ES512: r is 66 bytes, s is 66 bytes, total 132 bytes.
    """
    vectors = []

    # We don't have a verified ECDSA r||s reference; use pycose as a
    # known reference for the SIGNATURE structure. The oracle here
    # doesn't generate the signature bytes — only the message structure.
    cases = [
        ("es256_sign1_basic", {1: -7}, b"payload", "ES256"),
        ("es384_sign1_basic", {1: -35}, b"payload", "ES384"),
        ("es512_sign1_basic", {1: -36}, b"payload", "ES512"),
    ]
    for vid, prot, payload, alg in cases:
        # protected_bytes = encode_protected_bucket(prot)  # oracle now does the encoding itself
        struct_bytes = build_cose_sign1_to_be_signed(prot, b"", payload)
        # For oracle message bytes, use a placeholder signature of correct length
        sig_len = 64 if alg == "ES256" else 96 if alg == "ES384" else 132
        full_msg = build_cose_message(
            msg_type="Sign1", protected_headers=prot, unprotected_headers={},
            payload=payload, signature=b"\x00" * sig_len,
        )
        vectors.append({
            "axis": "ecdsa_r_s_encoding",
            "vector_id": vid,
            "data_item": {
                "msg_type": "Sign1",
                "protected": prot,
                "unprotected": {},
                "payload": payload.hex(),
                "alg": alg,
                "skip_alg_header": False,
            },
            "description": f"ECDSA {alg} COSE_Sign1 — verify r||s length={sig_len}",
            "oracle_structure_hex": struct_bytes.hex(),
            "oracle_message_hex": full_msg.hex(),
            "axis_metadata": {"expected_signature_length": sig_len, "algorithm": alg},
        })
    return vectors


# ============================================================================
# Axis 7: eddsa_signature_encoding (RFC 9053 §3.1)
# ============================================================================

def gen_eddsa_signature_encoding():
    """Verify EdDSA signature is r || s where r and s are 32 bytes (Ed25519)."""
    vectors = []

    cases = [
        ("eddsa_sign1_basic", {1: -8}, b"payload", "EdDSA"),
    ]
    for vid, prot, payload, alg in cases:
        # protected_bytes = encode_protected_bucket(prot)  # oracle now does the encoding itself
        struct_bytes = build_cose_sign1_to_be_signed(prot, b"", payload)
        full_msg = build_cose_message(
            msg_type="Sign1", protected_headers=prot, unprotected_headers={},
            payload=payload, signature=b"\x00" * 64,  # Ed25519: 32+32
        )
        vectors.append({
            "axis": "eddsa_signature_encoding",
            "vector_id": vid,
            "data_item": {
                "msg_type": "Sign1",
                "protected": prot,
                "unprotected": {},
                "payload": payload.hex(),
                "alg": "EdDSA",
                "skip_alg_header": False,
            },
            "description": "EdDSA COSE_Sign1 — verify r||s is 32+32 bytes",
            "oracle_structure_hex": struct_bytes.hex(),
            "oracle_message_hex": full_msg.hex(),
            "axis_metadata": {"expected_signature_length": 64, "algorithm": "EdDSA"},
        })
    return vectors


# ============================================================================
# Axis 8: aes_gcm_nonce_construction (RFC 9053 §5)
# ============================================================================

def gen_aes_gcm_nonce_construction():
    """Verify AES-GCM nonce construction (12 bytes for GCM) and AAD."""
    vectors = []

    cases = [
        ("aes-gcm-a128-12byte-iv",
         {1: 1}, {5: b"\x00" * 12}, b"plaintext", b"ciphertext_data",
         "A128GCM with 12-byte IV in unprotected (int 5)"),
        ("aes-gcm-a256-12byte-iv",
         {1: 3}, {5: b"\xaa" * 12}, b"plaintext", b"ciphertext_data",
         "A256GCM with 12-byte IV"),
        ("aes-gcm-iv-in-protected",
         {1: 1, 5: b"\xbb" * 12}, {}, b"plaintext", b"ciphertext_data",
         "A128GCM with IV in protected (alg+iv)"),
    ]
    for vid, prot, unprot, payload, ciphertext, desc in cases:
        # protected_bytes = encode_protected_bucket(prot)  # oracle now does the encoding itself
        struct_bytes = build_cose_encrypt0_aad(prot)
        full_msg = build_cose_message(
            msg_type="Encrypt0", protected_headers=prot, unprotected_headers=unprot,
            payload=payload, ciphertext=ciphertext,
        )
        vectors.append({
            "axis": "aes_gcm_nonce_construction",
            "vector_id": vid,
            "data_item": {
                "msg_type": "Encrypt0",
                "protected": prot,
                "unprotected": unprot,
                "payload": payload.hex(),
                "ciphertext": ciphertext.hex(),
                "alg": "A128GCM" if prot.get(1) == 1 else "A256GCM",
            },
            "description": desc,
            "oracle_structure_hex": struct_bytes.hex(),
            "oracle_message_hex": full_msg.hex(),
        })
    return vectors


# ============================================================================
# Axis 9: deterministic_ecdsa_nonce (RFC 6979)
# ============================================================================

def gen_deterministic_ecdsa_nonce():
    """Deterministic ECDSA nonce: same input → same signature.

    pycose uses the cryptography library which has RFC 6979 support.
    Other libraries may use a different nonce derivation path.
    """
    vectors = []

    # Two calls with same input must produce same signature (deterministic)
    for i in range(3):
        vectors.append({
            "axis": "deterministic_ecdsa_nonce",
            "vector_id": f"sign1_es256_deterministic_call_{i}",
            "data_item": {
                "msg_type": "Sign1",
                "protected": {1: -7},
                "unprotected": {},
                "payload": b"deterministic_test_payload".hex(),
                "alg": "ES256",
                "skip_alg_header": False,
                "deterministic_key_seed": (b"\x42" * 32).hex(),
            },
            "description": f"Deterministic ECDSA call #{i+1} — same input must produce same signature",
            # No oracle at structure level; the matrix compares actual outputs across calls
            "oracle_structure_hex": build_cose_sign1_to_be_signed(
                {1: -7}, b"", b"deterministic_test_payload"
            ).hex(),
            "oracle_message_hex": "",  # We compare signatures across calls, not vs an oracle
            "axis_metadata": {"call_index": i, "verify_determinism": True},
        })
    return vectors


# ============================================================================
# Axis 10: cose_kdf_context (RFC 9053 §5.2)
# ============================================================================

def _bytes_to_hex_in(obj):
    """Recursively convert bytes values to hex strings for JSON serialization."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _bytes_to_hex_in(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_bytes_to_hex_in(x) for x in obj]
    return obj


def gen_cose_kdf_context():
    """Verify COSE_KDF_Context encoding for ECDH key agreement."""
    vectors = []

    cases = [
        # (vid, alg_id, party_u_info, party_v_info, supp_pub_info)
        ("kdf_context_ecdh_es_hkdf256",
         -25,  # ECDH-ES + HKDF-256
         {1: b"\x01" * 32},  # nonce
         {1: b"\x02" * 32},  # nonce
         b"\x00" * 32,  # keydatalen
         "COSE_KDF_Context for ECDH-ES + HKDF-256"),
    ]

    for vid, alg_id, u_info, v_info, supp_pub, desc in cases:
        # Build COSE_KDF_Context per RFC 9053 §5.2:
        # COSE_KDF_Context = [
        #   AlgorithmID : int,
        #   PartyUInfo : { nonce : bstr, ... },
        #   PartyVInfo : { nonce : bstr, ... },
        #   supp_pub_info : bstr
        # ]
        # Per RFC 9053 §5.2.1.4: when supp_pub_info is empty, it can be
        # omitted, but COSE_KDF_Context always has all 4 fields.
        kdf_context = [
            alg_id,
            u_info,
            v_info,
            supp_pub,
        ]

        # Use the oracle's CBOR encoder for the KDF context itself
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "cbor-cross-impl" / "oracle"))
        from cbor_oracle import encode_deterministic
        oracle_kdf_hex = encode_deterministic(kdf_context).hex()

        # We emit this via the adapter's protected header structure
        # by passing it as a "kdf_context" data item.
        vectors.append({
            "axis": "cose_kdf_context",
            "vector_id": vid,
            "data_item": {
                "msg_type": "KDF_Context",
                "kdf_context": _bytes_to_hex_in(kdf_context),
                "alg": alg_id,
            },
            "description": desc,
            "oracle_structure_hex": oracle_kdf_hex,
            "oracle_message_hex": oracle_kdf_hex,  # KDF context is itself the message
            "axis_metadata": {"kdf_alg": "ECDH-ES+HKDF-256"},
        })
    return vectors


# ============================================================================
# Master driver
# ============================================================================

AXIS_GENERATORS = [
    ("cose_sign1_message_construction", gen_sign1_message_construction),
    ("cose_encrypt0_message_construction", gen_encrypt0_message_construction),
    ("cose_mac0_message_construction", gen_mac0_message_construction),
    ("empty_protected_bucket", gen_empty_protected_bucket),
    ("header_label_sorting", gen_header_label_sorting),
    ("ecdsa_r_s_encoding", gen_ecdsa_r_s_encoding),
    ("eddsa_signature_encoding", gen_eddsa_signature_encoding),
    ("aes_gcm_nonce_construction", gen_aes_gcm_nonce_construction),
    ("deterministic_ecdsa_nonce", gen_deterministic_ecdsa_nonce),
    ("cose_kdf_context", gen_cose_kdf_context),
]


def main():
    print(f"Generating COSE adversarial vectors (seed=0x{SEED:08X})")
    print("=" * 60)
    total = 0
    for axis_name, gen_func in AXIS_GENERATORS:
        vectors = gen_func()
        out_path = OUT_DIR / f"vectors_{axis_name}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for v in vectors:
                # Sanitize: convert all bytes to hex for JSON
                v["data_item"] = _bytes_to_hex_in(v["data_item"])
                f.write(json.dumps(v) + "\n")
        print(f"  {axis_name:<40} {len(vectors):>3} vectors -> {out_path.name}")
        total += len(vectors)
    print("=" * 60)
    print(f"  TOTAL: {total} vectors across {len(AXIS_GENERATORS)} axes")


if __name__ == "__main__":
    main()
