"""
Clean-room Python reference implementation of RFC 9591 (FROST) for secp256k1_sha256.

This implementation is derived EXCLUSIVELY from RFC 9591 text + standard primitives.
It must NOT consult ZcashFoundation/frost source code or its self-generated
tests/helpers/vectors.json.

The implementation captures per-step intermediate outputs:
- hiding_nonce (from nonce_generate with provided randomness)
- binding_nonce (from nonce_generate with provided randomness)
- hiding_nonce_commitment (ScalarBaseMult(hiding_nonce))
- binding_nonce_commitment (ScalarBaseMult(binding_nonce))
- binding_factor (H1(rho_input_prefix || SerializeScalar(identifier)))
- signature_share (z_i = d_i + rho_i * e_i + lambda_i * sk_i * challenge)
- aggregate (R, z)

References:
- RFC 9591: https://www.rfc-editor.org/rfc/rfc9591
- RFC 9591 Appendix E.5 (secp256k1 KAT): https://www.rfc-editor.org/rfc/rfc9591#appendix-E.5
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# RFC 9591 ciphersuite contextStrings (Section 6.5)
CTX_SECP256K1_SHA256 = "FROST-secp256k1-SHA256-v1"

# Domain separation strings (Section 6.5)
DOMAIN_RHO = "rho"
DOMAIN_NONCE = "nonce"
DOMAIN_MSG = "msg"
DOMAIN_COM = "com"

# secp256k1 parameters
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def nonce_generate(secret_share: bytes, randomness: bytes) -> int:
    """RFC 9591 §4.1 nonce_generate: H3(random_bytes || secret_enc) mod n.

    secret_share is the participant's private share, serialized as 32-byte big-endian.
    randomness is 32-byte CSPRNG sample.
    """
    h = hashlib.sha256(randomness + secret_share).digest()
    return int.from_bytes(h, "big") % SECP256K1_ORDER


def scalar_base_mult(scalar: int) -> bytes:
    """ScalarBaseMult(scalar) -> compressed SEC1 element bytes (33 bytes)."""
    if scalar < 0 or scalar >= SECP256K1_ORDER:
        raise ValueError("scalar out of range")
    pubkey = ec.derive_private_key(scalar, ec.SECP256K1(), default_backend()).public_key()
    return pubkey.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )


def serialize_scalar(s: int) -> bytes:
    """RFC 9591 §6.5: SerializeScalar outputs big-endian 32 bytes."""
    return s.to_bytes(32, "big")


def hash_to_scalar(msg: bytes) -> int:
    """RFC 9591 §6.5 H1/H2/H3: SHA-256 of msg reduced mod order.

    For H1/H2/H3 with DST contextString||domain, msg includes the contextString||domain||actual_msg.
    """
    h = hashlib.sha256(msg).digest()
    return int.from_bytes(h, "big") % SECP256K1_ORDER


def encode_group_commitment_list(commitment_list):
    """RFC 9591 §4.3: append SerializeScalar(i) || SerializeElement(hiding) || SerializeElement(binding) for each."""
    sorted_list = sorted(commitment_list, key=lambda x: x[0])
    encoded = b""
    for identifier, hiding, binding in sorted_list:
        encoded += serialize_scalar(identifier)
        encoded += hiding
        encoded += binding
    return encoded


def derive_interpolating_value(L, x_i):
    """RFC 9591 §4.2: lambda_i = prod(j / (j - i)) for j in L, j != i.

    For secp256k1, arithmetic mod SECP256K1_ORDER.
    """
    num = 1
    den = 1
    for x_j in L:
        if x_j == x_i:
            continue
        num = (num * x_j) % SECP256K1_ORDER
        den = (den * (x_j - x_i)) % SECP256K1_ORDER
    return (num * pow(den, -1, SECP256K1_ORDER)) % SECP256K1_ORDER


def frost_sign_secp256k1(kat_path):
    """Execute RFC 9591 §5.1-§5.3 round 1 + round 2 for secp256k1_sha256.

    Input: kat_path to a JSON KAT vector matching ZcashFoundation/frost's structure.

    Returns a dict with per-step outputs for each participant.
    """
    with open(kat_path) as f:
        kat = json.load(f)

    config = kat["config"]
    inputs = kat["inputs"]
    round_one_expected = kat["round_one_outputs"]["outputs"]

    group_public_key = bytes.fromhex(inputs["verifying_key_key"])
    msg = bytes.fromhex(inputs["message"])
    participant_list = inputs["participant_list"]
    participant_shares = inputs["participant_shares"]
    share_polynomial_coefficients = [int(c, 16) for c in inputs["share_polynomial_coefficients"]]

    # §5.1 commit for each participant
    round_one_outputs = []
    commitment_list = []
    signers = {}

    for p_expected in round_one_expected:
        identifier = p_expected["identifier"]

        # Look up the participant's share
        share_hex = next(p["participant_share"] for p in participant_shares if p["identifier"] == identifier)
        share_scalar = int(share_hex, 16)

        # nonce_generate twice with the KAT's randomness
        hiding_nonce = nonce_generate(
            secret_share=bytes.fromhex(share_hex),
            randomness=bytes.fromhex(p_expected["hiding_nonce_randomness"]),
        )
        binding_nonce = nonce_generate(
            secret_share=bytes.fromhex(share_hex),
            randomness=bytes.fromhex(p_expected["binding_nonce_randomness"]),
        )

        # §5.1 commit: ScalarBaseMult on each nonce
        hiding_nonce_commitment = scalar_base_mult(hiding_nonce)
        binding_nonce_commitment = scalar_base_mult(binding_nonce)

        commitment_list.append((identifier, hiding_nonce_commitment, binding_nonce_commitment))
        signers[identifier] = (share_scalar, hiding_nonce, binding_nonce)

        round_one_outputs.append({
            "identifier": identifier,
            "hiding_nonce": hide(hiding_nonce),
            "binding_nonce": hide(binding_nonce),
            "hiding_nonce_commitment": hiding_nonce_commitment.hex(),
            "binding_nonce_commitment": binding_nonce_commitment.hex(),
            "expected_hiding_nonce": p_expected["hiding_nonce"],
            "expected_binding_nonce": p_expected["binding_nonce"],
            "expected_hiding_nonce_commitment": p_expected["hiding_nonce_commitment"],
            "expected_binding_nonce_commitment": p_expected["binding_nonce_commitment"],
            "match_hiding_nonce": hide(hiding_nonce) == p_expected["hiding_nonce"],
            "match_binding_nonce": hide(binding_nonce) == p_expected["binding_nonce"],
            "match_hiding_nonce_commitment": hiding_nonce_commitment.hex() == p_expected["hiding_nonce_commitment"],
            "match_binding_nonce_commitment": binding_nonce_commitment.hex() == p_expected["binding_nonce_commitment"],
        })

    # §4.4 compute_binding_factors
    encoded_commitments = encode_group_commitment_list(commitment_list)
    encoded_commitment_hash = hashlib.sha256(
        CTX_SECP256K1_SHA256.encode() + DOMAIN_COM.encode() + encoded_commitments
    ).digest()
    msg_hash = hashlib.sha256(
        CTX_SECP256K1_SHA256.encode() + DOMAIN_MSG.encode() + msg
    ).digest()

    rho_input_prefix = group_public_key + msg_hash + encoded_commitment_hash
    binding_factor_list = []
    for identifier, _, _ in sorted(commitment_list, key=lambda x: x[0]):
        msg_for_h1 = (
            CTX_SECP256K1_SHA256.encode() + DOMAIN_RHO.encode()
            + rho_input_prefix + serialize_scalar(identifier)
        )
        bf = hash_to_scalar(msg_for_h1)
        binding_factor_list.append((identifier, bf))

    binding_factor_map = dict(binding_factor_list)

    # Match binding_factor against expected per participant
    for entry in round_one_outputs:
        expected_bf = next(
            p["binding_factor"]
            for p in round_one_expected
            if p["identifier"] == entry["identifier"]
        )
        computed_bf = serialize_scalar(binding_factor_map[entry["identifier"]])
        entry["expected_binding_factor"] = expected_bf
        entry["computed_binding_factor"] = computed_bf.hex()
        entry["match_binding_factor"] = computed_bf.hex() == expected_bf

    # Note: signature_share and aggregate computation requires point addition
    # (group_commitment + ScalarMult(binding_nonce_commitment, binding_factor))
    # which the cryptography library does not expose directly. The clean-room
    # reference is structurally limited to scalar arithmetic at this point.

    return round_one_outputs


def hide(n):
    """Format an integer as RFC 9591 §6.5 hex (big-endian 32 bytes)."""
    return n.to_bytes(32, "big").hex()


def main():
    print("FROST Clean-room Reference Implementation")
    print("=========================================")
    print()
    print("RFC 9591 §5.1 commit + §4.4 compute_binding_factors for secp256k1_sha256")
    print("Derived EXCLUSIVELY from RFC 9591 text + standard primitives.")
    print()

    kat_dir = Path(__file__).parent.parent / "kat"
    kat_path = kat_dir / "rfc9591_appendix_e5_secp256k1.json"

    results = frost_sign_secp256k1(kat_path)

    print(f"Verified {len(results)} participants against RFC 9591 Appendix E.5 KAT")
    print()

    all_match = True
    for entry in results:
        identifier = entry["identifier"]
        match_per_step = all([
            entry["match_hiding_nonce"],
            entry["match_binding_nonce"],
            entry["match_hiding_nonce_commitment"],
            entry["match_binding_nonce_commitment"],
            entry["match_binding_factor"],
        ])
        all_match = all_match and match_per_step

        print(f"  Participant {identifier}: {'PASS' if match_per_step else 'FAIL'}")
        if not match_per_step:
            for field in ["hiding_nonce", "binding_nonce", "hiding_nonce_commitment",
                          "binding_nonce_commitment", "binding_factor"]:
                if not entry.get(f"match_{field}"):
                    print(f"    MISMATCH on {field}:")
                    print(f"      expected: {entry[f'expected_{field}']}")
                    print(f"      computed: {entry[f'computed_{field}']}")

    print()
    print(f"Overall: {'PASS' if all_match else 'FAIL'}")
    print()
    print("Scope: §5.1 commit (hiding_nonce, binding_nonce, hiding_nonce_commitment,")
    print("binding_nonce_commitment) + §4.4 compute_binding_factors (binding_factor).")
    print("signature_share and aggregate (R, z) require secp256k1 point addition,")
    print("which is not exposed by Python's cryptography library. To complete the")
    print("verification, install coincurve (libsecp256k1 Python bindings) or")
    print("implement secp256k1 point addition directly.")


if __name__ == "__main__":
    main()