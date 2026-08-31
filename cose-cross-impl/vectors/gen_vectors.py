"""Adversarial COSE vector generator for msn-2026-0018.

Synthesizes inputs targeting each audit axis in spc-2026-0005.
Deterministic given the seed. Each vector is a tuple:
    (axis_id, vector_id, data_item, description, oracle_expected_hex, axis_metadata)

Output: cose-cross-impl/vectors/vectors_<axis>.jsonl (one per axis)
"""

from __future__ import annotations

import json
import os
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
SEED = 0xC0DE0CB0  # "COSE cohort bytes"


def gen_empty_protected_bucket_vectors():
    """Test the empty protected bucket encoding (the known interop issue).

    Per RFC 9052 §3: empty protected bucket SHOULD be h'' (0x40),
    not bstr wrapping empty map (0x41 0xa0).
    """
    vectors = []
    # Vector 1: Sign1 with empty protected, alg in unprotected (key=1 int)
    # Expected: protected=0x40, unprotected={1: -7} (alg), payload, signature
    full = build_cose_message(
        msg_type="Sign1",
        protected_headers={},
        unprotected_headers={1: -7},  # alg = ES256
        payload=b"hello",
        signature=b"\x00" * 64,
    )
    vectors.append({
        "axis": "empty_protected_bucket",
        "vector_id": "sign1_empty_protected_with_alg_uhdr",
        "data_item": {
            "msg_type": "Sign1",
            "protected": {},
            "unprotected": {1: -7},  # int key
            "payload": "68656c6c6f",  # "hello"
            "alg": "ES256",
            "skip_alg_header": True
        },
        "description": "COSE_Sign1 with empty protected (0x40), alg in uhdr",
        "oracle_expected_hex": full.hex(),
    })

    return vectors


def gen_sign1_message_construction_vectors():
    """Test the basic COSE_Sign1 message-construction encoding."""
    vectors = []
    # Vector 1: Sign1 with non-empty protected (alg=ES256)
    full = build_cose_message(
        msg_type="Sign1",
        protected_headers={1: -7},  # alg = ES256
        unprotected_headers={},
        payload=b"test",
        signature=b"\x00" * 64,
    )
    vectors.append({
        "axis": "cose_sign1_message_construction",
        "vector_id": "sign1_es256_in_protected",
        "data_item": {
            "msg_type": "Sign1",
            "protected": {1: -7},
            "unprotected": {},
            "payload": "74657374",  # "test"
            "alg": "ES256",
            "skip_alg_header": False
        },
        "description": "COSE_Sign1 with alg=ES256 in protected",
        "oracle_expected_hex": full.hex(),
    })

    return vectors


# Master driver
AXIS_GENERATORS = [
    ("empty_protected_bucket", gen_empty_protected_bucket_vectors),
    ("cose_sign1_message_construction", gen_sign1_message_construction_vectors),
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
                f.write(json.dumps(v) + "\n")
        print(f"  {axis_name:<40} {len(vectors):>3} vectors -> {out_path.name}")
        total += len(vectors)
    print("=" * 60)
    print(f"  TOTAL: {total} vectors across {len(AXIS_GENERATORS)} axes")


if __name__ == "__main__":
    main()
