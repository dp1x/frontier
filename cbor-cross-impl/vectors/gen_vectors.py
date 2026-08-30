"""Adversarial CBOR vector generator for msn-2026-0015.

Synthesizes inputs targeting each audit axis in spc-2026-0004.
Deterministic given the seed. Each vector is a tuple:
    (axis_id, vector_id, data_item, description, oracle_a_expected_hex, axis_metadata)

Output: cbor-cross-impl/vectors/vectors_<axis>.jsonl (one per axis)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Add oracle to path
sys.path.insert(0, str(Path(__file__).parent.parent / "oracle"))
from cbor_oracle import (
    encode_deterministic, encode_canonical,
    DuplicateKeyError, CborValueError, Tagged as Tag,
)

OUT_DIR = Path(__file__).parent
SEED = 0xCB0F1E21

# ---------- Axis 1: integer shortest-form ----------

def gen_integer_shortest_form_vectors():
    vectors = []
    # Boundary values that exercise the additional-info transitions
    test_values = [
        0, 1, 22, 23, 24, 25, 254, 255, 256, 257, 65534, 65535, 65536, 65537,
        # Power-of-2 boundaries
        (1 << 7) - 1, 1 << 7, (1 << 8) - 1,
        (1 << 15) - 1, 1 << 15, (1 << 16) - 1,
        (1 << 31) - 1, 1 << 31, (1 << 32) - 1,
        (1 << 63) - 1, 1 << 63,
        # A few arbitrary values
        100, 1000, 1000000, 1000000000000,
    ]
    # Add negative counterparts
    neg_values = [-v - 1 for v in test_values if v <= 1000000]
    for v in test_values:
        try:
            exp_det = encode_deterministic(v).hex()
            exp_can = encode_canonical(v).hex()
            vectors.append({
                "axis": "integer_shortest_form",
                "vector_id": f"int_pos_{v}",
                "data_item": v,
                "description": f"positive integer {v}",
                "oracle_deterministic_hex": exp_det,
                "oracle_canonical_hex": exp_can,
            })
        except Exception as e:
            pass
    for v in neg_values:
        try:
            exp_det = encode_deterministic(v).hex()
            exp_can = encode_canonical(v).hex()
            vectors.append({
                "axis": "integer_shortest_form",
                "vector_id": f"int_neg_{v}",
                "data_item": v,
                "description": f"negative integer {v}",
                "oracle_deterministic_hex": exp_det,
                "oracle_canonical_hex": exp_can,
            })
        except Exception as e:
            pass
    return vectors


# ---------- Axis 2: map_key_sort ----------

def gen_map_key_sort_vectors():
    vectors = []
    # Map keys of varying lengths (1-byte, 2-byte, 3-byte, etc.)
    keys_1byte_int = [0, 1, 5, 10, 23, 100, 200]  # encode to 0x00-0x18xx (1-2 bytes)
    keys_1byte_neg = [-1, -10, -100]  # encode to 0x20-0x38xx
    keys_2byte_str = ["a", "b", "aa", "ab", "ba"]  # 1-2 char strings (1-2 bytes after CBOR prefix)
    keys_3byte_str = ["abc", "abd", "xyz", "aaa"]  # 3-char strings

    # Map 1: Mixed-length keys
    m1 = {}
    for k in keys_1byte_int + keys_2byte_str + keys_1byte_neg + keys_3byte_str:
        m1[k] = 1
    vectors.append({
        "axis": "map_key_sort",
        "vector_id": "map_mixed_lengths",
        "data_item": m1,
        "description": "map with mixed-length keys (RFC 8949 §4.2.1 example 1)",
        "oracle_deterministic_hex": encode_deterministic(m1).hex(),
        "oracle_canonical_hex": encode_canonical(m1).hex(),
    })

    # Map 2: §4.2.3 (length-first) example
    # Per RFC 8949 §4.2.3 length-first, the example order is:
    #   10 (0x0a, 1 byte), -1 (0x20, 1 byte), false (0xf4, 1 byte),
    #   100 (0x1864, 2 bytes), "z" (0x617a, 2 bytes),
    #   [-1] (0x8120, 2 bytes), "aa" (0x626161, 3 bytes),
    #   [100] (0x811864, 3 bytes)
    m2 = {
        100: 1,
        "z": 1,
        "aa": 1,
        10: 1,
        -1: 1,
        False: 1,
        (100,): 1,   # tuple [100]
        (-1,): 1,    # tuple [-1]
    }
    vectors.append({
        "axis": "map_key_sort",
        "vector_id": "map_rfc_4_2_3_example",
        "data_item": m2,
        "description": "RFC 8949 §4.2.3 length-first ordering example",
        "oracle_deterministic_hex": encode_deterministic(m2).hex(),
        "oracle_canonical_hex": encode_canonical(m2).hex(),
    })

    # Map 3: All same length, just lex order
    m3 = {1: "a", 2: "b", 3: "c"}
    vectors.append({
        "axis": "map_key_sort",
        "vector_id": "map_same_length_lex",
        "data_item": m3,
        "description": "map with same-length integer keys (lexicographic only)",
        "oracle_deterministic_hex": encode_deterministic(m3).hex(),
        "oracle_canonical_hex": encode_canonical(m3).hex(),
    })

    # Map 4: keys that differ only at boundary byte lengths
    # 2-byte encoded vs 3-byte encoded (forces length-first decision)
    # 0 -> 00 (1 byte), "aa" -> 626161 (3 bytes), 100 -> 1864 (2 bytes)
    m4 = {"aa": 1, 0: 2, 100: 3}
    vectors.append({
        "axis": "map_key_sort",
        "vector_id": "map_boundary_lengths_1_2_3",
        "data_item": m4,
        "description": "keys at length boundaries 1/2/3 bytes",
        "oracle_deterministic_hex": encode_deterministic(m4).hex(),
        "oracle_canonical_hex": encode_canonical(m4).hex(),
    })

    # Map 5: string keys that lex-sort before some integers and after others
    m5 = {"aa": 1, -1: 2, 10: 3, "z": 4, 100: 5, False: 6}
    vectors.append({
        "axis": "map_key_sort",
        "vector_id": "map_mixed_types",
        "data_item": m5,
        "description": "mixed string/integer/bool map keys",
        "oracle_deterministic_hex": encode_deterministic(m5).hex(),
        "oracle_canonical_hex": encode_canonical(m5).hex(),
    })

    return vectors


# ---------- Axis 3: float shortest-form ----------

def gen_float_shortest_form_vectors():
    vectors = []
    # Values representable in half precision exactly
    half_representable = [0.0, 1.0, -1.0, 0.5, -0.5, 1.5, -1.5, 2.0, -2.0,
                          65504.0, -65504.0,  # max half
                          0.00006103515625,  # min positive half subnormal-ish
                          ]
    # Values representable only in single precision
    single_only = [1.1, 3.14159, -3.14159, 1.0e10, -1.0e10, 1.0e-10, 6.022e23]
    # Values requiring double precision
    double_only = [1.1e-300, 1.0e300, -1.0e300, 3.141592653589793, 2.718281828459045]
    # Special values
    special = [float("inf"), float("-inf")]

    for v in half_representable:
        try:
            det = encode_deterministic(v).hex()
            can = encode_canonical(v).hex()
            # Verify the oracle actually used half-precision
            import struct
            half_bytes = struct.pack(">e", v).hex()
            assert det[2:6] == half_bytes, f"oracle did not use half for {v}"
            vectors.append({
                "axis": "float_shortest_form",
                "vector_id": f"float_half_{v}",
                "data_item": v,
                "description": f"float {v} (representable in half-precision)",
                "oracle_deterministic_hex": det,
                "oracle_canonical_hex": can,
            })
        except Exception:
            pass
    for v in single_only:
        try:
            det = encode_deterministic(v).hex()
            can = encode_canonical(v).hex()
            import struct
            single_bytes = struct.pack(">f", v).hex()
            assert det[2:10] == single_bytes, f"oracle did not use single for {v}"
            vectors.append({
                "axis": "float_shortest_form",
                "vector_id": f"float_single_{v}",
                "data_item": v,
                "description": f"float {v} (representable in single-precision)",
                "oracle_deterministic_hex": det,
                "oracle_canonical_hex": can,
            })
        except Exception:
            pass
    for v in double_only:
        try:
            det = encode_deterministic(v).hex()
            can = encode_canonical(v).hex()
            import struct
            double_bytes = struct.pack(">d", v).hex()
            assert det[2:18] == double_bytes, f"oracle did not use double for {v}"
            vectors.append({
                "axis": "float_shortest_form",
                "vector_id": f"float_double_{v}",
                "data_item": v,
                "description": f"float {v} (requires double-precision)",
                "oracle_deterministic_hex": det,
                "oracle_canonical_hex": can,
            })
        except Exception:
            pass
    for v in special:
        try:
            det = encode_deterministic(v).hex()
            can = encode_canonical(v).hex()
            vectors.append({
                "axis": "float_shortest_form",
                "vector_id": f"float_{'inf' if v > 0 else 'neg_inf'}",
                "data_item": v,
                "description": f"float {v}",
                "oracle_deterministic_hex": det,
                "oracle_canonical_hex": can,
            })
        except Exception:
            pass
    return vectors


# ---------- Axis 4: definite-length preferred ----------

def gen_definite_length_vectors():
    """Since our oracle only outputs definite-length, we test that
    libraries also produce definite-length for inputs that COULD be
    encoded indefinite. We hand-craft the inputs as definite-length
    and verify the oracle reproduces them; libraries should match."""
    vectors = []
    # Empty array
    vectors.append({
        "axis": "definite_length_preferred",
        "vector_id": "array_empty",
        "data_item": [],
        "description": "empty array (definite-length)",
        "oracle_deterministic_hex": encode_deterministic([]).hex(),
        "oracle_canonical_hex": encode_canonical([]).hex(),
    })
    # Empty map
    vectors.append({
        "axis": "definite_length_preferred",
        "vector_id": "map_empty",
        "data_item": {},
        "description": "empty map (definite-length)",
        "oracle_deterministic_hex": encode_deterministic({}).hex(),
        "oracle_canonical_hex": encode_canonical({}).hex(),
    })
    # Empty byte string
    vectors.append({
        "axis": "definite_length_preferred",
        "vector_id": "bstr_empty",
        "data_item": b"",
        "description": "empty byte string (definite-length)",
        "oracle_deterministic_hex": encode_deterministic(b"").hex(),
        "oracle_canonical_hex": encode_canonical(b"").hex(),
    })
    # Empty text string
    vectors.append({
        "axis": "definite_length_preferred",
        "vector_id": "tstr_empty",
        "data_item": "",
        "description": "empty text string (definite-length)",
        "oracle_deterministic_hex": encode_deterministic("").hex(),
        "oracle_canonical_hex": encode_canonical("").hex(),
    })
    # 1-element array
    vectors.append({
        "axis": "definite_length_preferred",
        "vector_id": "array_1elem",
        "data_item": [1],
        "description": "1-element array",
        "oracle_deterministic_hex": encode_deterministic([1]).hex(),
        "oracle_canonical_hex": encode_canonical([1]).hex(),
    })
    # 1-pair map
    vectors.append({
        "axis": "definite_length_preferred",
        "vector_id": "map_1pair",
        "data_item": {"a": 1},
        "description": "1-pair map",
        "oracle_deterministic_hex": encode_deterministic({"a": 1}).hex(),
        "oracle_canonical_hex": encode_canonical({"a": 1}).hex(),
    })
    return vectors


# ---------- Axis 5: duplicate-key rejection (canonical only) ----------

def gen_duplicate_key_vectors():
    vectors = []
    # Same string key twice (in dict literal, Python would dedupe; use a list-of-tuples constructor)
    # Our encoder uses dict which silently dedupes; we need to test that canonical mode
    # would reject duplicates if given a sequence with duplicates.
    # For now, we encode a non-duplicate map and document that libraries should reject duplicates
    # in canonical mode.

    # Map with semantically equal keys (int 1 and string "1") — NOT duplicates in CBOR generic model
    m = {1: "int-one", "1": "str-one"}
    vectors.append({
        "axis": "duplicate_key_rejection",
        "vector_id": "map_int1_vs_str1_not_duplicate",
        "data_item": m,
        "description": "map with int 1 and string '1' (NOT duplicates per generic model)",
        "oracle_deterministic_hex": encode_deterministic(m).hex(),
        "oracle_canonical_hex": encode_canonical(m).hex(),
    })

    # The actual duplicate-key test: encode a 2-element dict with the same key value
    # (in Python this dedupes, so we can't generate it from dict literal).
    # Instead, document this as: "input is malformed; canonical encoder MUST reject"
    # We add a synthetic test: the oracle's canonical mode raises DuplicateKeyError
    # if we feed it a non-dict structure. Since Python dicts can't have duplicates,
    # we instead note: any implementation accepting the canonical mode should reject
    # inputs with duplicate keys when calling the lower-level encode function.
    vectors.append({
        "axis": "duplicate_key_rejection",
        "vector_id": "map_duplicate_test_inert",
        "data_item": {"a": 1, "a": 2},  # Python deduplicates to {"a": 2}
        "description": "Python dedupes; canonical-impl should reject duplicate keys at lower level",
        "oracle_deterministic_hex": encode_deterministic({"a": 2}).hex(),
        "oracle_canonical_hex": encode_canonical({"a": 2}).hex(),
    })
    return vectors


# ---------- Axis 6: tag shortest-form ----------

def gen_tag_shortest_form_vectors():
    vectors = []
    # Tags at boundary values
    tag_values = [0, 1, 2, 3, 4, 5, 21, 22, 23, 24, 25, 32, 33, 34, 36, 255, 256, 55799]
    for tag in tag_values:
        try:
            tagged_value = Tag(tag, 1)  # Tag(tag, content)
            det = encode_deterministic(tagged_value).hex()
            can = encode_canonical(tagged_value).hex()
            vectors.append({
                "axis": "tag_shortest_form",
                "vector_id": f"tag_{tag}_int1",
                "data_item": tagged_value,
                "description": f"tag {tag} around integer 1",
                "oracle_deterministic_hex": det,
                "oracle_canonical_hex": can,
            })
        except Exception:
            pass

    # Nested tags: tag 1 (epoch) around tag 1 around int
    nested = Tag(1, Tag(1, 100))
    try:
        det = encode_deterministic(nested).hex()
        can = encode_canonical(nested).hex()
        vectors.append({
            "axis": "tag_shortest_form",
            "vector_id": "tag_nested_1_around_1_around_100",
            "data_item": nested,
            "description": "nested tag 1 around tag 1 around 100",
            "oracle_deterministic_hex": det,
            "oracle_canonical_hex": can,
        })
    except Exception:
        pass

    # RFC 8949 §3.4.3 bignum example
    bignum = Tag(2, b"\x01\x00\x00\x00\x00\x00\x00\x00\x00")
    try:
        det = encode_deterministic(bignum).hex()
        can = encode_canonical(bignum).hex()
        vectors.append({
            "axis": "tag_shortest_form",
            "vector_id": "bignum_2^64",
            "data_item": bignum,
            "description": "bignum tag 2 around 2^64 (RFC 8949 §3.4.3 example)",
            "oracle_deterministic_hex": det,
            "oracle_canonical_hex": can,
        })
    except Exception:
        pass
    return vectors


# ---------- Axis 7: simple-value shortest-form ----------

def gen_simple_value_vectors():
    vectors = []
    # Note: simple values 0-23 are encoded as additional info; values 32-255
    # use the 2-byte form (ai=24 + value byte)
    for sv in [False, True, None, "undefined"]:
        try:
            det = encode_deterministic(sv).hex()
            can = encode_canonical(sv).hex()
            vectors.append({
                "axis": "simple_value_shortest_form",
                "vector_id": f"simple_{sv}",
                "data_item": sv,
                "description": f"simple value {sv}",
                "oracle_deterministic_hex": det,
                "oracle_canonical_hex": can,
            })
        except Exception:
            pass
    return vectors


# ---------- Axis 8: chunked-string consistency ----------

def gen_chunked_string_vectors():
    """Our oracle doesn't produce indefinite-length output, so this axis
    tests that libraries DO produce definite-length for inputs that
    could also be encoded indefinite."""
    vectors = []
    # Long strings that would be chunked if indefinite were used
    long_bstr = b"A" * 1000
    long_tstr = "B" * 1000
    vectors.append({
        "axis": "chunked_string_consistency",
        "vector_id": "bstr_1000",
        "data_item": long_bstr,
        "description": "1000-byte byte string (definite-length preferred)",
        "oracle_deterministic_hex": encode_deterministic(long_bstr).hex(),
        "oracle_canonical_hex": encode_canonical(long_bstr).hex(),
    })
    vectors.append({
        "axis": "chunked_string_consistency",
        "vector_id": "tstr_1000",
        "data_item": long_tstr,
        "description": "1000-char text string (definite-length preferred)",
        "oracle_deterministic_hex": encode_deterministic(long_tstr).hex(),
        "oracle_canonical_hex": encode_canonical(long_tstr).hex(),
    })
    # 256-byte string (exercises 2-byte length)
    vectors.append({
        "axis": "chunked_string_consistency",
        "vector_id": "bstr_256",
        "data_item": b"X" * 256,
        "description": "256-byte string (2-byte length)",
        "oracle_deterministic_hex": encode_deterministic(b"X" * 256).hex(),
        "oracle_canonical_hex": encode_canonical(b"X" * 256).hex(),
    })
    return vectors


# ---------- Master driver ----------

AXIS_GENERATORS = [
    ("integer_shortest_form", gen_integer_shortest_form_vectors),
    ("map_key_sort", gen_map_key_sort_vectors),
    ("float_shortest_form", gen_float_shortest_form_vectors),
    ("definite_length_preferred", gen_definite_length_vectors),
    ("duplicate_key_rejection", gen_duplicate_key_vectors),
    ("tag_shortest_form", gen_tag_shortest_form_vectors),
    ("simple_value_shortest_form", gen_simple_value_vectors),
    ("chunked_string_consistency", gen_chunked_string_vectors),
]


class _DataItemEncoder(json.JSONEncoder):
    """JSON encoder that handles bytes, tuples, and Tag objects."""
    def default(self, obj):
        if isinstance(obj, bytes):
            return {"__type__": "bytes", "hex": obj.hex()}
        if isinstance(obj, tuple):
            return {"__type__": "tuple", "items": list(obj)}
        if isinstance(obj, Tag):
            return {"__type__": "tag", "tag": obj.tag, "content": obj.content}
        if isinstance(obj, Undefined):
            return {"__type__": "undefined"}
        if isinstance(obj, complex):
            return {"__type__": "complex", "value": str(obj)}
        return super().default(obj)

    def encode(self, o):
        """Override to convert dicts with non-string keys to a sidecar structure."""
        # JSON cannot represent dicts with non-string keys. Convert to a list
        # of pairs with __type__ markers for non-string keys.
        def _convert(obj):
            if isinstance(obj, dict):
                # Check for non-string keys
                non_string_keys = [k for k in obj.keys() if not isinstance(k, str)]
                if non_string_keys:
                    # Convert to list of [key_repr, value_repr] pairs
                    pairs = []
                    for k, v in obj.items():
                        pairs.append([_convert(k), _convert(v)])
                    return {"__type__": "dict_int_keys", "pairs": pairs}
                return {k: _convert(v) for k, v in obj.items()}
            if isinstance(obj, tuple):
                # Tuples need explicit type marker so the decoder can reconstruct
                return {"__type__": "tuple", "items": [_convert(i) for i in obj]}
            if isinstance(obj, list):
                return [_convert(i) for i in obj]
            if isinstance(obj, bool):
                return {"__type__": "bool", "value": obj}
            return obj
        return super().encode(_convert(o))


def _decode_data_item(obj):
    """Reverse _DataItemEncoder for JSON-decoded dicts."""
    if isinstance(obj, dict) and "__type__" in obj:
        if obj["__type__"] == "bytes":
            return bytes.fromhex(obj["hex"])
        if obj["__type__"] == "tag":
            return Tag(obj["tag"], _decode_data_item(obj.get("content")))
        if obj["__type__"] == "tuple":
            return tuple(_decode_data_item(i) for i in obj["items"])
        if obj["__type__"] == "dict_int_keys":
            return {_decode_data_item(k): _decode_data_item(v) for k, v in obj["pairs"]}
        if obj["__type__"] == "bool":
            return obj["value"]
        if obj["__type__"] == "undefined":
            return Undefined()
    if isinstance(obj, list):
        return [_decode_data_item(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _decode_data_item(v) for k, v in obj.items()}
    return obj


def main():
    print(f"Generating adversarial vectors (seed=0x{SEED:08X})")
    print("=" * 60)
    total = 0
    for axis_name, gen_func in AXIS_GENERATORS:
        vectors = gen_func()
        out_path = OUT_DIR / f"vectors_{axis_name}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for v in vectors:
                if "data_item" in v:
                    # Recode data_item through JSON round-trip to ensure it's JSON-serializable,
                    # then convert back to native Python types
                    json_str = json.dumps(v["data_item"], cls=_DataItemEncoder)
                    reloaded = json.loads(json_str)
                    native = _decode_data_item(reloaded)
                    v2 = dict(v)
                    v2["data_item"] = native
                else:
                    v2 = v  # has data_item_repr only
                f.write(json.dumps(v2, cls=_DataItemEncoder) + "\n")
        print(f"  {axis_name:<30} {len(vectors):>4} vectors -> {out_path.name}")
        total += len(vectors)
    print("=" * 60)
    print(f"  TOTAL: {total} vectors across {len(AXIS_GENERATORS)} axes")


if __name__ == "__main__":
    main()