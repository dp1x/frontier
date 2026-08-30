"""Adapter for cbor2 (Python).

cbor2 is a pure-Python CBOR encoder/decoder by Alex Grönholm.
- Default mode: NOT deterministic (allows map insertion order, non-shortest integers, etc.)
- canonical=True: deterministic + duplicate-key rejection
- canonical=False (default): non-canonical

Per cbor2 docs (https://github.com/agronholm/cbor2):
"The canonical=True option produces an output that is in the
deterministic CBOR format as defined in RFC 7049 §3.9 (and the
updated RFC 8949 §4.2)."

We expose both modes for cross-impl comparison.

Data item format: the runner passes a data_item_repr string for axes
that have non-JSON-native data (tuples, bytes, tags). This adapter
recognizes the special reprs and reconstructs the data item from them.
For native JSON types (int, float, str, bool, None, list, dict with
JSON-native keys), it passes them through directly.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "oracle"))

import cbor2
from cbor2 import CBORTag
from cbor_oracle import Tagged, Undefined

ADAPTER_NAME = "lib_cbor2"
LIB_VERSION = "6.1.4"
supports_canonical = True

# Special repr tokens used in vectors for non-JSON-native data items.
import re
from typing import Any


def _materialize(data_item: Any) -> Any:
    """Reconstruct a CBOR data item from its string repr if needed.

    The runner passes either a Python object directly (for JSON-native
    types like int, float, str, bool, None, list, dict with JSON-native
    keys) or a string repr (for tuples as array keys, bytes, tags).

    We recognize these patterns:
      - "{100:1, 'z':1, ...}" - dict literal (parse with ast.literal_eval)
      - "Tag(N, content_repr)" - tagged value
      - "[100]" / "[-1]" - tuple-as-array-key (handled by parent map)
      - anything else - return as-is (Python object)
    """
    # Pass through native Python types unchanged
    if isinstance(data_item, (int, float, bool, type(None), str, bytes, list, tuple, dict, Tagged, Undefined)):
        return data_item
    if not isinstance(data_item, str):
        return data_item
    s = data_item.strip()
    if s.startswith("Tag("):
        # Parse "Tag(tag, content)" where content may be a string repr
        m = re.match(r"Tag\((\d+),\s*(.*)\)$", s, re.DOTALL)
        if m:
            tag_num = int(m.group(1))
            content_str = m.group(2)
            # Try to materialize content_str as Python literal
            try:
                import ast
                content = ast.literal_eval(content_str)
            except Exception:
                content = content_str
            return CBORTag(tag_num, content)
    if s.startswith("{") and s.endswith("}"):
        # Dict literal — parse with ast.literal_eval, then convert tuples to arrays
        import ast
        d = ast.literal_eval(s)
        # Tuple keys (e.g., (100,)) are already tuples; CBOR encodes tuples as arrays
        return d
    if s.startswith("b\"") or s.startswith("b'"):
        # Bytes literal
        import ast
        return ast.literal_eval(s)
    # Try parsing as Python literal for general cases
    try:
        import ast
        return ast.literal_eval(s)
    except Exception:
        return data_item


def _convert_to_cbor2_native(item: Any) -> Any:
    """Recursively convert Frontier Tagged/Undefined sentinels to cbor2's
    CBORTag / undefined types so cbor2 can encode them."""
    if isinstance(item, Tagged):
        return CBORTag(item.tag, _convert_to_cbor2_native(item.content))
    if isinstance(item, Undefined):
        return cbor2.undefined
    if isinstance(item, dict):
        return {_convert_to_cbor2_native(k): _convert_to_cbor2_native(v) for k, v in item.items()}
    if isinstance(item, list):
        return [_convert_to_cbor2_native(i) for i in item]
    if isinstance(item, tuple):
        return tuple(_convert_to_cbor2_native(i) for i in item)
    return item


def encode(data_item: Any, mode: str = "default") -> bytes | None:
    """Encode a CBOR data item using cbor2.

    mode='default': cbor2.dumps(obj) (default mode, NOT necessarily deterministic)
    mode='canonical': cbor2.dumps(obj, canonical=True) (RFC 8949 §4.2 deterministic)
    """
    try:
        item = _materialize(data_item)
        item = _convert_to_cbor2_native(item)
        if mode == "canonical":
            return cbor2.dumps(item, canonical=True)
        else:
            return cbor2.dumps(item)
    except Exception:
        return None