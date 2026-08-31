"""Adapter for cbor-x (JavaScript/Node.js).

cbor-x 1.6.6 by Patrick Conant / dentsu-dev.
- Default mode: NOT canonical (insertion-order map keys, double-precision
  floats, no shortest-form, self-described CBOR header prepended by default).
- Canonical mode: NOT SUPPORTED (no deterministic encoding flag in API).

Per cbor-x docs (https://github.com/dentsu-dev/cbor-x):
"Ultra-fast and conformant CBOR (RFC 8949) implementation."

The library is described as "conformant" for decoding, but the encoder
behavior is optimized for speed, not canonical form. The encoder
prepends a self-described CBOR header (0xd9dfff) by default; it does
not sort map keys; it uses double-precision floats for all non-integer
floats; and it encodes small integer-valued floats as integers.

This adapter shells out to a Node.js driver (R:/cbor-cohort/cbor-x/driver.js)
that takes a JSON description of the data item and emits a hex CBOR
encoding on stdout. The adapter subprocesses it per call.

Data item format: the runner passes a data_item_repr string for axes
that have non-JSON-native data (tuples, bytes, tags). This adapter
recognizes the special reprs and reconstructs the data item from them.
For native JSON types (int, float, str, bool, None, list, dict with
JSON-native keys), it passes them through directly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "oracle"))

from cbor_oracle import Tagged, Undefined

ADAPTER_NAME = "lib_cbor_x"
LIB_VERSION = "1.6.6"
supports_canonical = False  # cbor-x has no canonical mode

# Path to the Node.js driver script
DRIVER_PATH = Path(os.environ.get(
    "CBOR_X_DRIVER",
    r"R:\cbor-cohort\cbor-x\driver.js"
))
NODE_BIN = os.environ.get("CBOR_X_NODE", "node")

# Cache the driver path check
_DRIVER_AVAILABLE = None


def _driver_available() -> bool:
    global _DRIVER_AVAILABLE
    if _DRIVER_AVAILABLE is not None:
        return _DRIVER_AVAILABLE
    if not DRIVER_PATH.exists():
        _DRIVER_AVAILABLE = False
        return False
    _DRIVER_AVAILABLE = True
    return True


def _to_driver_json(data_item: Any) -> dict:
    """Convert a Frontier data item to the cbor-x driver's JSON format.

    The driver expects:
      - plain JSON for native types
      - {"__type__": "bytes", "hex": "..."} for bytes
      - {"__type__": "tag", "tag": N, "content": <value>} for tags
      - {"__type__": "undefined"} for undefined (mapped to 0xf7 by the
        driver using encodeUndefinedAsNil=false)
      - {"__type__": "tuple", "items": [...]} for tuples
      - {"__type__": "dict_pairs", "pairs": [[k, v], ...]} for non-string
        keyed maps
    """
    if isinstance(data_item, Undefined):
        return {"__type__": "undefined"}
    if isinstance(data_item, Tagged):
        return {"__type__": "tag", "tag": data_item.tag,
                "content": _to_driver_json(data_item.content)}
    if isinstance(data_item, (bytes, bytearray)):
        return {"__type__": "bytes", "hex": bytes(data_item).hex()}
    if isinstance(data_item, tuple):
        return {"__type__": "tuple",
                "items": [_to_driver_json(v) for v in data_item]}
    if isinstance(data_item, dict):
        # Check if all keys are strings (plain JSON object)
        if all(isinstance(k, str) for k in data_item.keys()):
            return {k: _to_driver_json(v) for k, v in data_item.items()}
        # Non-string keys: emit as dict_pairs
        return {"__type__": "dict_pairs",
                "pairs": [[_to_driver_json(k), _to_driver_json(v)]
                          for k, v in data_item.items()]}
    if isinstance(data_item, list):
        return [_to_driver_json(v) for v in data_item]
    if isinstance(data_item, bool):
        return data_item
    if data_item is None:
        return None
    if isinstance(data_item, (int, float)):
        return data_item
    if isinstance(data_item, str):
        return data_item
    raise TypeError(f"unsupported data item type: {type(data_item).__name__}")


def _materialize(data_item: Any) -> Any:
    """Reconstruct a CBOR data item from its string repr if needed.

    The runner passes either a Python object directly (for JSON-native
    types) or a string repr (for tuples as array keys, bytes, tags).
    """
    if isinstance(data_item, (int, float, bool, type(None), str, bytes, list, tuple, dict, Tagged, Undefined)):
        return data_item
    if not isinstance(data_item, str):
        return data_item
    s = data_item.strip()
    if s.startswith("Tag("):
        import re
        import ast
        m = re.match(r"Tag\((\d+),\s*(.*)\)$", s, re.DOTALL)
        if m:
            tag_num = int(m.group(1))
            content_str = m.group(2)
            try:
                content = ast.literal_eval(content_str)
            except Exception:
                content = content_str
            return Tagged(tag_num, content)
    if s.startswith("{") and s.endswith("}"):
        import ast
        d = ast.literal_eval(s)
        return d
    if s.startswith("b\"") or s.startswith("b'"):
        import ast
        return ast.literal_eval(s)
    try:
        import ast
        return ast.literal_eval(s)
    except Exception:
        return data_item


def _run_driver(data: Any, mode: str = "default") -> bytes | None:
    """Subprocess the Node.js driver and return the encoded bytes.

    The driver emits:
      - "OK:<hex>" on success
      - "ERR:<msg>" on error
      - "CANONICAL_NOT_SUPPORTED" if canonical mode requested

    Returns None on error or if canonical mode was requested.
    """
    if not _driver_available():
        return None
    payload = json.dumps({"mode": mode, "data": _to_driver_json(data)})
    try:
        proc = subprocess.run(
            [NODE_BIN, str(DRIVER_PATH)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
    out = (proc.stdout or "").strip()
    if out.startswith("OK:"):
        hex_str = out[3:]
        try:
            return bytes.fromhex(hex_str)
        except Exception:
            return None
    return None  # ERR or CANONICAL_NOT_SUPPORTED both map to None


def encode(data_item: Any, mode: str = "default") -> bytes | None:
    """Encode a CBOR data item using cbor-x (via Node.js driver).

    mode='default': cbor-x default encoding (non-canonical).
    mode='canonical': not supported by cbor-x; returns None.
    """
    try:
        item = _materialize(data_item)
        if mode == "canonical":
            # cbor-x does not support canonical mode. The runner will
            # skip canonical cells for libraries with supports_canonical=False.
            return None
        return _run_driver(item, mode="default")
    except Exception:
        return None
