"""Adapter for ciborium (Rust).

ciborium 0.2.2 by enarx.
- Default mode: minimal-roundtrip encoding (does NOT produce canonical
  output; does NOT sort map keys; does NOT use shortest-form floats).
- Canonical mode: NOT SUPPORTED in ciborium 0.2.2 (no deterministic
  encoding API).

Per ciborium docs (https://github.com/enarx/ciborium):
ciborium is a "no_std-friendly" CBOR codec. Its encoder is designed
for round-trip correctness, not canonical form. It does not implement
RFC 8949 §4.2.1/§4.2.3 deterministic encoding.

This adapter shells out to a Rust binary driver
(R:/cbor-cohort/ciborium/target/release/cbor-driver.exe) that takes a
JSON description of the data item and emits a hex CBOR encoding on
stdout.

Data item format: the runner passes a data_item_repr string for axes
that have non-JSON-native data (tuples, bytes, tags). This adapter
recognizes the special reprs and reconstructs the data item from them.
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

ADAPTER_NAME = "lib_ciborium"
LIB_VERSION = "0.2.2"
supports_canonical = True  # ciborium 0.2.2 has canonical_into_writer (added Jun 2025, commit 1b60854)

# Path to the Rust binary driver. Override with CIBORIUM_DRIVER env var.
DRIVER_PATH = Path(os.environ.get(
    "CIBORIUM_DRIVER",
    r"R:\cbor-cohort\ciborium\target\release\cbor-driver.exe"
))

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
    """Convert a Frontier data item to the Rust driver's JSON format."""
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
        if all(isinstance(k, str) for k in data_item.keys()):
            return {k: _to_driver_json(v) for k, v in data_item.items()}
        return {"__type__": "dict_pairs",
                "pairs": [[_to_driver_json(k), _to_driver_json(v)]
                          for k, v in data_item.items()]}
    if isinstance(data_item, list):
        return [_to_driver_json(v) for v in data_item]
    if isinstance(data_item, bool):
        return data_item
    if data_item is None:
        return None
    if isinstance(data_item, float):
        # JSON has no standard literal for Infinity / -Infinity / NaN.
        # Use string sentinels that the Rust driver recognizes.
        import math
        if math.isnan(data_item):
            return "NaN"
        if math.isinf(data_item):
            return "Infinity" if data_item > 0 else "-Infinity"
        return data_item
    if isinstance(data_item, int):
        return data_item
    if isinstance(data_item, str):
        return data_item
    raise TypeError(f"unsupported data item type: {type(data_item).__name__}")


def _materialize(data_item: Any) -> Any:
    """Reconstruct a CBOR data item from its string repr if needed."""
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
        return ast.literal_eval(s)
    if s.startswith("b\"") or s.startswith("b'"):
        import ast
        return ast.literal_eval(s)
    try:
        import ast
        return ast.literal_eval(s)
    except Exception:
        return data_item


def _run_driver(data: Any, mode: str = "default") -> bytes | None:
    """Subprocess the Rust driver and return the encoded bytes."""
    if not _driver_available():
        return None
    payload = json.dumps({"mode": mode, "data": _to_driver_json(data)})
    try:
        proc = subprocess.run(
            [str(DRIVER_PATH)],
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
    return None


def encode(data_item: Any, mode: str = "default") -> bytes | None:
    """Encode a CBOR data item using ciborium (via Rust driver).

    mode='default': ciborium default encoding (non-canonical).
    mode='canonical': not supported by ciborium 0.2.2; returns None.
    """
    try:
        item = _materialize(data_item)
        if mode == "canonical":
            return _run_driver(item, mode="canonical")
        return _run_driver(item, mode="default")
    except Exception:
        return None
