"""Adapter for go-cose (Veraison/ex-Mozilla) v1.3.0.

This adapter SHELLS OUT to a Go driver at R:/cose-cohort/go-cose/driver/driver.exe
which reads a JSON data item from stdin and emits the structure bytes (hex)
to stdout. The driver internally uses fxamacker/cbor with SortCoreDeterministic
(equivalent to RFC 8949 §4.2.1 bytewise-lex sort, which is what RFC 9052 §9
requires for COSE message structures).

Adapter interface mirrors lib_pycose_adapter.py.

For COSE_Encrypt0/COSE_Mac0, the driver constructs the structure bytes
directly using fxamacker/cbor (same backend go-cose uses internally).
This isolates message-construction logic from cryptography — exactly what
the Frontier matrix needs to compare.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ADAPTER_NAME = "lib_go_cose"
LIB_VERSION = "1.3.0"
supports_canonical = True  # go-cose uses CoreDeterministic (§4.2.1)

DRIVER_PATH = Path(r"R:\cose-cohort\go-cose\driver\driver.exe")
_DRIVER_AVAILABLE = DRIVER_PATH.exists()


def _run_driver(data_item: dict) -> bytes | None:
    """Run the go-cose driver with the given data item."""
    if not _DRIVER_AVAILABLE:
        return None
    try:
        proc = subprocess.run(
            [str(DRIVER_PATH)],
            input=json.dumps(data_item).encode("utf-8"),
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None
        out = json.loads(proc.stdout)
        hex_str = out.get("structure_hex")
        if not hex_str:
            return None
        return bytes.fromhex(hex_str)
    except Exception:
        return None


def _normalize_int_keys(d: dict | None) -> dict:
    """Convert string keys that look like ints to ints.

    Same convention as lib_pycose_adapter: JSON keys are strings, but COSE
    labels are int (alg=1, ctyp=3, kid=4, iv=5). We pass int keys through.
    """
    if not d:
        return {} if d is None else dict(d)
    out = {}
    for k, v in d.items():
        if isinstance(k, str):
            try:
                k = int(k)
            except ValueError:
                pass
        out[k] = v
    return out


def encode_structure(data_item: Any) -> bytes | None:
    """Extract Sig_structure / Enc_structure / MAC_structure bytes via go driver."""
    if not _DRIVER_AVAILABLE:
        return None
    try:
        msg_type = data_item.get("msg_type", "Sign1")
        protected = _normalize_int_keys(data_item.get("protected"))
        unprotected = _normalize_int_keys(data_item.get("unprotected"))
        payload_hex = data_item.get("payload", "")
        ciphertext_hex = data_item.get("ciphertext", "")
        skip_alg = data_item.get("skip_alg_header", False)
        kdf_context = data_item.get("kdf_context")

        driver_input = {
            "msg_type": msg_type,
            "protected": protected,
            "unprotected": unprotected,
            "payload": payload_hex,
            "ciphertext": ciphertext_hex,
            "kdf_context": kdf_context,
            "skip_alg_header": skip_alg,
        }
        return _run_driver(driver_input)
    except Exception:
        return None


def encode(data_item: Any, mode: str = "default") -> bytes | None:
    """Full message bytes — not yet supported by driver (no crypto)."""
    # The driver currently only computes structure bytes. For full-message
    # byte-exact comparison, we'd need to add SignAndEncode/Encrypt/ComputeTag
    # paths to the driver. The matrix treats full-message comparison as
    # message-level verdict.
    return None


def encode_kdf_context(data_item: Any) -> bytes | None:
    return _run_driver({"msg_type": "KDF_Context", "kdf_context": data_item.get("kdf_context")})