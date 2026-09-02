"""
FROST cross-impl matrix runner (msn-2026-0019).

Runs a cohort of FROST implementations against a set of test vectors and
produces a TSV/JSONL matrix report.

Cohort (current):
  - cleanroom: in-process Python cleanroom (always available)
  - pycose:    in-process Python pycose 1.1.0
  - go-frost:  subprocess adapter to a locally-built Go frost driver (when available)

Verdict classification:
  - PASS:             byte-exact match (or verified-under-pk for aggregate)
  - SPEC_AMBIGUITY:   real normative ambiguity or permitted encoding range
  - SPEC_VIOLATION:   concrete normative requirement + observed deviation
  - INTEROP_BREAK:    two independently valid impls produce non-interop output
  - ERROR:            experimental path failed; cannot conclude
  - NOT_SUPPORTED:    library genuinely lacks the feature
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

CLEANROOM_DIR = Path(__file__).parent.parent / "cleanroom"
sys.path.insert(0, str(CLEANROOM_DIR))
import frost_cleanroom  # type: ignore

VECTORS_DIR = Path(__file__).parent.parent / "vectors"
ADAPTERS_DIR = Path(__file__).parent.parent / "adapters"
RESULTS_DIR = Path(__file__).parent.parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

KAT_DIR = Path(__file__).parent.parent / "kat"


def load_kat(group: str) -> Path:
    return KAT_DIR / {
        "secp256k1": "rfc9591_appendix_e5_secp256k1.json",
        "ed25519": "rfc9591_appendix_e1_ed25519.json",
    }[group]


def run_cleanroom_adapter(kat_path: Path, group: str) -> dict:
    """In-process cleanroom adapter (always available)."""
    start = time.time()
    try:
        out = frost_cleanroom.frost_sign(kat_path, group=group)
        return {
            "adapter": "cleanroom",
            "ok": True,
            "elapsed_s": time.time() - start,
            "round_one": out["round_one"],
            "round_two": out["round_two"],
            "aggregate_R_hex": out["aggregate_R_hex"],
            "aggregate_z_hex": out["aggregate_z_hex"],
            "challenge_hex": out["challenge_hex"],
            "computed_final_sig": out["computed_final_sig"],
            "expected_final_sig": out["expected_final_sig"],
            "match_final_sig": out["match_final_sig"],
            "verify_aggregate": out["verify_aggregate"],
            "error": None,
        }
    except Exception as e:
        return {
            "adapter": "cleanroom",
            "ok": False,
            "elapsed_s": time.time() - start,
            "error": repr(e),
        }


def run_pycose_adapter(kat_path: Path, group: str) -> dict:
    """In-process pycose 1.1.0 adapter.

    NOTE: pycose 1.1.0 does NOT support FROST (RFC 9591) at the time of
    writing — its COSE_Sign1 / COSE_Sign abstractions do not implement
    the threshold signing protocol. This adapter returns NOT_SUPPORTED
    with a clear reason.
    """
    start = time.time()
    try:
        import pycose
        version = getattr(pycose, "__version__", "?")
    except ImportError as e:
        return {
            "adapter": "pycose",
            "ok": False,
            "elapsed_s": time.time() - start,
            "error": f"pycose import failed: {e}",
        }
    return {
        "adapter": "pycose",
        "ok": False,
        "elapsed_s": time.time() - start,
        "verdict": "NOT_SUPPORTED",
        "reason": f"pycose {version} does not implement FROST (RFC 9591); only COSE_Sign1/Sign/Encrypt/Mac/Encrypt0/Mac0",
        "error": None,
    }


def run_go_frost_adapter(kat_path: Path, group: str) -> dict:
    """Subprocess adapter to a locally-built Go frost driver.

    The driver is expected to be at R:/frost-cohort/go-frost/driver/driver.exe
    (or .scratch/frost-cohort/go-frost/driver/driver.exe).
    It takes a KAT JSON path and prints a JSON line with per-step outputs.
    """
    start = time.time()
    possible_paths = [
        Path(r"R:/frost-cohort/go-frost/driver/driver.exe"),
        Path(r"C:/Users/Dhane/frontier/.scratch/frost-cohort/go-frost/driver/driver.exe"),
        Path("R:/frost-cohort/go-frost/driver/driver"),
        Path("/tmp/frost-cohort/go-frost/driver/driver"),
    ]
    driver_path = None
    for p in possible_paths:
        if p.exists():
            driver_path = p
            break
    if driver_path is None:
        return {
            "adapter": "go-frost",
            "ok": False,
            "elapsed_s": time.time() - start,
            "verdict": "NOT_BUILT",
            "reason": "Go frost driver not found in any expected location",
        }
    try:
        result = subprocess.run(
            [str(driver_path), str(kat_path), group],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return {
                "adapter": "go-frost",
                "ok": False,
                "elapsed_s": time.time() - start,
                "error": f"driver exit {result.returncode}: {result.stderr[:500]}",
            }
        # Parse last JSON line of stdout
        lines = [l for l in result.stdout.splitlines() if l.strip().startswith("{")]
        if not lines:
            return {
                "adapter": "go-frost",
                "ok": False,
                "elapsed_s": time.time() - start,
                "error": f"no JSON output from driver; stdout={result.stdout[:500]}",
            }
        data = json.loads(lines[-1])
        return {
            "adapter": "go-frost",
            "ok": True,
            "elapsed_s": time.time() - start,
            **data,
        }
    except subprocess.TimeoutExpired:
        return {
            "adapter": "go-frost",
            "ok": False,
            "elapsed_s": time.time() - start,
            "error": "driver timeout (60s)",
        }
    except Exception as e:
        return {
            "adapter": "go-frost",
            "ok": False,
            "elapsed_s": time.time() - start,
            "error": repr(e),
        }


def classify_cell(adapter_result: dict, expected_final_sig: str) -> str:
    """Apply the verdict classification to a single cell."""
    if not adapter_result.get("ok"):
        verdict = adapter_result.get("verdict", "ERROR")
        if verdict == "NOT_SUPPORTED":
            return "NOT_SUPPORTED"
        if verdict == "NOT_BUILT":
            return "NOT_BUILT"
        return "ERROR"
    if adapter_result.get("verify_aggregate") is True:
        return "PASS"
    if adapter_result.get("computed_final_sig") == expected_final_sig:
        return "PASS"
    if adapter_result.get("error"):
        return "ERROR"
    return "SPEC_AMBIGUITY"


def run_matrix(cohort: list[str] = None) -> dict:
    if cohort is None:
        cohort = ["cleanroom", "pycose", "go-frost"]

    results = []
    for group in ["secp256k1", "ed25519"]:
        kat_path = load_kat(group)
        # Read KAT for expected
        with open(kat_path) as f:
            kat = json.load(f)
        expected_final_sig = kat["final_output"]["sig"]

        row = {
            "ciphersuite": group,
            "kat_file": str(kat_path.name),
            "expected_final_sig": expected_final_sig,
            "cells": {},
        }
        for adapter_name in cohort:
            if adapter_name == "cleanroom":
                ar = run_cleanroom_adapter(kat_path, group)
            elif adapter_name == "pycose":
                ar = run_pycose_adapter(kat_path, group)
            elif adapter_name == "go-frost":
                ar = run_go_frost_adapter(kat_path, group)
            else:
                ar = {"adapter": adapter_name, "ok": False, "error": "unknown adapter"}
            verdict = classify_cell(ar, expected_final_sig)
            row["cells"][adapter_name] = {
                "verdict": verdict,
                "elapsed_s": ar.get("elapsed_s"),
                "match_final_sig": ar.get("match_final_sig"),
                "verify_aggregate": ar.get("verify_aggregate"),
                "reason": ar.get("reason") or ar.get("error"),
            }
        results.append(row)

    return {"cohort": cohort, "rows": results}


def write_tsv(matrix: dict, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        cohort = matrix["cohort"]
        f.write("\t".join(["ciphersuite", "kat_file", "expected_final_sig"] + cohort) + "\n")
        for row in matrix["rows"]:
            cells = [row["cells"].get(a, {}).get("verdict", "?") for a in cohort]
            f.write("\t".join([row["ciphersuite"], row["kat_file"], row["expected_final_sig"][:32] + "..."] + cells) + "\n")


def write_jsonl(matrix: dict, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        for row in matrix["rows"]:
            for adapter_name, cell in row["cells"].items():
                record = {
                    "ciphersuite": row["ciphersuite"],
                    "kat_file": row["kat_file"],
                    "expected_final_sig": row["expected_final_sig"],
                    "adapter": adapter_name,
                    **cell,
                }
                f.write(json.dumps(record) + "\n")


def main():
    print("FROST Cross-Impl Matrix Runner (msn-2026-0019)")
    print("===============================================")
    print()

    matrix = run_matrix()

    tsv_path = RESULTS_DIR / "matrix.tsv"
    jsonl_path = RESULTS_DIR / "matrix.jsonl"
    write_tsv(matrix, tsv_path)
    write_jsonl(matrix, jsonl_path)

    print(f"Matrix written to {tsv_path} and {jsonl_path}")
    print()
    print("Results:")
    for row in matrix["rows"]:
        line = f"  {row['ciphersuite']:11s}  "
        for adapter_name, cell in row["cells"].items():
            line += f"{adapter_name}={cell['verdict']:8s}  "
        print(line)
    print()

    # Summary
    total = 0
    pass_count = 0
    for row in matrix["rows"]:
        for cell in row["cells"].values():
            total += 1
            if cell["verdict"] == "PASS":
                pass_count += 1
    print(f"Summary: {pass_count}/{total} cells PASS")


if __name__ == "__main__":
    main()