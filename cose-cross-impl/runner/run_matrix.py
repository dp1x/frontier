"""COSE §4 cross-implementation matrix runner (v2).

Operates on TWO levels:
  1. STRUCTURE level: compare Sig_structure / Enc_structure / MAC_structure
     bytes extracted from each library. This isolates message-construction
     logic from cryptography.
  2. WRAPPING level: compare the full CBOR-tagged COSE message bytes for
     the parts that don't depend on signature/ciphertext (i.e., the
     protected/unprotected header encoding). This catches things like
     empty-protected-bucket (40 vs 41 a0).

Verdict classifications (per AGENTS.md):
    PASS                    - byte-exact match with oracle
    SPEC_AMBIGUITY          - same semantics, different representation
    SPEC_VIOLATION          - encoder output is NOT conformant
    INTEROP_BREAK           - encoder output is valid but not parseable
    ERROR                   - encoder raised exception or returned None
    NOT_SUPPORTED           - library does not support this combination
    INSTRUMENT_QUESTION     - comparison uncertain (oracle/vector problem)

Inputs:
    vectors/<axis>.jsonl (output of gen_vectors.py)
Adapters:
    adapters/<lib_id>_adapter.py (uniform interface)
    Each adapter must expose:
        ADAPTER_NAME: str
        LIB_VERSION: str
        supports_canonical: bool
        encode(data_item, mode='default') -> bytes | None
        encode_structure(data_item) -> bytes | None
            Returns Sig_structure / Enc_structure / MAC_structure bytes
            (without the crypto applied) — the canonical to-be-signed bytes.

Outputs:
    results/matrix.tsv (header + one row per cell)
    results/matrix.jsonl (machine-readable)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ORACLE_DIR = Path(__file__).parent.parent / "oracle"
VECTORS_DIR = Path(__file__).parent.parent / "vectors"
ADAPTERS_DIR = Path(__file__).parent.parent / "adapters"
RESULTS_DIR = Path(__file__).parent.parent / "results"

sys.path.insert(0, str(ORACLE_DIR))
sys.path.insert(0, str(ADAPTERS_DIR))


def _load_jsonl(path: Path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def load_adapters(adapters_dir=ADAPTERS_DIR):
    adapters = []
    for adapter_path in sorted(adapters_dir.glob("*_adapter.py")):
        if adapter_path.name.startswith("_"):
            continue
        module_name = adapter_path.stem
        try:
            import importlib
            if module_name in sys.modules:
                importlib.reload(sys.modules[module_name])
            mod = importlib.import_module(module_name)
            if not hasattr(mod, "ADAPTER_NAME") or not hasattr(mod, "encode"):
                print(f"  [SKIP] {module_name}: missing ADAPTER_NAME or encode()")
                continue
            adapters.append(mod)
        except Exception as exc:
            print(f"  [SKIP] {module_name}: {exc}")
    return adapters


def classify_structure_match(actual: bytes | None, expected: bytes | None) -> tuple[str, str]:
    """Classify a structure-byte comparison."""
    if actual is None:
        return "NOT_SUPPORTED", "adapter returned None (no structure extraction)"
    if expected is None:
        return "INSTRUMENT_QUESTION", "no oracle expected bytes for this vector"
    if actual == expected:
        return "PASS", ""
    if len(actual) != len(expected):
        return "SPEC_VIOLATION", f"length mismatch: actual={len(actual)} expected={len(expected)}"
    # Same length but different bytes — check whether it's the empty-protected-bucket issue
    return "SPEC_VIOLATION", f"byte mismatch: actual={actual.hex()} expected={expected.hex()}"


def classify_full_message(actual: bytes | None, expected: bytes | None) -> tuple[str, str]:
    """Classify a full-message comparison.

    Full messages include signature/ciphertext/MAC, so byte-exact match
    is only meaningful when the matrix provides identical crypto inputs.
    For the wrapping-layer analysis, we only compare the header bytes.
    """
    if actual is None:
        return "NOT_SUPPORTED", "adapter returned None"
    if expected is None:
        return "INSTRUMENT_QUESTION", "no oracle expected bytes"
    if actual == expected:
        return "PASS", ""
    return "DIVERGE", f"actual={actual.hex()} expected={expected.hex()}"


def run_matrix(adapters, vectors_dir=VECTORS_DIR, results_dir=RESULTS_DIR):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    jsonl_rows = []

    if not adapters:
        print("WARNING: no adapters loaded.")

    for axis_path in sorted(vectors_dir.glob("vectors_*.jsonl")):
        axis_name = axis_path.stem.replace("vectors_", "")
        print(f"\n[axis] {axis_name}")
        raw_vectors = list(_load_jsonl(axis_path))
        print(f"  vectors loaded: {len(raw_vectors)}")

        for vec in raw_vectors:
            data_item = vec.get("data_item")
            expected_struct = vec.get("oracle_structure_hex")
            expected_msg = vec.get("oracle_message_hex")
            desc = vec.get("description", "")
            vid = vec.get("vector_id", "")

            for adapter in adapters:
                adapter_name = getattr(adapter, "ADAPTER_NAME", adapter.__name__)
                lib_version = getattr(adapter, "LIB_VERSION", "?")

                # --- STRUCTURE level ---
                struct_verdict = "NOT_SUPPORTED"
                struct_actual = ""
                struct_expected = expected_struct or ""
                struct_notes = ""
                if hasattr(adapter, "encode_structure"):
                    try:
                        actual_struct_bytes = adapter.encode_structure(data_item)
                    except Exception as exc:
                        actual_struct_bytes = None
                        struct_notes = f"exception: {type(exc).__name__}: {exc}"
                    struct_verdict, struct_msg = classify_structure_match(
                        actual_struct_bytes,
                        bytes.fromhex(expected_struct) if expected_struct else None,
                    )
                    if struct_notes:
                        struct_verdict = f"ERROR:{type(exc).__name__}"
                    struct_actual = actual_struct_bytes.hex() if actual_struct_bytes else ""
                    if not struct_notes and struct_msg:
                        struct_notes = struct_msg
                else:
                    struct_verdict = "NOT_SUPPORTED"
                    struct_notes = "adapter has no encode_structure()"

                # --- FULL MESSAGE level (for wrapping analysis only) ---
                msg_verdict = "NOT_SUPPORTED"
                msg_actual = ""
                msg_expected = expected_msg or ""
                msg_notes = ""
                try:
                    actual_msg_bytes = adapter.encode(data_item, mode="default")
                except Exception as exc:
                    actual_msg_bytes = None
                    msg_notes = f"exception: {type(exc).__name__}: {exc}"

                msg_verdict, msg_msg = classify_full_message(
                    actual_msg_bytes,
                    bytes.fromhex(expected_msg) if expected_msg else None,
                )
                msg_actual = actual_msg_bytes.hex() if actual_msg_bytes else ""
                if not msg_notes and msg_msg:
                    msg_notes = msg_msg

                row = (
                    axis_name, vid, adapter_name, lib_version,
                    struct_expected, struct_actual, struct_verdict, struct_notes,
                    msg_expected, msg_actual, msg_verdict, msg_notes,
                )
                rows.append(row)
                jsonl_rows.append({
                    "axis": axis_name,
                    "vector_id": vid,
                    "adapter": adapter_name,
                    "lib_version": lib_version,
                    "description": desc,
                    "oracle_structure_hex": struct_expected,
                    "actual_structure_hex": struct_actual,
                    "structure_verdict": struct_verdict,
                    "structure_notes": struct_notes,
                    "oracle_message_hex": msg_expected,
                    "actual_message_hex": msg_actual,
                    "message_verdict": msg_verdict,
                    "message_notes": msg_notes,
                })

    # Write outputs
    results_dir.mkdir(parents=True, exist_ok=True)
    tsv_path = results_dir / "matrix.tsv"
    with open(tsv_path, "w", encoding="utf-8") as f:
        f.write("axis\tvector_id\tadapter\tlib_version\texpected_struct_hex\tactual_struct_hex\tstruct_verdict\tstruct_notes\texpected_msg_hex\tactual_msg_hex\tmsg_verdict\tmsg_notes\n")
        for row in rows:
            f.write("\t".join(str(x) for x in row) + "\n")
    jsonl_path = results_dir / "matrix.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in jsonl_rows:
            f.write(json.dumps(r) + "\n")

    print()
    print("=" * 70)
    print(f"Matrix complete: {len(rows)} cells")
    from collections import Counter
    struct_counts = Counter(row[6] for row in rows)
    msg_counts = Counter(row[10] for row in rows)
    print(f"Structure-level verdict distribution:")
    for v, c in struct_counts.most_common():
        print(f"  {v:<25} {c:>5}")
    print(f"Message-level verdict distribution:")
    for v, c in msg_counts.most_common():
        print(f"  {v:<25} {c:>5}")
    print()
    print(f"Adapters: {[a.ADAPTER_NAME for a in adapters]}")
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", default=str(VECTORS_DIR))
    parser.add_argument("--results", default=str(RESULTS_DIR))
    args = parser.parse_args()
    adapters = load_adapters()
    run_matrix(adapters, Path(args.vectors), Path(args.results))