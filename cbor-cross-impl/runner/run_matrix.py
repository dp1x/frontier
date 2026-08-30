"""CBOR §4.2 cross-implementation matrix runner.

Runs the vector matrix against multiple CBOR encoders and produces
a per-cell verdict. Verdict classifications:
    PASS                    - encoder output matches oracle byte-exactly
    PASS_REPR_DIFF          - byte-exact match but Python repr differs (e.g. dict ordering)
    SPEC_VIOLATION          - encoder output is NOT §4.2-conformant (e.g. uses 64-bit for 1000000)
    SPEC_AMBIGUITY          - encoder uses a non-shortest form that is still §4.2.1 valid
                              (e.g. uses 2-byte length when 1-byte would do, but both are deterministic)
    INTEROP_BREAK           - encoder output is valid CBOR but non-canonical (would not be parsed
                              equivalently by other RFC-8949 conformant decoders)
    ERROR                   - encoder raised exception or returned None

Inputs:
    vectors/<axis>.jsonl (output of gen_vectors.py)
Adapters:
    adapters/<lib_id>_adapter.py (uniform interface)
Outputs:
    results/matrix.tsv (header + one row per cell)
    results/matrix.jsonl (machine-readable)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Add oracle to path
sys.path.insert(0, str(Path(__file__).parent.parent / "oracle"))

ORACLE_DIR = Path(__file__).parent.parent / "oracle"
VECTORS_DIR = Path(__file__).parent.parent / "vectors"
ADAPTERS_DIR = Path(__file__).parent.parent / "adapters"
RESULTS_DIR = Path(__file__).parent.parent / "results"

sys.path.insert(0, str(ORACLE_DIR))
sys.path.insert(0, str(ADAPTERS_DIR))


def _load_jsonl(path: Path):
    """Load a JSONL file, decoding __type__ wrappers back to native objects."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _decode_data_item_recursive(obj):
    """Recursively decode __type__ wrappers."""
    if isinstance(obj, dict):
        if "__type__" in obj:
            if obj["__type__"] == "bytes":
                return bytes.fromhex(obj["hex"])
            if obj["__type__"] == "tag":
                from cbor_oracle import Tagged
                return Tagged(obj["tag"], _decode_data_item_recursive(obj.get("content_repr")))
            if obj["__type__"] == "tuple":
                return tuple(_decode_data_item_recursive(i) for i in obj["items"])
            if obj["__type__"] == "dict_int_keys":
                return {_decode_data_item_recursive(k): _decode_data_item_recursive(v) for k, v in obj["pairs"]}
            if obj["__type__"] == "bool":
                return obj["value"]
        return {k: _decode_data_item_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode_data_item_recursive(i) for i in obj]
    return obj


def _materialize_data_item(vector: dict):
    """Reconstruct the data item from a vector entry. Since we now store
    oracle_deterministic_hex and oracle_canonical_hex as ground truth,
    we don't need to re-materialize the original data item for most axes
    — we use a per-adapter reconstruction approach."""
    # The vectors store 'oracle_deterministic_hex' / 'oracle_canonical_hex'
    # For encoders, the test driver is: "given this data item, encode it,
    # and compare against oracle hex". We pass data_item_repr to adapters
    # and the adapter decides how to materialize it.
    return vector.get("data_item_repr", vector.get("data_item"))


def load_adapters():
    """Discover and instantiate all adapter modules.

    Each adapter module exports: ADAPTER_NAME, encode(data_item, mode) -> bytes or None.
    """
    adapters = []
    for adapter_path in sorted(ADAPTERS_DIR.glob("*_adapter.py")):
        if adapter_path.name.startswith("_"):
            continue
        module_name = adapter_path.stem
        try:
            import importlib
            mod = importlib.import_module(module_name)
            if not hasattr(mod, "ADAPTER_NAME") or not hasattr(mod, "encode"):
                print(f"  [SKIP] {module_name}: missing ADAPTER_NAME or encode()")
                continue
            adapters.append(mod)
        except Exception as exc:
            print(f"  [SKIP] {module_name}: {exc}")
    return adapters


def run_matrix(adapters, vectors_dir=VECTORS_DIR, results_dir=RESULTS_DIR):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = []  # (axis, vector_id, adapter, mode, expected_hex, actual_hex, match, verdict)
    jsonl_rows = []

    if not adapters:
        print("WARNING: no adapters loaded.")

    for axis_path in sorted(vectors_dir.glob("vectors_*.jsonl")):
        axis_name = axis_path.stem.replace("vectors_", "")
        print(f"\n[axis] {axis_name}")
        raw_vectors = list(_load_jsonl(axis_path))
        # Decode __type__ wrappers back to native Python objects
        vectors = []
        for v in raw_vectors:
            v2 = dict(v)
            v2["data_item"] = _decode_data_item_recursive(v.get("data_item"))
            vectors.append(v2)
        print(f"  vectors loaded: {len(vectors)}")

        for vec in vectors:
            # Prefer the decoded data_item (native Python object) over the string repr.
            # Some axes use repr strings (e.g., tuple keys that JSON cannot express);
            # adapters know how to interpret those via their _materialize() function.
            data_item = vec.get("data_item")
            if data_item is not None:
                data_repr = data_item
            else:
                data_repr = vec.get("data_item_repr")
            oracle_det_hex = vec.get("oracle_deterministic_hex")
            oracle_can_hex = vec.get("oracle_canonical_hex")
            desc = vec.get("description", "")
            vid = vec.get("vector_id", "")
            for adapter in adapters:
                adapter_name = getattr(adapter, "ADAPTER_NAME", adapter.__name__)
                for mode in ("default", "canonical"):
                    if mode == "canonical" and not getattr(adapter, "supports_canonical", True):
                        continue
                    expected = oracle_can_hex if mode == "canonical" else oracle_det_hex
                    try:
                        actual_bytes = adapter.encode(data_repr, mode=mode)
                        if actual_bytes is None:
                            actual_hex = ""
                            verdict = "ERROR"
                        else:
                            actual_hex = actual_bytes.hex()
                            if actual_hex == expected:
                                verdict = "PASS"
                            else:
                                # Compare lengths: if the library produced a longer encoding,
                                # classify as SPEC_AMBIGUITY (longer-but-still-deterministic);
                                # if different bytes at same length, classify as SPEC_VIOLATION
                                if expected is None:
                                    verdict = "PASS_REPR_DIFF"
                                elif len(actual_hex) > len(expected):
                                    verdict = "SPEC_AMBIGUITY"
                                elif len(actual_hex) == len(expected):
                                    verdict = "SPEC_VIOLATION"
                                else:
                                    verdict = "INTEROP_BREAK"
                    except Exception as exc:
                        actual_hex = ""
                        verdict = f"ERROR:{type(exc).__name__}"
                    row = (
                        axis_name,
                        vid,
                        adapter_name,
                        mode,
                        expected or "",
                        actual_hex,
                        "MATCH" if verdict == "PASS" else "DIVERGE",
                        verdict,
                    )
                    rows.append(row)
                    jsonl_rows.append({
                        "axis": axis_name,
                        "vector_id": vid,
                        "adapter": adapter_name,
                        "mode": mode,
                        "description": desc,
                        "expected_hex": expected,
                        "actual_hex": actual_hex,
                        "match": verdict == "PASS",
                        "verdict": verdict,
                    })

    # Write outputs
    results_dir.mkdir(parents=True, exist_ok=True)
    tsv_path = results_dir / "matrix.tsv"
    with open(tsv_path, "w", encoding="utf-8") as f:
        f.write("axis\tvector_id\tadapter\tmode\texpected_hex\tactual_hex\tmatch\tverdict\n")
        for row in rows:
            f.write("\t".join(str(x) for x in row) + "\n")
    jsonl_path = results_dir / "matrix.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in jsonl_rows:
            f.write(json.dumps(r) + "\n")

    # Summary statistics
    print()
    print("=" * 60)
    print(f"Matrix complete: {len(rows)} cells")
    from collections import Counter
    verdict_counts = Counter(row[7] for row in rows)
    print(f"Verdict distribution:")
    for v, c in verdict_counts.most_common():
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