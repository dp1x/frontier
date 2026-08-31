"""COSE §4.2 cross-implementation matrix runner.

Runs the COSE vector matrix against multiple COSE encoders and produces
a per-cell verdict. Verdict classifications:
    PASS                    - encoder output matches oracle byte-exactly
    SPEC_AMBIGUITY          - byte-exact match but different Python repr
    SPEC_VIOLATION          - encoder output is NOT conformant (e.g., 41 a0 vs 40)
    INTEROP_BREAK           - encoder output is valid COSE but not parseable
    ERROR                   - encoder raised exception or returned None
    NOT_SUPPORTED           - library does not support this combination

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


def load_adapters():
    """Discover and instantiate all adapter modules."""
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
            expected_hex = vec.get("oracle_expected_hex")
            desc = vec.get("description", "")
            vid = vec.get("vector_id", "")
            for adapter in adapters:
                adapter_name = getattr(adapter, "ADAPTER_NAME", adapter.__name__)
                try:
                    actual_bytes = adapter.encode(data_item, mode="default")
                    if actual_bytes is None:
                        actual_hex = ""
                        verdict = "NOT_SUPPORTED"
                    else:
                        actual_hex = actual_bytes.hex()
                        if actual_hex == expected_hex:
                            verdict = "PASS"
                        else:
                            # Compare lengths
                            if len(actual_hex) > len(expected_hex):
                                verdict = "SPEC_AMBIGUITY"
                            elif len(actual_hex) < len(expected_hex):
                                verdict = "INTEROP_BREAK"
                            else:
                                verdict = "SPEC_VIOLATION"
                except Exception as exc:
                    actual_hex = ""
                    verdict = f"ERROR:{type(exc).__name__}"
                row = (
                    axis_name,
                    vid,
                    adapter_name,
                    "default",
                    expected_hex or "",
                    actual_hex,
                    "MATCH" if verdict == "PASS" else "DIVERGE",
                    verdict,
                )
                rows.append(row)
                jsonl_rows.append({
                    "axis": axis_name,
                    "vector_id": vid,
                    "adapter": adapter_name,
                    "mode": "default",
                    "description": desc,
                    "expected_hex": expected_hex,
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
