"""Run the UTF-8 validity corpus through all three implementations."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vectors" / "vectors.jsonl"
ADAPTERS = ROOT / "adapters"
RESULTS = ROOT / "results"
_rust = os.environ.get("UTF8_RUST_EXE", str(ADAPTERS / "rust_utf8.exe"))
_go = os.environ.get("UTF8_GO_EXE", str(ADAPTERS / "go_utf8.exe"))
_simd = os.environ.get("UTF8_SIMDUTF_EXE", str(ADAPTERS / "simdutf_utf8.exe"))
IMPLS = {
    "rust_core_str_from_utf8": Path(_rust),
    "go_unicode_utf8_Valid": Path(_go),
    "simdutf_validate_utf8": Path(_simd),
}


def run_one(exe: Path, data: bytes) -> dict:
    try:
        proc = subprocess.run(
            [str(exe)],
            input=data,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"result": "TIMEOUT", "stdout": "", "stderr": "timeout", "rc": None}
    except Exception as e:  # noqa: BLE001
        return {"result": "ERROR", "stdout": "", "stderr": str(e), "rc": None}
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    err = proc.stderr.decode("utf-8", errors="replace").strip()
    if out == "VALID":
        res = "VALID"
    elif out == "INVALID":
        res = "INVALID"
    else:
        res = "ERROR"
    return {"result": res, "stdout": out, "stderr": err, "rc": proc.returncode}


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    raw = VECTORS.read_text(encoding="utf-8").splitlines()
    vectors = [json.loads(line) for line in raw if line.strip()]
    rows = []
    mismatches = 0
    for v in vectors:
        data = bytes.fromhex(v["bytes_hex"])
        row = {
            "id": v["id"],
            "bytes_hex": v["bytes_hex"],
            "expected_oracle": v["expected"],
            "category": v["category"],
        }
        impl_results = {}
        for name, exe in IMPLS.items():
            r = run_one(exe, data)
            impl_results[name] = r
            row[name] = r["result"]
            row[name + "_stderr"] = r["stderr"]
        # agreement check
        vals = [impl_results[n]["result"] for n in IMPLS]
        expected_str = "VALID" if v["expected"] else "INVALID"
        row["all_agree_with_each_other"] = len(set(vals)) == 1
        row["all_agree_with_oracle"] = (vals[0] == expected_str) and len(set(vals)) == 1
        if not row["all_agree_with_oracle"]:
            mismatches += 1
        rows.append(row)

    # write jsonl
    with (RESULTS / "matrix.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    # write tsv
    cols = (["id", "bytes_hex", "category", "expected_oracle"]
            + list(IMPLS.keys())
            + ["all_agree_with_each_other", "all_agree_with_oracle"])
    with (RESULTS / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("\t".join(cols) + "\n")
        for r in rows:
            f.write("\t".join(str(r[c]) for c in cols) + "\n")

    # summary
    print(f"vectors: {len(rows)}")
    print(f"mismatches vs oracle: {mismatches}")
    # category-level
    from collections import Counter
    cat_total = Counter()
    cat_mismatch = Counter()
    for r in rows:
        cat_total[r["category"]] += 1
        if not r["all_agree_with_oracle"]:
            cat_mismatch[r["category"]] += 1
    print("per-category (total / mismatch):")
    for c in sorted(cat_total):
        print(f"  {c}: {cat_total[c]} / {cat_mismatch[c]}")
    # impl error counts
    for name in IMPLS:
        errs = sum(1 for r in rows if r[name] == "ERROR")
        print(f"{name}: errors={errs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
