import json, subprocess, sys, os

HARNESS = sys.argv[1]
VECTORS = sys.argv[2]
OUT = sys.argv[3]
LABEL = sys.argv[4]
FLAGS = sys.argv[5] if len(sys.argv) > 5 else ""

MODE_NAMES = ["nearest", "downward", "upward", "towardzero"]

vectors = json.load(open(VECTORS))
records = []
for v in vectors:
    typ_char = "f" if v["type"] == "float" else "d"
    fmt_char = "h" if v["grammar"] == "hex" else "g"
    for mi, mname in enumerate(MODE_NAMES):
        cmd = [HARNESS, typ_char, fmt_char, str(mi), v["input"]]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
        try:
            run = json.loads(line)
        except Exception:
            run = {"error": (p.stderr.strip() or p.stdout.strip())}
        rec = {
            "vector_id": v["vector_id"],
            "input": v["input"],
            "grammar": v["grammar"],
            "destination_type": v["type"],
            "exact_rational_input": v["rational_input"],
            "expected_bits": v["expected_bits"],
            "tie_classification": "non-tie",
            "target_label": LABEL,
            "compiler_flags": FLAGS,
            "requested_mode": mname,
            "fesetround_return": run.get("rc_set"),
            "actual_mode_before": run.get("actual_before"),
            "from_chars_ec": run.get("ec"),
            "consumed": run.get("consumed"),
            "actual_bits": run.get("bits"),
            "actual_mode_after": run.get("actual_after"),
            "success": run.get("ok"),
            "expected_match": (run.get("bits") == v["expected_bits"]) if run.get("ok") else None,
        }
        records.append(rec)
        print(v["vector_id"], mname, hex(run.get("bits",0)) if run.get("ok") else "FAIL", "match=" + str(rec["expected_match"]), flush=True)

with open(OUT, "w") as f:
    for r in records:
        f.write(json.dumps(r) + "\n")
print("total records:", len(records), flush=True)
print("written:", OUT, flush=True)
