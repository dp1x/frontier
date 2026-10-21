import json, subprocess, sys

REPRO = sys.argv[1]
VECTOR_FILES = sys.argv[2].split(",")
OUT = sys.argv[3]
MODE_NAMES = ["nearest", "downward", "upward", "towardzero"]

vectors = []
for vf in VECTOR_FILES:
    vectors.extend(json.load(open(vf)))

records = []
for v in vectors:
    typ_char = "f" if v["type"] == "float" else "d"
    for mi, mname in enumerate(MODE_NAMES):
        p = subprocess.run([REPRO, typ_char, str(mi), v["input"]],
                           capture_output=True, text=True, timeout=30)
        line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
        try:
            run = json.loads(line)
        except Exception:
            run = {"error": (p.stderr.strip() or p.stdout.strip())}
        rec = {
            "vector_id": v["vector_id"],
            "input": v["input"],
            "destination_type": v["type"],
            "requested_mode": mname,
            "clinger_eligible": run.get("clinger_eligible"),
            "clinger_bits": run.get("clinger_bits"),
            "expected_bits": v["expected_bits"],
            "parsed_mantissa": run.get("parsed_mantissa"),
            "parsed_exponent": run.get("parsed_exponent"),
            "truncated": run.get("truncated"),
        }
        records.append(rec)
        print(v["vector_id"], mname, "elig=", run.get("clinger_eligible"),
              "bits=", hex(run.get("clinger_bits", 0)) if run.get("clinger_bits") is not None else None,
              "exp=", hex(v["expected_bits"]), flush=True)

with open(OUT, "w") as f:
    for r in records:
        f.write(json.dumps(r) + "\n")
print("total records:", len(records), flush=True)
