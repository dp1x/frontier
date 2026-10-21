import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = os.path.join(ROOT, "vectors", "vectors.jsonl")
ADAPTER = os.path.join(ROOT, "adapters", "go_asn1.exe")
RESULTS = os.path.join(ROOT, "results")
os.makedirs(RESULTS, exist_ok=True)

rows = [json.loads(l) for l in open(VECTORS, encoding="utf-8") if l.strip()]

# Build requests
reqs = []
for r in rows:
    if r["track"] == "encoder":
        req = {"id": r["id"], "mode": "encode", "type": r["type"], "value": r["value"]}
    else:
        req = {"id": r["id"], "mode": "decode", "type": r["type"], "hex": r["input_hex"]}
    reqs.append(req)

inp = "".join(json.dumps(r) + "\n" for r in reqs)
p = subprocess.run([ADAPTER], input=inp, capture_output=True, text=True, timeout=120)
if p.returncode != 0:
    print("adapter error:", p.stderr)
    sys.exit(1)
resps = {json.loads(l)["id"]: json.loads(l) for l in p.stdout.splitlines() if l.strip()}

out_rows = []
for r in rows:
    resp = resps.get(r["id"], {})
    if r["track"] == "encoder":
        got = resp.get("hex", "")
        ok = (got == r["expected_canonical_hex"]) and not resp.get("error")
        rec = {
            "id": r["id"], "track": "encoder", "type": r["type"],
            "expected": r["expected_canonical_hex"], "got": got,
            "match": ok, "error": resp.get("error", ""),
        }
    else:
        rec = {
            "id": r["id"], "track": "decoder", "type": r["type"],
            "input_hex": r["input_hex"], "expected_class": r["expected_class"],
            "accepted": resp.get("accepted", False),
            "value_repr": resp.get("value_repr", ""),
            "rest_len": resp.get("rest_len", 0),
            "error": resp.get("error", ""),
        }
    out_rows.append(rec)

with open(os.path.join(RESULTS, "matrix.jsonl"), "w", encoding="utf-8") as f:
    for rec in out_rows:
        f.write(json.dumps(rec) + "\n")

# TSV summary
with open(os.path.join(RESULTS, "matrix.tsv"), "w", encoding="utf-8") as f:
    f.write("id\ttrack\ttype\tresult\n")
    for rec in out_rows:
        if rec["track"] == "encoder":
            f.write(f"{rec['id']}\tencoder\t{rec['type']}\t{'MATCH' if rec['match'] else 'MISMATCH'}\n")
        else:
            f.write(f"{rec['id']}\tdecoder\t{rec['type']}\t{'accept' if rec['accepted'] else 'reject'}\n")

# Print summary
enc_total = sum(1 for r in out_rows if r["track"] == "encoder")
enc_match = sum(1 for r in out_rows if r["track"] == "encoder" and r["match"])
dec_total = sum(1 for r in out_rows if r["track"] == "decoder")
print(f"encoder: {enc_match}/{enc_total} match")
print(f"decoder: {dec_total} cases")
