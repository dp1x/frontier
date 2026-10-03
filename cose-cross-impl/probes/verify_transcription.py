"""Verify every hex string transcribed into exp-2026-0034 / obs-2026-0046
matches the raw probe output. Guards against transcription errors.

Read-only. Exits non-zero on any mismatch.
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(r"C:\Users\Dhane\frontier")
OUT_FILES = [
    REPO / "cose-cross-impl" / "probes" / "probe_pycose_scope_gaps_output.json",
    REPO / "cose-cross-impl" / "probes" / "probe_ordering_discriminator_output.json",
]

raw_hex = set()


def walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{8,}", v):
                raw_hex.add(v)
            walk(v)
    elif isinstance(o, list):
        for v in o:
            walk(v)


for _f in OUT_FILES:
    walk(json.loads(_f.read_text()))

# Hex strings asserted in the artifacts that should come from the probe.
asserted = {
    "a40281637a7a7a636d6d6d0704496b69642d627974657363717171f5": "mixed forward (bare)",
    "a40281637a7a7a04496b69642d6279746573636d6d6d0763717171f5": "mixed canonical",
    "a463717171f504496b69642d6279746573636d6d6d070281637a7a7a": "mixed reversed (bare)",
    "a2044179031832": "int descending",
    "a2031832044179": "int canonical",
    "a2031832044179": "int ascending",
    "a56161016261610261620362616204617a05": "tstr unregistered pycose",
    "a5616101616203617a056261610262616204": "tstr unregistered canonical",
    "a204416b615a01": "tstr registered names pycose",
    "a2615a01634b4944416b": "tstr registered names canonical",
    "a3044179636d6d6d07031832": "unprotected mixed",
    "a3031832044179636d6d6d07": "unprotected mixed canonical",
}

bad = {h: label for h, label in asserted.items() if h not in raw_hex}
for h, label in asserted.items():
    print(("OK   " if h in raw_hex else "MISS "), label, h)

# Also check every long hex literal inside the two artifacts.
for art in ["knowledge/experiments/exp-2026-0034.yaml", "knowledge/observations/obs-2026-0046.yaml"]:
    text = (REPO / art).read_text()
    found = set(re.findall(r'"([0-9a-f]{10,})"', text))
    for h in sorted(found):
        if h not in raw_hex:
            print(f"NOT-IN-PROBE-OUTPUT {art}: {h}")
            bad[h] = art

print()
if bad:
    print("RESULT: MISMATCH")
    for h, label in bad.items():
        print("  ", label, h)
    sys.exit(1)
print("RESULT: all transcribed hex strings match the probe output")