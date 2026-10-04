"""Lint every artifact YAML for parse errors, with a located message.

`frontier validate` reports a malformed artifact as a dangling reference,
which points at the wrong thing: the ID never becomes visible, so every
artifact linking it is reported as broken. Parsing first gives the real error
and the real line.

Writes nothing and changes nothing; a non-zero exit means at least one artifact
does not parse.
"""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DIRS = ["knowledge", "missions", "formal"]

failures = []
count = 0

for d in DIRS:
    base = ROOT / d
    if not base.is_dir():
        continue
    for path in sorted(base.rglob("*.yaml")):
        rel = path.relative_to(ROOT)
        if rel.parts and rel.parts[0] == "knowledge" and rel.parts[1:2] in (("indices",), ("notes",)):
            continue
        count += 1
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:
            failures.append((rel, str(exc).replace("\n", " ")))
            continue
        if not isinstance(doc, dict):
            failures.append((rel, f"top level is {type(doc).__name__}, not a mapping"))
            continue
        for key in ("id", "type", "status", "created_at", "updated_at",
                    "summary", "epistemic_status", "provenance", "links"):
            if key not in doc:
                failures.append((rel, f"missing required field {key!r}"))

print(f"scanned {count} artifact file(s) under {', '.join(DIRS)}")
if failures:
    print(f"\n{len(failures)} problem(s):")
    for rel, msg in failures:
        print(f"  {rel}\n      {msg}")
    sys.exit(1)
print("all artifacts parse and carry the required envelope fields")
