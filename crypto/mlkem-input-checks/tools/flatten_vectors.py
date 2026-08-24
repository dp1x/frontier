"""Flatten the stimuli manifest into per-library TSV files for C harnesses.

Line format: <family>|<params>|<expected_7_2>|<source>|<ek_hex>
Deterministic order = manifest order.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    doc = json.loads(src.read_text(encoding="utf-8"))
    lines = [
        f"{v['family']}|{v['params']}|{v['expected_7_2']}|{v['source']}|{v['ek_hex']}"
        for v in doc["vectors"]
    ]
    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} lines to {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
