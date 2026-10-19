"""Deterministic vector generator for strict UTF-8 validation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "oracle"))
from utf8_oracle import is_valid_utf8

OUT = Path(__file__).resolve().parent / "vectors.jsonl"


def enc(cp: int) -> bytes:
    return chr(cp).encode("utf-8")


BOUNDARY_SCALARS = [
    0x0000, 0x007F, 0x0080, 0x07FF, 0x0800, 0x0FFF, 0x1000, 0xCFFF,
    0xD000, 0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x3FFFF, 0x40000, 0xFFFFF,
    0x100000, 0x10FFFF,
]


def main() -> None:
    seen: set[str] = set()
    rows: list[dict] = []

    def add(b: bytes, category: str, note: str = "") -> None:
        hx = b.hex()
        if hx in seen:
            return
        seen.add(hx)
        rows.append({
            "id": f"v{len(rows):04d}",
            "bytes_hex": hx,
            "expected": bool(is_valid_utf8(b)),
            "category": category,
            "note": note,
        })

    # Empty
    add(b"", "empty", "empty sequence is valid")

    # Valid scalars at boundaries
    for cp in BOUNDARY_SCALARS:
        add(enc(cp), "valid_scalar", f"U+{cp:04X}")

    # U+FFFD positive control
    add(b"\xef\xbf\xbd", "positive_control", "valid encoding of U+FFFD")

    # BOM
    add(b"\xef\xbb\xbf", "valid_scalar", "BOM U+FEFF")

    # Overlong encodings (2/3/4 byte)
    overlongs = [
        bytes([0xC0, 0x80]),  # U+0000 overlong 2
        bytes([0xC1, 0xBF]),  # U+007F overlong 2
        bytes([0xE0, 0x80, 0x80]),  # U+0000 overlong 3
        bytes([0xE0, 0x9F, 0xBF]),  # U+07FF overlong 3
        bytes([0xF0, 0x80, 0x80, 0x80]),  # overlong 4
        bytes([0xF0, 0x8F, 0xBF, 0xBF]),  # U+FFFF overlong 4
    ]
    for b in overlongs:
        add(b, "overlong", b.hex())

    # Surrogate encodings
    surrogates = [
        bytes([0xED, 0xA0, 0x80]),  # U+D800
        bytes([0xED, 0xBF, 0xBF]),  # U+DFFF
        bytes([0xED, 0xAD, 0x80]),  # mid surrogate
    ]
    for b in surrogates:
        add(b, "surrogate", b.hex())

    # Above U+10FFFF
    above = [
        bytes([0xF4, 0x90, 0x80, 0x80]),  # U+110000
        bytes([0xF5, 0x80, 0x80, 0x80]),
        bytes([0xF7, 0xBF, 0xBF, 0xBF]),
        bytes([0xFB, 0xBF, 0xBF, 0xBF, 0xBF]),
        bytes([0xFF]),
    ]
    for b in above:
        add(b, "above_max", b.hex())

    # Invalid starters as standalone single bytes handled by single_byte category
    # Truncated sequences
    seeds = [enc(0x0080), enc(0x0800), enc(0x10000), enc(0x10FFFF)]
    for s in seeds:
        for k in range(1, len(s)):
            add(s[:k], "truncated", s.hex())

    # Bad continuations
    bad_cont = [
        bytes([0xC2, 0x41]),
        bytes([0xE0, 0xA0, 0x41]),
        bytes([0xF0, 0x90, 0x80, 0x41]),
        bytes([0xC2, 0xC2]),
    ]
    for b in bad_cont:
        add(b, "bad_continuation", b.hex())

    # Single-byte all values
    for v in range(256):
        add(bytes([v]), "single_byte", f"0x{v:02X}")

    # Targeted mutations: mutate each byte of representative sequences
    reps = [enc(0x10FFFF), enc(0x0080), enc(0x0800), b"\xef\xbf\xbd", enc(0xD7FF)]
    mutation_values = [0x00, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF,
                      0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xEC, 0xED, 0xEE,
                      0xEF, 0xF0, 0xF3, 0xF4, 0xF5, 0xFF]
    for rep in reps:
        ba = bytearray(rep)
        for pos in range(len(ba)):
            orig = ba[pos]
            for mv in mutation_values:
                if mv == orig:
                    continue
                ba[pos] = mv
                add(bytes(ba), "mutation", f"mut {rep.hex()} pos{pos} -> {mv:02X}")
            ba[pos] = orig

    # Concatenations of valid scalars
    add(enc(0x0041) + enc(0x0000) + enc(0x10FFFF), "concat", "mixed valid")

    # Write
    with OUT.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} vectors to {OUT}")


if __name__ == "__main__":
    main()
