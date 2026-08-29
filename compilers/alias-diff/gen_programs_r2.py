#!/usr/bin/env python3
"""ALIAS-DIFF round-2 program generator for msn-2026-0004 (compilers track).

Round-2 extends round-1 with an opaque-TU barrier: programs that call into
a separately-compiled translation unit (`opaque_tu.c`) so the optimizer
cannot fold the aliasing edge through the call.

Two output trees are emitted:
  <outdir>/asm/<fam>-<var>.c       - the round-1 program (inline-asm barrier)
  <outdir>/opaque-tu/<fam>-<var>.c - the round-2 program (opaque-TU barrier)

Round-2 is targeted at family (d) only, where the aliasing edge under test
is a scalar probe through a cast pointer.  Family (ctl) is run as a positive
control.  Other families are not round-2'd because round-1 already showed
they do not produce a divergent result; including them would inflate the
matrix without narrowing the search.

Determinism contract:
  - Same inputs -> byte-identical outputs on every run/platform.
  - Programs are non-RNG; parameters derive from splitmix64 seeded by
    (family, variant).
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from string import Template

# Reuse round-1 parameter derivation so the asm and opaque-tu variants
# are sibling programs with the same byte payload.
sys.path.insert(0, str(Path(__file__).parent))
from gen_programs import (
    derive_params,
    FAMILIES,
    VARIANTS_PER_FAMILY,
    DECLS_FILL,
    FLAT_OPEN,
    NESTED_OPEN,
    FLAT_CLOSE,
    NESTED_CLOSE,
    IDX_LINE,
    MAX_LINES,
    MASK64,
)

OPAQUE_TU_PROLOGUE = Template("""\
/* ALIAS-DIFF round-2 msn-2026-0004 family=$FAM variant=$VAR seed=$SEEDX barrier=opaque-tu */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "opaque_tu.h"

#define N ((size_t)$N)
#define M ($M)

static volatile uint32_t g_sink;

static uint32_t mix(uint32_t h, uint32_t x) {
    h ^= x;
    h *= UINT32_C($MULT);
    h = (h << $ROT) | (h >> (32 - $ROT));
    return h;
}

static uint32_t fbits(float f) {
    uint32_t u;
    memcpy(&u, &f, sizeof u);
    return u;
}
""")

OPAQUE_TU_MAIN_OPEN = Template("""\
int main(void) {
    uint32_t acc = UINT32_C($SEEDX), nops = 0, i, k, j, idx;
$DECLS
    for (i = 0; i < N; i++) {
        acc = mix(acc, opaque_ext(UINT32_C($K0)) + i);
$FILL
    }
$INIT""")

# Family (d) loop body with opaque-TU barriers: every `opaque(...)` in
# round-1 becomes `opaque_ext(...)` and every `touch(...)` becomes
# `touch_ext(...)`.  All other loop bodies are the same as round-1.
LOOP_BODY_OPAQUE_TU = {
    "a": Template("""\
        uint32_t b = bits[(idx + UINT32_C($C2)) % N];
        float f, g;
        memcpy(&f, &b, sizeof f);
        touch_ext(&b);
        g_sink ^= bits[idx];
        g = f * ${AF}f + ${BF}f;
        acc = mix(acc, fbits(g));
        acc = mix(acc, (uint32_t)((g > 0.25f) | ((g < -0.25f) << 1)));
        bits[idx] = b ^ acc;"""),
    "b": Template("""\
        union uf un;
        un.u = bits[(idx + UINT32_C($C2)) % N];
        touch_ext(&un.u);
        g_sink ^= un.u;
        acc = mix(acc, fbits(un.f * ${AF}f + ${BF}f));
        bits[idx] = un.u ^ acc;"""),
    "c": Template("""\
        size_t byt = (size_t)(opaque_ext(UINT32_C($C2)) % 4);
        cp[4u * idx + byt] = (unsigned char)(acc >> (8u * byt));
        touch_ext(cp);
        g_sink ^= cp[4u * idx + byt];
        acc = mix(acc, arr[idx] ^ UINT32_C($KM));"""),
    "d": Template("""\
        uint32_t *pp = (uint32_t *)&probe;
        touch_ext(&fa[idx]);
        *(uint32_t *)&fa[idx] = acc ^ UINT32_C($KD);
        *pp = acc ^ UINT32_C($KE);
        acc = mix(acc, fbits(probe));
        acc = mix(acc, fbits(fa[idx] * ${AF}f + ${BF}f));"""),
    "ctl": Template("""\
        uint32_t nb = (idx + 1u) % N, t;
        float fv;
        arr[idx] = acc ^ UINT32_C($KC);
        t = arr[nb] | UINT32_C(1);
        touch_ext(&arr[idx]);
        g_sink ^= arr[nb];
        acc = mix(acc, arr[idx] ^ arr[nb]);
        memcpy(&fv, &t, sizeof fv);
        fa[idx] = fv;
        acc = mix(acc, fbits(fa[idx]));"""),
}

# Round-2 only targets family (d) and (ctl) per exp-2026-0015.
ROUND2_FAMILIES = ["d", "ctl"]


def render_opaque_tu(fam: str, var: int) -> str:
    p = derive_params(fam, var)
    parts = [OPAQUE_TU_PROLOGUE.substitute(p)]
    decls, fill, init = DECLS_FILL[fam]
    parts.append(OPAQUE_TU_MAIN_OPEN.substitute(dict(
        p, DECLS=decls.rstrip("\n"), FILL=fill.rstrip("\n"), INIT=init)))
    # The IDX_LINE and NESTED_OPEN templates use `opaque(...)`; we need
    # `opaque_ext(...)` so the round-2 programs link against the opaque TU.
    idx_line = IDX_LINE.substitute(p).replace("opaque(", "opaque_ext(")
    body = idx_line + LOOP_BODY_OPAQUE_TU[fam].substitute(p) + "\n        nops++;\n"
    if p["SHAPE"] == "nested":
        nested_open = NESTED_OPEN.substitute(p).replace("opaque(", "opaque_ext(")
        parts.append(nested_open)
        parts.append("".join("    " + ln if ln.strip() else ln for ln in body.splitlines(keepends=True)))
        parts.append(NESTED_CLOSE)
    else:
        parts.append(FLAT_OPEN)
        parts.append(body)
        parts.append(FLAT_CLOSE)
    parts.append(
        '    printf("%08x %08x\\n", (unsigned)mix(acc, nops), (unsigned)nops);\n'
        "    g_sink ^= acc;\n"
        "    return 0;\n"
        "}\n"
    )
    return "".join(parts)


def emit(outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    opaque_dir = outdir / "opaque-tu"
    opaque_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    seen_hashes: set[str] = set()
    # Generate opaque-tu variants for round-2 target families.
    for fam in ROUND2_FAMILIES:
        for var in range(1, VARIANTS_PER_FAMILY + 1):
            text = render_opaque_tu(fam, var)
            n_lines = text.count("\n")
            if n_lines > MAX_LINES:
                raise SystemExit(
                    f"template overflow: {fam}-{var:02d}.c has {n_lines} lines (max {MAX_LINES})"
                )
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest in seen_hashes:
                raise SystemExit(f"duplicate program content for {fam}-{var:02d}")
            seen_hashes.add(digest)
            if re.search(r"(?<![.\w])\d+f\b", text):
                raise SystemExit(f"invalid float literal in {fam}-{var:02d}")
            path = opaque_dir / f"{fam}-{var:02d}.c"
            path.write_text(text, encoding="ascii")
            written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Emit ALIAS-DIFF round-2 opaque-tu programs")
    ap.add_argument("outdir")
    args = ap.parse_args(argv)
    paths = emit(Path(args.outdir))
    max_lines = max(p.read_text(encoding="ascii").count("\n") for p in paths)
    print(f"EMITTED|round=2|total={len(paths)}|families={','.join(ROUND2_FAMILIES)}|max_lines={max_lines}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
