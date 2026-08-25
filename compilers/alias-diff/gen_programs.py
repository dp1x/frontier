#!/usr/bin/env python3
"""ALIAS-DIFF program generator for msn-2026-0004 (compilers track).

Emits deterministic single-file C11 programs probing C11 6.5p6-7 effective-type
semantics across five families:

  a   memcpy type-punning          (defined behavior)
  b   union member punning         (C11 TC3 footnote 95; implementation-defined value)
  c   unsigned char* aliasing      (explicitly allowed by 6.5p7)
  d   incompatible pointer cast    (undefined behavior - expected-divergence class)
  ctl same-type control            (must never diverge)

Determinism contract:
  - No RNG module: parameters derive from splitmix64 seeded by (family, variant).
  - Same inputs -> byte-identical outputs on every run/platform.
  - Runtime values pass through an inline-asm barrier so optimizers cannot fold
    them, while staying fixed at execution time (output remains deterministic).

Oracle: every program prints two integers ("checksum nops"); any config whose
stdout sha256 differs from the gcc -O0 baseline for the same program is DIVERGENT.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path
from string import Template

FAMILIES = ["a", "b", "c", "d", "ctl"]
VARIANTS_PER_FAMILY = 10
MAX_LINES = 80

MASK64 = (1 << 64) - 1

# C float literals must carry a decimal point; ":g" would render 2.0 as "2"
# and produce the invalid token "2f".
def flit(x: float) -> str:
    s = f"{x:g}"
    return s if ("." in s or "e" in s) else s + ".0"


def splitmix64(state: int) -> tuple[int, int]:
    """One splitmix64 step: returns (next_state, output)."""
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, z ^ (z >> 31)


class Rng:
    """Tiny deterministic PRNG (splitmix64); stable across platforms."""

    def __init__(self, seed: int) -> None:
        self.state = seed & MASK64

    def next(self) -> int:
        self.state, out = splitmix64(self.state)
        return out


def derive_params(fam: str, var: int) -> dict:
    fam_idx = FAMILIES.index(fam)
    rng = Rng(seed=(fam_idx + 1) * 0xD1B54A32D192ED03 + var * 0xA0761D6478BD642F)
    sizes = [16, 20, 24, 32, 40, 48, 56, 64]
    mults = [31, 33, 131, 2654435761, 2246822519]
    rots = [5, 7, 9, 11, 13, 17]
    af = [0.5, 0.25, 1.5, 0.75, 2.0][var % 5]
    bf = [0.25, -0.5, -0.75, 0.125, -0.25][(var + fam_idx) % 5]
    return {
        "FAM": fam,
        "VAR": f"{var:02d}",
        "N": sizes[(fam_idx * 3 + var) % len(sizes)],
        "M": 8 + (var * 5 + fam_idx * 3) % 17,
        "SHAPE": "flat" if (var + fam_idx) % 2 == 0 else "nested",
        "J": str(1 + var % 3),
        "MULT": mults[(fam_idx + var) % len(mults)],
        "ROT": rots[(fam_idx * 2 + var) % len(rots)],
        # NOTE: constants feed UINT32_C(), which pastes its own suffix (glibc
        # `c ## U`); a trailing 'u' here would form an invalid literal.
        "SEEDX": f"0x{rng.next() & 0xFFFFFFFF:08x}",
        "K0": f"0x{rng.next() & 0xFFFFFFFF:08x}",
        "C1": f"0x{(rng.next() | 1) & 0x00FFFFFF:06x}",
        "C2": f"0x{(rng.next() % 61) + 1:02x}",
        "AF": flit(af),
        "BF": flit(bf),
        "KD": f"0x{rng.next() & 0xFFFFFFFF:08x}",
        "KC": f"0x{rng.next() & 0xFFFFFFFF:08x}",
        "KM": f"0x{rng.next() & 0xFFFFFFFF:08x}",
        "KE": f"0x{(rng.next() | 1) & 0xFFFFFFFF:08x}",
    }


PROLOGUE = Template("""\
/* ALIAS-DIFF msn-2026-0004 family=$FAM variant=$VAR seed=$SEEDX */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define N ((size_t)$N)
#define M ($M)

static volatile uint32_t g_sink;

/* Value barrier: constant at runtime, unknowable at compile time. */
static uint32_t opaque(uint32_t x) {
    __asm__ volatile("" : "+r"(x));
    return x;
}

/* Memory barrier: invisible side effects force reloads across the call. */
static void touch(volatile void *p) {
    __asm__ volatile("" : : "r"(p) : "memory");
}

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

MAIN_OPEN = Template("""\
int main(void) {
    uint32_t acc = UINT32_C($SEEDX), nops = 0, i, k, j, idx;
$DECLS
    for (i = 0; i < N; i++) {
        acc = mix(acc, opaque(UINT32_C($K0)) + i);
$FILL
    }
$INIT""")

IDX_LINE = Template("        idx = opaque(UINT32_C($C1) * (nops + 1u)) % N;\n")

LOOP_BODY = {
    "a": Template("""\
        uint32_t b = bits[(idx + UINT32_C($C2)) % N];
        float f, g;
        memcpy(&f, &b, sizeof f);
        touch(&b);
        g_sink ^= bits[idx];
        g = f * ${AF}f + ${BF}f;
        acc = mix(acc, fbits(g));
        acc = mix(acc, (uint32_t)((g > 0.25f) | ((g < -0.25f) << 1)));
        bits[idx] = b ^ acc;"""),
    "b": Template("""\
        union uf un;
        un.u = bits[(idx + UINT32_C($C2)) % N];
        touch(&un.u);
        g_sink ^= un.u;
        acc = mix(acc, fbits(un.f * ${AF}f + ${BF}f));
        bits[idx] = un.u ^ acc;"""),
    "c": Template("""\
        size_t byt = (size_t)(opaque(UINT32_C($C2)) % 4);
        cp[4u * idx + byt] = (unsigned char)(acc >> (8u * byt));
        touch(cp);
        g_sink ^= cp[4u * idx + byt];
        acc = mix(acc, arr[idx] ^ UINT32_C($KM));"""),
    "d": Template("""\
        uint32_t *pp = (uint32_t *)&probe;
        touch(&fa[idx]);
        *(uint32_t *)&fa[idx] = acc ^ UINT32_C($KD);
        *pp = acc ^ UINT32_C($KE);
        acc = mix(acc, fbits(probe));
        acc = mix(acc, fbits(fa[idx] * ${AF}f + ${BF}f));"""),
    "ctl": Template("""\
        uint32_t nb = (idx + 1u) % N, t;
        float fv;
        arr[idx] = acc ^ UINT32_C($KC);
        t = arr[nb] | UINT32_C(1);
        touch(&arr[idx]);
        g_sink ^= arr[nb];
        acc = mix(acc, arr[idx] ^ arr[nb]);
        memcpy(&fv, &t, sizeof fv);
        fa[idx] = fv;
        acc = mix(acc, fbits(fa[idx]));"""),
}

DECLS_FILL = {
    "a": ("    uint32_t bits[N];\n",
          "        bits[i] = acc;\n",
          ""),
    "b": ("    uint32_t bits[N];\n    union uf { uint32_t u; float f; };\n",
          "        bits[i] = acc;\n",
          ""),
    "c": ("    uint32_t arr[N];\n    unsigned char *cp = (unsigned char *)arr;\n",
          "        arr[i] = acc;\n",
          ""),
    # Scalar probe exists so the optimizer KNOWS *(uint32_t*)&probe and probe
    # denote the same storage - the precondition for TBAA value forwarding.
    "d": ("    float fa[N], probe;\n",
          "        uint32_t t = acc | UINT32_C(1);\n        memcpy(&fa[i], &t, sizeof t);\n",
          "    {\n"
          "        uint32_t t0 = acc | UINT32_C(1);\n"
          "        memcpy(&probe, &t0, sizeof t0);\n"
          "    }\n"),
    "ctl": ("    uint32_t arr[N];\n    float fa[N];\n",
            "        arr[i] = acc;\n        fa[i] = 0.0f;\n",
            ""),
}

FLAT_OPEN = "    for (k = 0; k < M; k++) {\n"
NESTED_OPEN = Template(
    "    for (k = 0; k < M; k++) {\n"
    "        for (j = 0; j < opaque((uint32_t)$J); j++) {\n"
)
FLAT_CLOSE = "    }\n"
NESTED_CLOSE = "        }\n    }\n"


def render(fam: str, var: int) -> str:
    p = derive_params(fam, var)
    parts = [PROLOGUE.substitute(p)]
    decls, fill, init = DECLS_FILL[fam]
    parts.append(MAIN_OPEN.substitute(dict(
        p, DECLS=decls.rstrip("\n"), FILL=fill.rstrip("\n"), INIT=init)))
    body = IDX_LINE.substitute(p) + LOOP_BODY[fam].substitute(p) + "\n        nops++;\n"
    if p["SHAPE"] == "nested":
        parts.append(NESTED_OPEN.substitute(p))
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
    written: list[Path] = []
    seen_hashes: set[str] = set()
    for fam in FAMILIES:
        for var in range(1, VARIANTS_PER_FAMILY + 1):
            text = render(fam, var)
            n_lines = text.count("\n")
            if n_lines > MAX_LINES:
                raise SystemExit(
                    f"template overflow: {fam}-{var:02d}.c has {n_lines} lines (max {MAX_LINES})"
                )
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest in seen_hashes:
                raise SystemExit(f"duplicate program content for {fam}-{var:02d}")
            seen_hashes.add(digest)
            # A digit run starting a token and followed by 'f' means an
            # integer constant got an FP suffix (e.g. "2f"); reject loudly.
            if re.search(r"(?<![.\w])\d+f\b", text):
                raise SystemExit(f"invalid float literal in {fam}-{var:02d}")
            path = outdir / f"{fam}-{var:02d}.c"
            path.write_text(text, encoding="ascii")
            written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Emit ALIAS-DIFF differential programs")
    ap.add_argument("outdir")
    args = ap.parse_args(argv)
    paths = emit(Path(args.outdir))
    max_lines = max(p.read_text(encoding="ascii").count("\n") for p in paths)
    print(f"EMITTED|total={len(paths)}|per_family={VARIANTS_PER_FAMILY}|max_lines={max_lines}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
