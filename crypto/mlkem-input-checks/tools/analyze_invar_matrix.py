"""Per-cell analysis of the cross-path invariance matrix reports.

Reads the 4-cell OpenSSL invariance report, the FIPS-only report, the two OQS
auto/ref reports, and the dotnet-linux report, and produces a verdict-by-cell
matrix with per-pair divergence counts.

This is the analysis that the inline verify_invariance.py can't do because it
doesn't know about cells. We use it to emit obs-2026-0013.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
REPORTS = REPO / "crypto" / "mlkem-input-checks" / "reports"


def load_rows(name: str) -> list[dict]:
    p = REPORTS / name
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith(("META", "SUMMARY")):
            continue
        parts = line.split("|")
        if len(parts) < 5:
            continue
        # family | params | variant | seed:... | format=raw|provider=default|verdict|detail
        rec = {
            "family": parts[0],
            "params": parts[1],
            "variant": parts[2],
            "seed": parts[3],
            "format": None,
            "provider": None,
            "import": None,
            "encap": None,
            "raw": line,
        }
        for tok in parts[4:]:
            if tok.startswith("format="):
                rec["format"] = tok.split("=", 1)[1]
            elif tok.startswith("provider="):
                rec["provider"] = tok.split("=", 1)[1]
            elif tok.startswith("import-"):
                rec["import"] = tok
            elif tok.startswith("encap-"):
                rec["encap"] = tok
            elif tok == "blocked":
                rec["import"] = "blocked"
        out.append(rec)
    return out


def key4(rec):
    return (rec["family"], rec["params"], rec["variant"], rec["seed"])


def main() -> int:
    print("=" * 70)
    print("Cross-path invariance matrix - per-cell analysis")
    print("=" * 70)

    # -- OpenSSL 4-cell invariance --
    invar = load_rows("openssl_invar_report.tsv")
    if invar:
        cells = defaultdict(list)  # (format, provider) -> [rec]
        for r in invar:
            if r["format"] and r["provider"]:
                cells[(r["format"], r["provider"])].append(r)
        print(f"\nOpenSSL invariance report: {len(invar)} rows, {len(cells)} cells")
        for (fmt, prov), recs in sorted(cells.items()):
            verdicts = [r["import"] for r in recs]
            from collections import Counter
            v_counts = Counter(verdicts)
            print(f"  cell format={fmt:5s} provider={prov:7s}: rows={len(recs):4d}  verdicts={dict(v_counts)}")

        # Pairwise comparison: raw vs spki, per provider
        print("\n  Pairwise divergence (import verdict):")
        for prov in ("default", "fips"):
            raw = {key4(r): r["import"] for r in cells.get(("raw", prov), [])}
            spki = {key4(r): r["import"] for r in cells.get(("spki", prov), [])}
            common = set(raw) & set(spki)
            if not common:
                print(f"    {prov}: no common vectors")
                continue
            mismatched = [(k, raw[k], spki[k]) for k in common if raw[k] != spki[k]]
            print(f"    {prov:7s} raw vs spki: common={len(common):3d} mismatched={len(mismatched):3d}")
            for k, a, b in mismatched[:5]:
                print(f"      e.g. {k}  raw={a}  spki={b}")

        # raw default vs raw fips
        print("\n  Provider comparison (raw, import verdict):")
        for fmt in ("raw", "spki"):
            d = {key4(r): r["import"] for r in cells.get((fmt, "default"), [])}
            f = {key4(r): r["import"] for r in cells.get((fmt, "fips"), [])}
            common = set(d) & set(f)
            if not common:
                print(f"    {fmt}: no common vectors")
                continue
            fips_blocked = sum(1 for k in common if f[k] == "blocked")
            d_blocked = sum(1 for k in common if d[k] == "blocked")
            print(f"    {fmt:5s} default vs fips: common={len(common):3d}  default_blocked={d_blocked}  fips_blocked={fips_blocked}")

    # -- OQS auto vs ref --
    print("\n" + "=" * 70)
    print("liboqs auto vs forced-ref")
    print("=" * 70)
    auto = load_rows("oqs_auto_invar_report.tsv")
    ref = load_rows("oqs_ref_invar_report.tsv")
    print(f"  auto rows: {len(auto)};  ref rows: {len(ref)}")
    if auto and ref:
        # OQS rows: family|params|variant|seed|rc=0|verdict  (no format/provider)
        a_idx = {key4(r): r["import"] for r in auto}
        r_idx = {key4(r): r["import"] for r in ref}
        common = set(a_idx) & set(r_idx)
        mismatched = [k for k in common if a_idx[k] != r_idx[k]]
        print(f"  common={len(common)}  mismatched={len(mismatched)}")
        if mismatched:
            for k in mismatched[:5]:
                print(f"    e.g. {k}  auto={a_idx[k]}  ref={r_idx[k]}")

    # -- dotnet linux invariance --
    print("\n" + "=" * 70)
    print("dotnet linux invariance (Windows-CNG vs Linux-OpenSSL)")
    print("=" * 70)
    linux = load_rows("dotnet_linux_invar_report.tsv")
    print(f"  linux rows: {len(linux)}")
    if linux:
        from collections import Counter
        v_counts = Counter(r["import"] for r in linux)
        print(f"  import verdicts: {dict(v_counts)}")

    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print("Default-provider raw vs SPKI: see pairwise block above.")
    print("FIPS-provider rows: structurally blocked (fips-unavailable).")
    print("OQS auto vs ref: see block above.")
    print("dotnet linux: rows present; compare against dotnet_windows_report.tsv.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
