"""Deterministic verification for fnd-2026-0001 (msn-2026-0001).

Re-derives the headline verdicts directly from the committed raw report files
and cross-checks them against the counts recorded in the knowledge
observations. Exit code 0 + 'PASS' iff every check holds.

Method: deterministic-script (frontier.promotion VERIFICATION_METHODS).
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
REPORTS = REPO / "crypto" / "mlkem-input-checks" / "reports"


def load(name: str) -> list[str]:
    return (REPORTS / name).read_text(encoding="utf-8").splitlines()


def col(line: str, i: int) -> str:
    return line.split("|")[i]


def main() -> int:
    checks: list[tuple[str, bool]] = []

    # --- PQClean: accepts every callable vector, wrong-length inexpressible.
    pq = [l for l in load("pqclean_x64_report.tsv") if "|" in l]
    verdicts = Counter(col(l, 5) for l in pq if not l.startswith("SUMMARY"))
    checks.append((
        "PQClean: all 190 callable vectors accepted, 0 surprises, "
        "9 inexpressible-at-api",
        verdicts.get("accepted") == 190 and verdicts.get("inexpressible-at-api") == 9,
    ))

    # --- Cross-architecture gate: identical tables.
    x64 = load("pqclean_x64_report.tsv")
    a64 = load("pqclean_arm64_report.tsv")
    checks.append(("Control: x64-emulated table == arm64-native table", x64 == a64))

    # --- liboqs: rejects exactly the non-canonical families everywhere.
    oqs = [l for l in load("oqs_runner_report.tsv") if not l.startswith(("META", "SUMMARY"))]
    oqs_by_family: dict[str, set[str]] = {}
    for l in oqs:
        fam, verdict = col(l, 0), col(l, 5)
        oqs_by_family.setdefault(fam, set()).add(verdict)
    reject_families = {f for f, v in oqs_by_family.items() if v == {"rejected"}}
    accept_families = {f for f, v in oqs_by_family.items() if v == {"accepted"}}
    expected_reject = {"wycheproof-modoverflow"} | {
        f"noncanon-{v}-{p}" for v in ("q3329", "v4000", "max4095")
        for p in ("first", "middle", "last")
    } | {"congruent-plant"}
    expected_accept = {"valid-control"} | {f"rho-{t}" for t in ("zero", "ff", "prng-a", "prng-b")}
    checks.append((
        "liboqs: rejection set == all non-canonical families; acceptance set == valid+rho",
        reject_families == expected_reject and accept_families == expected_accept,
    ))
    # Parameter-set uniformity: each family has identical verdicts across k=2/3/4.
    per_family_params: dict[tuple[str, str], str] = {}
    for l in oqs:
        per_family_params[(col(l, 0), col(l, 1))] = col(l, 5)
    uniform = True
    for fam in expected_reject | expected_accept:
        verdict_set = {per_family_params.get((fam, p)) for p in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")}
        if None in verdict_set or len(verdict_set) != 1:
            uniform = False
            break
    checks.append(("liboqs: parameter-set uniformity (k=2/3/4 identical)", uniform))

    # --- Go: length-class vs modulus-class error separation.
    go = [l for l in load("go_runner_report.tsv") if not l.startswith("SUMMARY")]
    go_len = sum(1 for l in go if "invalid encapsulation key length" in l)
    go_mod = sum(1 for l in go if "invalid polynomial encoding" in l)
    go_acc = sum(1 for l in go if col(l, 4) == "rc=0")
    checks.append((
        "Go: 58 modulus rejections, 5 length rejections, 72 accepted",
        go_mod == 58 and go_len == 5 and go_acc == 72,
    ))

    # --- Rust: all malformed import-rejected, all canonical accepted.
    rust = [l for l in load("rust_runner_report.tsv") if not l.startswith("SUMMARY")]
    rust_rej = sum(1 for l in rust if "import-rejected" in l)
    rust_acc = sum(1 for l in rust if "|rc=0|accepted" in l)
    checks.append((
        "Rust: 91 import-rejected (incl. wrong-length), 108 accepted",
        rust_rej == 91 and rust_acc == 108,
    ))

    # --- Congruent differential: ct differs AND both secrets diverge from peer.
    cong = [l for l in load("congruent_diff_report.tsv") if "planted=" in l and "accepted" in l]
    cong_ok = all(
        "ct_eq=0" in l and "ss_sender==peer:0" in l and "ss_canon==peer:0" in l
        for l in cong
    ) and len(cong) >= 8
    checks.append((f"Congruent-plant: {len(cong)} rows, ct differs, peer decap fails closed", cong_ok))

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}: {name}")
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    if failed:
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
