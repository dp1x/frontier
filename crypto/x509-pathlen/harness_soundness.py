"""Harness soundness check: is the corpus usable as a pathLen experiment?

The corpus is only informative about pathLenConstraint if every case that the
Frontier oracle says should be ACCEPTED is actually accepted by a real
validator for reasons UNRELATED to path length.  This module runs one real
validator (pyca/cryptography, which delegates to the platform libcrypto) over
the whole corpus and reports:

  * cases where a real validator rejects an oracle-ACCEPT case -- a confounder,
    because whatever it objected to masks the pathLen signal for every case;
  * cases where it rejects an oracle-REJECT case for a reason that is NOT
    path length -- an uninterpretable cell, since the rejection would have
    happened anyway;
  * the discriminating pairs, which must actually differ.

Both failure classes were observed during construction (a missing SAN, then a
spurious AuthorityKeyIdentifier), which is why this is a first-class check and
not an afterthought.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, DNSName


def load(certs: Path, label: str) -> x509.Certificate:
    return x509.load_der_x509_certificate((certs / f"{label}.der").read_bytes())


def verify(anchor, target, inter, at_time) -> tuple[str, str]:
    try:
        policy = (PolicyBuilder().store(Store([anchor])).time(at_time)
                  .build_server_verifier(DNSName("example.invalid")))
        policy.verify(target, inter)
        return "ACCEPT", ""
    except Exception as exc:  # noqa: BLE001 - surface the message verbatim
        return "REJECT", " ".join(str(exc).split())[:200]


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".scratch/fx/corpus")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    oracle = {c["id"]: c for c in
              json.loads((root / "oracle.json").read_text(encoding="utf-8"))}
    at_time = datetime.fromisoformat(manifest["verify_time"])

    verdicts: dict[str, str] = {}
    details: dict[str, str] = {}
    for case in manifest["cases"]:
        anchor = load(root / "certs", case["anchor"])
        target = load(root / "certs", case["path"][-1])
        inter = [load(root / "certs", lbl) for lbl in case["path"][:-1]]
        v, d = verify(anchor, target, inter, at_time)
        verdicts[case["id"]] = v
        details[case["id"]] = d

    confounders, uninterpretable = [], []
    for case in manifest["cases"]:
        cid = case["id"]
        expect_accept = oracle[cid]["accepted"]
        if verdicts[cid] == "REJECT" and expect_accept:
            confounders.append((cid, details[cid]))
        elif verdicts[cid] == "REJECT" and not expect_accept:
            uninterpretable.append((cid, details[cid]))

    pairs = [("c10_pair1_nonself", "c11_pair1_selfissued"),
             ("c12_pair2_nonself", "c13_pair2_selfissued")]
    print(f"cases: {len(manifest['cases'])}")
    print(f"oracle ACCEPT / REJECT: "
          f"{sum(1 for c in oracle.values() if c['accepted'])} / "
          f"{sum(1 for c in oracle.values() if not c['accepted'])}")
    print(f"libcrypto ACCEPT / REJECT: "
          f"{sum(1 for v in verdicts.values() if v == 'ACCEPT')} / "
          f"{sum(1 for v in verdicts.values() if v == 'REJECT')}")

    print(f"\nCONFOUNDERS (oracle says ACCEPT, real validator rejects): {len(confounders)}")
    for cid, detail in confounders:
        print(f"  ! {cid}: {detail}")
    print(f"\nUNINTERPRETABLE (oracle says REJECT, but for another reason): "
          f"{len(uninterpretable)}")
    for cid, detail in uninterpretable:
        print(f"  ? {cid}: {detail}")

    print("\nDISCRIMINATING PAIRS (must differ under a real validator):")
    pair_ok = True
    for a, b in pairs:
        differs = verdicts[a] != verdicts[b]
        pair_ok &= differs
        print(f"  {a}={verdicts[a]:6} {b}={verdicts[b]:6} "
              f"{'DIFFERS (discriminates)' if differs else 'IDENTICAL (does not discriminate)'}")

    (root / "harness_soundness.json").write_text(json.dumps({
        "verdicts": verdicts,
        "details": details,
        "confounders": [c for c, _ in confounders],
        "uninterpretable": [c for c, _ in uninterpretable],
        "pairs_discriminate": pair_ok,
    }, indent=2), encoding="utf-8")

    clean = not confounders and pair_ok
    print(f"\nHARNESS SOUND: {clean}")
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
