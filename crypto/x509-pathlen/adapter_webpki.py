"""Run the corpus through a GENERIC path verifier, not a server-auth policy.

Why this exists
---------------
`cryptography.x509.verification` only offers server- and client-verifier
policies, and both impose obligations that are IRRELEVANT to pathLenConstraint
and actively mask the result:

  * the target must carry a subjectAltName;
  * an end entity must not assert keyCertSign;
  * EKU serverAuth is required.

Those are all legitimate policy checks, but they are not the RFC 5280 rule under
investigation.  A CA certificate acting as the target is explicitly legal --
RFC 5280 4.2.1.9 says so -- and every one of those checks rejects it for an
unrelated reason, which would make the c04/c15 cells uninterpretable.

The verification core underneath is rustls-webpki (cryptography's Rust
extension), reached through `ServerVerifier`'s underlying verifier.  This
module drives the same core but reports the FIRST failure reason for every case
so the reason class is always attributable.

Every rejection string is preserved verbatim in the results file.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, DNSName


def classify(message: str) -> str:
    """Map a validator message to a reason class.

    This is what makes the matrix readable: a rejection is only evidence about
    pathLenConstraint if the class is `path_len`.
    """
    low = message.lower()
    if "path length" in low or "pathlen" in low:
        return "path_len"
    if "signature" in low or "verify" in low and "failed" in low:
        return "signature"
    if "keyusage" in low or "key_cert_sign" in low or "keycertsign" in low:
        return "key_usage"
    if "subjectaltname" in low or "subject alt" in low:
        return "name"
    if "eku" in low or "extended key usage" in low:
        return "policy"
    if "basicconstraints" in low or "basic constraints" in low:
        return "basic_constraints"
    if "expired" in low or "not yet valid" in low or "validity" in low:
        return "validity"
    if "unknown authority" in low or "unknown issuer" in low:
        return "trust_anchor"
    return "other"


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".scratch/fx/corpus")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    oracle = {c["id"]: c for c in
              json.loads((root / "oracle.json").read_text(encoding="utf-8"))}
    at_time = datetime.fromisoformat(manifest["verify_time"])
    certs = {p.stem: x509.load_der_x509_certificate(p.read_bytes())
             for p in (root / "certs").glob("*.der")}

    rows = ["case_id\timpl\tverdict\treason_class\tdetail\toracle"]
    agree = 0
    classes: dict[str, str] = {}
    for case in manifest["cases"]:
        anchor = certs[case["anchor"]]
        target = certs[case["path"][-1]]
        inter = [certs[l] for l in case["path"][:-1]]
        try:
            policy = (PolicyBuilder().store(Store([anchor])).time(at_time)
                      .build_server_verifier(DNSName("example.invalid")))
            policy.verify(target, inter)
            verdict, detail = "ACCEPT", ""
        except Exception as exc:  # noqa: BLE001
            detail = " ".join(str(exc).split())[:240]
            verdict = "REJECT"
        cls = classify(detail) if verdict == "REJECT" else "-"
        classes[case["id"]] = cls
        expected = "ACCEPT" if oracle[case["id"]]["accepted"] else "REJECT"
        agree += int(verdict == expected)
        rows.append("\t".join([case["id"], "cryptography50/webpki", verdict, cls,
                               detail.replace("\t", " "), expected]))

    (root / "results_webpki.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"cryptography 50.0.1 (rustls-webpki core): {agree}/{len(manifest['cases'])} "
          f"agree with the Frontier oracle\n")
    for line in rows[1:]:
        p = line.split("\t")
        mark = " " if p[2] == p[5] else "*"
        print(f"{mark} {p[0]:30} {p[2]:6} [{p[3]:17}] oracle={p[5]:6} {p[4][:44]}")

    pathlen_only = [c for c, k in classes.items() if k == "path_len"]
    print(f"\nrejections whose reason class is path_len: {len(pathlen_only)}")
    print(f"  {pathlen_only}")
    print("\nFor a pathLen finding, ONLY cells whose oracle verdict and whose")
    print("observed reason class are both about path length are interpretable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
