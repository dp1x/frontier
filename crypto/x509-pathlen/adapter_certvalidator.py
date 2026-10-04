"""Second, INDEPENDENT lineage: pyca/certvalidator (pure-Python RFC 5280).

Why this matters for the session's central claim
-----------------------------------------------
The webpki result is one validation core.  certvalidator is a from-scratch
Python transcription of RFC 5280 section 6.1 -- it shares no code, no crypto
provider, no parser library and no upstream with rustls-webpki, and it does not
delegate to OpenSSL (IMPL-5 verified there are no ctypes bindings in the
package).  Agreement between the two is therefore genuine cross-implementation
evidence; disagreement is a rule difference, not a shared-ancestry artefact.

Its path-length core is validate.py:286-289 (step 1 k) and validate.py:640-653
(steps 3 l and 3 m), which follows the RFC's own variable names
(`max_path_length`, `cert.self_issued`, `cert.max_path_length`) closely enough
to audit line by line.

API shape, read from the source rather than guessed
--------------------------------------------------
`certvalidator.Certificate` is NOT a certvalidator class -- it is a re-export of
`asn1crypto.x509.Certificate` (`certvalidator/__init__.py:5`), a subclass of
asn1crypto's `Sequence`.  asn1crypto `Sequence.__init__` expects a dict of
field values or another Sequence (`asn1crypto/core.py:3398` calls
`value.keys()`), so calling `Certificate(der_bytes)` raises
`AttributeError: 'bytes' object has no attribute 'keys'`.  DER must be parsed
with the classmethod: `Certificate.load(der)`.

There is also no `certvalidator.Path`; the type the validator wants is
`certvalidator.path.ValidationPath` (`certvalidator/__init__.py:5-9` re-exports
`validate_path`, `validate_tls_hostname`, `validate_usage` but not `Path`).
`validate_path(context, path)` requires a `ValidationPath` instance and raises
TypeError otherwise (validate.py:229-234).

Two results are reported separately, never conflated: `validate_path` alone
(the RFC 5280 6.1 algorithm) and `validate_tls_hostname` (a TLS policy layer on
top of it).  A `name` verdict is a harness artefact -- certvalidator demands a
SAN matching a hostname, which a CA certificate cannot carry -- and is never
evidence about path length.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

from asn1crypto import x509 as asn1_x509

# certvalidator.Certificate is an alias of asn1crypto.x509.Certificate; alias it
# under the certvalidator name too so the source-read API is visible in code.
import certvalidator
from certvalidator import validate_path, validate_tls_hostname
from certvalidator.context import ValidationContext
from certvalidator.path import ValidationPath

DETAIL_CAP = 240


def classify(message: str) -> str:
    low = message.lower()
    if "path length" in low or "pathlen" in low:
        return "path_len"
    if "self-issued" in low or "self_issued" in low:
        return "self_issued"
    if "hostname" in low or "subjectaltname" in low or "common name" in low:
        return "name"
    if "not valid for" in low or "expired" in low or "not yet valid" in low:
        return "validity"
    if "unable to get local issuer" in low or "unknown" in low and "issuer" in low:
        return "trust_anchor"
    return "other"


def load(root: Path, label: str) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load((root / "certs" / f"{label}.der").read_bytes())


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".scratch/fx/corpus")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    oracle = {c["id"]: c for c in
              json.loads((root / "oracle.json").read_text(encoding="utf-8"))}
    # context.py:230-236 forbids allow_fetching=True together with moment, and
    # context.py:141 notes that a pinned moment means only supplied CRLs/OCSPs
    # can be consulted -- which is what we want: a hermetic, offline run.
    at_time = datetime.fromisoformat(manifest["verify_time"])
    loaded = {p.stem: load(root, p.stem) for p in (root / "certs").glob("*.der")}

    rows = ["case_id\timpl\tpath_verdict\tpath_reason_class\tpath_detail\t"
            "tls_verdict\toracle"]
    agree = 0
    classes: dict[str, str] = {}
    for case in manifest["cases"]:
        # The manifest lists the anchor separately: case["path"][0] is the
        # certificate *issued by* the anchor (gen_corpus.py's chain-integrity
        # check asserts path[0].issuer == anchor.subject).  The trust anchor is
        # therefore certificate 0 of the prospective certification path and
        # must be supplied as such, because the anchor's own pathLenConstraint
        # seeds max_path_length at validate.py:286-289 (RFC 5280 6.1.1 (k)).
        anchor = loaded[case["anchor"]]
        chain = [loaded[label] for label in case["path"]]
        ctx = ValidationContext(trust_roots=[anchor], moment=at_time,
                                allow_fetching=False)

        path = ValidationPath(anchor)
        for cert in chain:
            path.append(cert)

        # Result 1: the RFC 5280 section 6.1 algorithm, on its own.
        try:
            validate_path(ctx, path)
            verdict, detail = "ACCEPT", ""
        except Exception as exc:  # noqa: BLE001
            detail = " ".join(str(exc).split())[:DETAIL_CAP]
            verdict = "REJECT"

        # Result 2: the TLS policy layer, reported separately and never used to
        # override result 1.
        try:
            validate_tls_hostname(ctx, chain[-1], "example.invalid")
            tls = "ok"
        except Exception as exc:  # noqa: BLE001
            tls = "REJECT: " + " ".join(str(exc).split())[:120]

        cls = classify(detail) if verdict == "REJECT" else "-"
        classes[case["id"]] = cls
        expected = "ACCEPT" if oracle[case["id"]]["accepted"] else "REJECT"
        agree += int(verdict == expected)
        rows.append("\t".join([case["id"], "certvalidator0.11.1", verdict, cls,
                               detail.replace("\t", " "), tls.replace("\t", " "),
                               expected]))

    (root / "results_certvalidator.tsv").write_text("\n".join(rows) + "\n",
                                                    encoding="utf-8")
    print(f"certvalidator 0.11.1 (pure-Python, independent lineage): "
          f"{agree}/{len(manifest['cases'])} validate_path verdicts agree "
          f"with the Frontier oracle\n")
    print("  case_id                        path    class      oracle   "
          "tls_hostname")
    for line in rows[1:]:
        p = line.split("\t")
        mark = " " if p[2] == p[6] else "*"
        print(f"{mark} {p[0]:30} {p[2]:6} [{p[3]:11}] {p[6]:6}  {p[5][:34]}")

    pathlen_rejects = [c for c, k in classes.items() if k == "path_len"]
    print(f"\ncells whose validate_path rejection reason is path length: "
          f"{len(pathlen_rejects)}")
    print(f"  {pathlen_rejects}")
    by_class: dict[str, list[str]] = {}
    for case_id, cls in classes.items():
        by_class.setdefault(cls, []).append(case_id)
    print("\nreason classes over validate_path verdicts:")
    for cls in sorted(by_class):
        print(f"  {cls:12} {len(by_class[cls]):2}  {sorted(by_class[cls])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())