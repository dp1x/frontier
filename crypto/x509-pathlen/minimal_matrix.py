"""Run the minimal corpus through both oracles and both implementations.

Four independent verdicts per case, so the output discriminates between the
competing readings rather than merely recording a disagreement:

  H1  6.1.4 (l) is guarded on self-issued status, (m) is not.  A self-issued CA
      skips the decrement but still clamps its descendants.
  H2  The self-issued exception covers both (l) and (m).

The two oracles are written independently (minimal_oracle.walk vs
oracle.validate_path).  The two implementations are distinct validation cores:
pyca/cryptography's in-tree cryptography-x509-verification crate, and
wbond/certvalidator.  They share no code, vendor or ancestry.

DISCRIMINATING POWER is measured, not asserted: a case only discriminates H1
from H2 if the two oracles disagree on it.  A corpus of any size that never
produces a disagreement cannot support a claim about which reading is right.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cryptography.x509.verification import (  # noqa: E402
    DNSName,
    PolicyBuilder,
    Store,
)
from minimal_chain import build  # noqa: E402
from minimal_oracle import Node, walk, walk_H2  # noqa: E402

try:
    from certvalidator import validate_path as _cv_validate_path
    from certvalidator.context import ValidationContext as _CVContext
    from certvalidator.path import ValidationPath as _CVPath
    HAVE_CERTVALIDATOR = True
except ImportError:  # pragma: no cover
    HAVE_CERTVALIDATOR = False


def classify(message: str) -> str:
    """Reason class.  Only `path_len` supports a path-length conclusion."""
    low = message.lower()
    if "path length" in low or "pathlen" in low or "path length constraint" in low:
        return "path_len"
    if "signature" in low:
        return "signature"
    if "expired" in low or "not yet valid" in low or "validity" in low:
        return "validity"
    if "keyusage" in low or "key_cert_sign" in low or "key cert sign" in low:
        return "key_usage"
    if "basic" in low and "constraint" in low:
        return "basic_constraints"
    if "name" in low or "subject" in low or "alt" in low:
        return "name"
    if "authority" in low or "trust" in low:
        return "trust_anchor"
    return "other"


def run_webpki(anchor, path_certs, at_time):
    """pyca/cryptography's verification core, driven through a server policy.

    Note the `.cert` unwrapping: `path_certs` holds this corpus's `Cert`
    wrapper, and the verifier requires the `cryptography` Certificate object
    itself.  Passing the wrapper produces "'Cert' object is not an instance of
    'Certificate'" -- an exception from the TYPE system, which the reason
    classifier would otherwise file as an unexplained "other" and which says
    nothing at all about path length.
    """
    target = path_certs[-1].cert
    inter = [c.cert for c in path_certs[:-1]]
    try:
        policy = (PolicyBuilder().store(Store([anchor.cert])).time(at_time)
                  .build_server_verifier(DNSName("example.invalid")))
        policy.verify(target, inter)
        return "ACCEPT", ""
    except Exception as exc:  # noqa: BLE001
        return "REJECT", " ".join(str(exc).split())[:300]


def run_certvalidator(anchor, path_certs, at_time):
    """certvalidator's `validate_path` -- the RFC 5280 6.1 algorithm on its own.

    The trust anchor must be supplied as certificate 0 of the ValidationPath.
    That is certvalidator's convention, not a Frontier choice: its
    validate.py:286-289 seeds max_path_length from the anchor's own
    pathLenConstraint during initialisation, so the anchor has to be present in
    the path object.  This is exactly the 6.2-permitted augmentation that
    makes fnd-2026-0016 a conformance observation rather than a violation, and
    it means the anchor's presence is a CONSTANT across every cell here -- it
    cannot be the thing that varies between the self-issued and non-self-issued
    members of a pair.
    """
    if not HAVE_CERTVALIDATOR:
        return "NOT_RUN", "certvalidator not installed"
    try:
        ctx = _CVContext(trust_roots=[anchor.cert_asn1], moment=at_time,
                         allow_fetching=False)
        # ValidationPath(anchor) PREPENDS the anchor, so the anchor ends up at
        # the END of the list.  Appending the chain in anchor-first order then
        # yields anchor, cert1, cert2, ... which is the order certvalidator's
        # validate.py expects: it walks from the trust anchor at index 0.
        path = _CVPath(anchor.cert_asn1)
        for c in path_certs:
            path.append(c.cert_asn1)
        _cv_validate_path(ctx, path)
        return "ACCEPT", ""
    except Exception as exc:  # noqa: BLE001
        return "REJECT", " ".join(str(exc).split())[:300]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=r"R:\fx\minimal")
    args = ap.parse_args()

    forge, certs, cases = build()
    at_time = datetime.fromisoformat(
        json.loads((Path(args.out) / "manifest.json").read_text())["verify_time"]
    ) if (Path(args.out) / "manifest.json").exists() else None
    from minimal_chain import VERIFY_TIME
    at_time = at_time or VERIFY_TIME

    rows = []
    discriminating = []
    disagree = []

    for case in cases:
        anchor = certs[case.anchor]
        path_certs = [certs[label] for label in case.path]
        nodes = [
            Node(label=c.label, subject=c.subject, issuer=c.issuer,
                 ca=c.ca, pathlen=c.pathlen)
            for c in path_certs
        ]

        h1 = walk(nodes)
        h2 = walk_H2(nodes)

        wp_verdict, wp_detail = run_webpki(anchor, path_certs, at_time)
        cv_verdict, cv_detail = run_certvalidator(anchor, path_certs, at_time)

        h1_v = "ACCEPT" if h1.accepted else "REJECT"
        h2_v = "ACCEPT" if h2.accepted else "REJECT"
        sep = h1_v != h2_v
        if sep:
            discriminating.append(case.case_id)
        if wp_verdict != h1_v:
            disagree.append(case.case_id)

        rows.append({
            "id": case.case_id,
            "isolates": case.isolates,
            "control": case.control,
            "path": list(case.path),
            "anchor": case.anchor,
            "anchor_self_issued": anchor.self_issued,
            "anchor_in_path": case.anchor in case.path,
            "H1": h1_v,
            "H2": h2_v,
            "discriminates_H1_H2": sep,
            "H1_reason": h1.reason,
            "H2_reason": h2.reason,
            "trace": [f.as_dict() for f in h1.frames],
            "cryptography": wp_verdict,
            "cryptography_class": classify(wp_detail) if wp_verdict == "REJECT" else "-",
            "cryptography_detail": wp_detail,
            "certvalidator": cv_verdict,
            "certvalidator_class": classify(cvv) if (cvv := cv_detail) and
                                    cv_verdict == "REJECT" else "-",
            "certvalidator_detail": cv_detail,
        })

    out = Path(args.out) / "minimal_matrix.json"
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    print(f"{'case':<14} {'H1':<7} {'H2':<7} {'disc':<5} {'crypto':<9} "
          f"{'class':<10} {'certval':<9} {'class'}")
    print("-" * 88)
    for r in rows:
        print(f"{r['id']:<14} {r['H1']:<7} {r['H2']:<7} "
              f"{'YES' if r['discriminates_H1_H2'] else '.':<5} "
              f"{r['cryptography']:<9} {r['cryptography_class']:<10} "
              f"{r['certvalidator']:<9} {r['certvalidator_class']}")

    print(f"\ncases: {len(rows)}")
    print(f"discriminating H1 vs H2: {len(discriminating)} {discriminating}")
    print(f"cryptography disagrees with H1: {len(disagree)} {disagree}")

    print("\n--- traces for the self-issued cases ---")
    for r in rows:
        if any("si" == p or "_si" in p for p in r["path"]):
            print(f"\n{r['id']}  H1={r['H1']}  H2={r['H2']}  "
                  f"crypto={r['cryptography']} cv={r['certvalidator']}")
            for f in r["trace"]:
                print(f"  cert{f['position']} {f['label']:<14} "
                      f"si={int(f['self_issued'])} ca={int(f['ca'])} "
                      f"in={f['incoming_max_path_length']} "
                      f"(l)->{f['after_l']} pl={f['pathlen']} "
                      f"(m)->{f['final_max_path_length']}  {f['note']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())