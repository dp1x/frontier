"""Generate the Frontier pathLen corpus to disk and run the Frontier oracle.

Outputs, under ``--out`` (default ``corpus/``):

  certs/<label>.der        exact DER bytes of every generated certificate
  manifest.json            hashes, roles, chain order, self-issued status, times
  oracle.tsv               the oracle verdict and trace for every case
  oracle.json              the same, structured

The manifest records everything needed to re-run any validator against the
corpus byte-for-byte: SHA-256 of each DER, the certificate order, the trust
anchor, the verification time, and the algorithm parameters.

Run::

    .venv\\Scripts\\python.exe crypto\\x509-pathlen\\gen_corpus.py --out R:\\fx\\corpus
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from chainforge import ChainForge, CertSpec, KEY_ALG, NOT_BEFORE, NOT_AFTER, VERIFY_TIME, RNG_SEED  # noqa: E402
from corpus import CASES, Case, build_all, _specs  # noqa: E402
from oracle import CertFacts, validate_path, exists_valid_path  # noqa: E402


def facts_for(issued, label: str) -> CertFacts:
    """Build the oracle's view of one certificate.

    BOTH `subject` and `issuer` must come from the parsed certificate's
    distinguished names.  Using the corpus LABEL for one side and the DN for
    the other silently makes self-issued detection impossible -- every
    certificate looks non-self-issued, which is how an earlier version of this
    harness produced a corpus in which every case accepted.
    """
    item = issued[label]
    return CertFacts(
        subject=item.cert.subject.rfc4514_string(),
        issuer=item.cert.issuer.rfc4514_string(),
        ca=item.spec.ca,
        pathlen=item.spec.pathlen,
        basic_constraints_present=item.spec.basic_constraints,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="corpus", help="output directory")
    args = parser.parse_args()

    out = Path(args.out)
    (out / "certs").mkdir(parents=True, exist_ok=True)

    forge = ChainForge(seed=RNG_SEED)
    issued = build_all(forge)

    # Pre-flight before anything consumes the corpus: a stale label is a
    # corpus-data defect, not a KeyError from deep inside a comprehension.
    ref_problems = _verify_references(issued)
    if ref_problems:
        print("reference problems:")
        for problem in ref_problems:
            print(f"  ! {problem}")
        raise SystemExit(1)

    # --- write exact DER -------------------------------------------------
    for label, item in issued.items():
        (out / "certs" / f"{label}.der").write_bytes(item.der)

    # --- manifest --------------------------------------------------------
    specs = _specs()
    manifest = {
        "generator": "crypto/x509-pathlen/chainforge.py",
        "seed": RNG_SEED,
        "key_alg": KEY_ALG,
        "not_before": NOT_BEFORE.isoformat(),
        "not_after": NOT_AFTER.isoformat(),
        "verify_time": VERIFY_TIME.isoformat(),
        "rfc5280_sha256": "A2F2628C0A83B873FC4786ABD921F9B2C02395954B655D190BF16B831633345D",
        "certificates": {
            label: {
                "sha256": item.sha256,
                "der_len": len(item.der),
                "subject_cn": item.spec.common_name,
                "issuer_cn": specs[label].issuer_cn,
                "self_issued": item.is_self_issued,
                "self_signed_axis": item.spec.self_signed,
                "ca": item.spec.ca,
                "pathlen": item.spec.pathlen,
                "basic_constraints_present": item.spec.basic_constraints,
                "key_cert_sign": item.spec.key_cert_sign,
            }
            for label, item in issued.items()
        },
        "cases": [
            {
                "id": c.case_id,
                "description": c.description,
                "anchor": c.anchor,
                "path": list(c.path),
                "isolates": c.isolates,
                "notes": c.notes,
            }
            for c in CASES
        ],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # --- oracle ----------------------------------------------------------
    rows = ["case_id\taccepted\treason\tother_defects\ttrace"]
    results = []
    for case in CASES:
        path_facts = [facts_for(issued, label) for label in case.path]
        verdict = validate_path(path_facts)
        trace = " | ".join(
            f"{s.index}:{s.label}:si={int(s.self_issued)}:mpl={s.max_path_length_after}:{s.action}"
            for s in verdict.trace
        )
        rows.append(
            "\t".join([
                case.case_id,
                "ACCEPT" if verdict.accepted else "REJECT",
                verdict.reason.replace("\t", " "),
                "; ".join(verdict.other_defects).replace("\t", " "),
                trace,
            ])
        )
        results.append({
            "id": case.case_id,
            "isolates": case.isolates,
            "accepted": verdict.accepted,
            "reason": verdict.reason,
            "other_defects": verdict.other_defects,
            "trace": [
                {"index": s.index, "label": s.label, "self_issued": s.self_issued,
                 "max_path_length": s.max_path_length_after, "action": s.action}
                for s in verdict.trace
            ],
        })

    (out / "oracle.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (out / "oracle.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    # --- structural self-checks -------------------------------------------
    # The decisive structural check: each pair must differ ONLY in
    # self-issued status of the designated certificate. If they do not, the
    # discriminating pair does not discriminate and the corpus is confounded.
    pair_ok, pair_detail = _verify_discriminating_pair(issued)
    dn_ok, dn_detail = _verify_unique_dns(specs)
    chain_problems = _verify_chain_integrity(issued)

    print(f"certificates: {len(issued)}")
    print(f"cases: {len(CASES)}")
    print(f"discriminating pair isolated: {pair_ok}")
    print(f"  {pair_detail}")
    print(f"unique-DN invariant: {dn_ok}")
    print(f"  {dn_detail}")
    print(f"chain integrity (RFC 5280 6.1(a)-(c)): "
          f"{'OK' if not chain_problems else str(len(chain_problems)) + ' PROBLEM(S)'}")
    for problem in chain_problems:
        print(f"  ! {problem}")
    print(f"oracle: {sum(1 for r in results if r['accepted'])} ACCEPT / "
          f"{sum(1 for r in results if not r['accepted'])} REJECT")
    print(f"written to {out}")
    return 0 if (pair_ok and dn_ok and not chain_problems) else 1


def _verify_references(issued) -> list[str]:
    """Every certificate a case names must exist, and every spec must be used.

    Cheap pre-flight, so a stale label is reported as a corpus-data defect with
    a readable message instead of a KeyError from deep inside a comprehension.
    """
    problems: list[str] = []
    for case in CASES:
        if case.anchor not in issued:
            problems.append(f"{case.case_id}: unknown trust anchor {case.anchor!r}")
        for label in case.path:
            if label not in issued:
                problems.append(f"{case.case_id}: unknown certificate {label!r}")
    referenced = {c.anchor for c in CASES} | {lbl for c in CASES for lbl in c.path}
    for label in issued:
        if label not in referenced:
            problems.append(f"certificate {label!r} is generated but used by no case")
    return problems


def _verify_chain_integrity(issued) -> list[str]:
    """Every case path must be a genuine certification path per RFC 5280 6.1.

    6.1(a): for all x in {1..n-1}, the subject of certificate x is the issuer
    of certificate x+1.  6.1(b): certificate 1 is issued by the trust anchor.
    6.1 also forbids a certificate appearing more than once in a path.

    This invariant exists because a path that violates 6.1(a) makes every
    downstream path-length observation uninterpretable: the chain would be
    invalid for a reason that has nothing to do with the variable under test,
    and an implementation could reject it for that reason alone.  It was added
    after two early versions of this corpus had exactly that defect.
    """
    problems: list[str] = []
    for case in CASES:
        path = case.path
        if not path:
            problems.append(f"{case.case_id}: empty path")
            continue

        # 6.1(b): certificate 1 is issued by the trust anchor.
        anchor = issued[case.anchor]
        first = issued[path[0]]
        if first.cert.issuer != anchor.cert.subject:
            problems.append(
                f"{case.case_id}: certificate 1 issuer {first.cert.issuer!r} is not "
                f"the trust anchor subject {anchor.cert.subject!r}"
            )

        # 6.1(a): subject of x is issuer of x+1.
        for i in range(len(path) - 1):
            subj = issued[path[i]].cert.subject
            issuer = issued[path[i + 1]].cert.issuer
            if subj != issuer:
                problems.append(
                    f"{case.case_id}: 6.1(a) broken at {i}->{i+1}: "
                    f"{subj!r} != {issuer!r}"
                )

        # 6.1: a certificate must not appear twice in one path.
        if len(set(path)) != len(path):
            problems.append(f"{case.case_id}: a certificate label repeats in the path")
    return problems


def _verify_discriminating_pair(issued) -> tuple[bool, str]:
    """c10 vs c11 must differ only in the middle certificate's self-issued flag.

    Self-issued status is defined by subject DN == issuer DN.  If the middle
    certificate of either case shares its subject DN with the certificate that
    issued it AND shares that certificate's serial number, then that case is
    *already* self-issued and the pair does not discriminate.  So the check is
    on the real parsed certificate, not on the specification's intent.
    """
    by_id = {c.case_id: c for c in CASES}
    pairs = [
        ("c10_pair1_nonself", "c11_pair1_selfissued", 1,
         "pair 1 mirrors the x509-limbo chain shape"),
        ("c12_pair2_nonself", "c13_pair2_selfissued", 1,
         "pair 2 puts the variable on the constrained certificate"),
    ]
    lines: list[str] = []
    for id_a, id_b, pos, why in pairs:
        a, b = by_id.get(id_a), by_id.get(id_b)
        if a is None or b is None:
            return False, f"pair {id_a}/{id_b} missing from CASES"
        if len(a.path) != len(b.path) or len(a.path) != 4:
            return False, f"{why}: depth mismatch {len(a.path)} vs {len(b.path)}"

        ns, si = issued[a.path[pos]], issued[b.path[pos]]

        # Member B must be genuinely self-issued; member A genuinely not.
        if si.cert.subject != si.cert.issuer:
            return False, f"{id_b}: {b.path[pos]} intended self-issued but is not"
        if ns.cert.subject == ns.cert.issuer:
            return False, f"{id_a}: {a.path[pos]} intended non-self-issued but is not"

        # Everything else about the pair members must match.  Subject PUBLIC
        # KEYS are deliberately excluded: a self-issued certificate normally
        # carries a NEW key (that is the point of a key rollover).
        if ns.spec.ca != si.spec.ca or ns.spec.pathlen != si.spec.pathlen:
            return False, f"{id_a}/{id_b}: pair members differ in ca or pathlen"
        if ns.spec.key_usage != si.spec.key_usage:
            return False, f"{id_a}/{id_b}: pair members differ in key usage"
        if ns.spec.issuer_cn != si.spec.issuer_cn:
            return False, f"{id_a}/{id_b}: pair members issued by different CAs"
        if ns.spec.serial == si.spec.serial:
            return False, f"{id_a}/{id_b}: pair members share a serial number"
        if ns.spec.eku_server_auth != si.spec.eku_server_auth:
            return False, f"{id_a}/{id_b}: pair members differ in EKU"

        # Outer positions must match on every axis the oracle can see, EXCEPT
        # the DN of the pair member's own child.
        #
        # A self-issued certificate has subject == issuer BY DEFINITION, so the
        # self-issued member cannot carry the same subject DN as a non-self-issued
        # twin: the DN difference is the MECHANISM of the variable under test,
        # not a confound.  (x509-limbo's builder makes the same point from the
        # other side, stuffing the parent's serial into an OU "to break accidental
        # self-issuing chains".)  What must still match is everything else:
        # depth, CA flag, pathLen, key usage, EKU, and the issuing CA.
        for idx in (0, 2, 3):
            x, y = issued[a.path[idx]], issued[b.path[idx]]
            if x.spec.ca != y.spec.ca or x.spec.pathlen != y.spec.pathlen:
                return False, f"{id_a}/{id_b}: position {idx} ca/pathlen differs"
            if idx == 0:
                # Position 0 is the CA that issues the pair member: it must be
                # the same CA in both, or the pair would vary two things.
                if x.subject != y.subject:
                    return False, f"{id_a}/{id_b}: the issuing CA differs"
        # The children of the pair members are separate certificates by
        # necessity (one certificate cannot issue two certificates bearing its
        # own DN), so their DNs are allowed to differ.  Their CA flag and
        # pathLen must still match, which is checked above.

        lines.append(
            f"{why}: {id_a} middle cert subject="
            f"{ns.cert.subject.rfc4514_string()!r} (NOT self-issued) vs {id_b} "
            f"subject={si.cert.subject.rfc4514_string()!r} (self-issued); "
            "same depth, same pathLen values, same CA flags"
        )

    return True, "; ".join(lines)


def _verify_unique_dns(specs) -> tuple[bool, str]:
    """No two certificates may share a subject DN unless one issues the other.

    A shared DN makes "is this certificate self-issued?" ambiguous from the
    corpus description alone.  Two certificates may legitimately share a DN if
    one is the issuer of the other AND they differ in serial number -- that is
    exactly the discriminating-pair shape.  Any other sharing is a defect.
    """
    by_cn: dict[str, list[str]] = {}
    for label, spec in specs.items():
        by_cn.setdefault(spec.common_name, []).append(label)

    for cn, labels in sorted(by_cn.items()):
        if len(labels) == 1:
            continue
        for i, a in enumerate(labels):
            for b in labels[i + 1:]:
                sa, sb = specs[a], specs[b]
                parent_of_a = sb if sa.issuer_cn == sb.label else None
                parent_of_b = sa if sb.issuer_cn == sa.label else None
                # Sharing a DN IS self-issuance -- but ONLY together with being
                # signed by that issuer's key and bearing a DIFFERENT serial.
                # Sharing both DN and serial makes them the SAME certificate,
                # which RFC 5280 6.1 forbids ("a certificate MUST NOT appear
                # more than once in a prospective certification path").
                if parent_of_a is not None and sa.serial == sb.serial:
                    return False, (
                        f"{a} and {b} share DN {cn!r} AND serial {sa.serial}; "
                        "they are one certificate, not a self-issued pair"
                    )
                if parent_of_a is None and parent_of_b is None:
                    return False, (
                        f"DN {cn!r} shared by {a} and {b}, neither of which is "
                        "issued by the other; self-issued status would be ambiguous"
                    )
    return True, f"{len(by_cn)} distinct DNs across {sum(len(v) for v in by_cn.values())} certificates"


if __name__ == "__main__":
    raise SystemExit(main())
