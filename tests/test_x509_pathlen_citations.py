"""Verify every RFC 5280 quotation in the X.509 artifacts byte-exactly.

Why this is a test and not a one-off script
------------------------------------------
`tools/promotion_gate.py` reports "0 live normative claims" for these artifacts,
so the gate provides NO assurance about their quotations.  A quotation that is
attributed to the wrong clause, or that does not exist, is the exact failure
mode this repository exists to catch -- `fnd-2026-0014` carried text attributed
to RFC 9052 section 9 that is not in RFC 9052, and `spc-2026-0004` carries
fabricated RFC 8949 quotations.  Both survived because nobody re-fetched the
source.  So the check is done here, directly, against the authoritative text.

Normalization is deliberately conservative and is documented inline, because a
sloppy normalizer would make this test pass vacuously:

  * whitespace is collapsed (the RFC re-wraps at column 68);
  * a hyphen followed by a space and a lowercase letter is re-joined, because
    RFC 5280 soft-hyphenates compound words at line breaks ("non-\\nself-issued");
  * leading/trailing quote characters are stripped, because YAML block folding
    can leave them behind on an unquoted scalar.

An elision ("...") splits a quotation into fragments, and EVERY fragment must be
present.  That keeps a quotation honest: splicing two unrelated passages together
still fails, because the join point must be marked.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RFC_PATH = ROOT / ".scratch" / "fx" / "rfc5280.txt"

# RFC 5280, May 2008, Standards Track, fetched live from the RFC Editor.
EXPECTED_BYTES = 352580
EXPECTED_SHA256 = "A2F2628C0A83B873FC4786ABD921F9B2C02395954B655D190BF16B831633345D"

ARTIFACTS = [
    "knowledge/findings/fnd-2026-0016.yaml",
    "knowledge/hypotheses/hyp-2026-0028.yaml",
]


def _normalise(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r'^["\']+', "", text)
    text = re.sub(r'["\']+$', "", text)
    text = re.sub(r"\s+", " ", text).strip()
    # Line-break hyphenation: "non- self-issued" -> "non-self-issued".
    text = re.sub(r"-\s+(?=[a-z])", "-", text)
    return text


def _fragments(quotation: str) -> list[str]:
    parts = [p.strip(" \"'") for p in re.split(r"\.\.\.|…", _normalise(quotation))]
    return [p for p in parts if len(p) > 25]


def _load_rfc() -> str:
    if not RFC_PATH.is_file():
        pytest.skip(
            f"authoritative RFC text absent at {RFC_PATH}; re-fetch with "
            "https://www.rfc-editor.org/rfc/rfc5280.txt to run this test"
        )
    import hashlib

    # Hash the BYTES as fetched, before any text-mode line-ending translation:
    # reading with newline translation would rewrite CRLF and change the digest,
    # which is exactly the kind of silent substitution this check exists to
    # catch.  Compare case-insensitively because hashlib emits lowercase.
    raw = RFC_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest().upper()
    assert len(raw) == EXPECTED_BYTES, (
        f"RFC 5280 is {len(raw)} bytes, expected {EXPECTED_BYTES}; the text may "
        "have been substituted"
    )
    assert digest == EXPECTED_SHA256.upper(), (
        f"RFC 5280 SHA-256 mismatch: got {digest}, expected {EXPECTED_SHA256}"
    )
    return _normalise(raw.decode("utf-8", errors="replace"))


@pytest.fixture(scope="module")
def rfc_text() -> str:
    return _load_rfc()


def _quotations(path: str):
    doc = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    out = []
    for check in doc.get("normative_checks") or []:
        out.append((f"{path}: section {check.get('section')}", check.get("quoted", "")))
    for key, text in (doc.get("normative_basis") or {}).items():
        out.append((f"{path}: {key}", text))
    return out


@pytest.mark.parametrize("artifact", ARTIFACTS)
def test_artifact_has_quotations_to_verify(artifact):
    """A vacuous pass is worse than no test: require real quotations."""
    assert _quotations(artifact), f"{artifact} carries no normative quotations"


@pytest.mark.parametrize("artifact", ARTIFACTS)
def test_every_quotation_is_present_in_rfc_5280(artifact, rfc_text):
    for label, quotation in _quotations(artifact):
        fragments = _fragments(quotation)
        assert fragments, f"{label}: nothing long enough to probe"
        for fragment in fragments:
            assert fragment in rfc_text, (
                f"{label}: quotation not found in RFC 5280.\n"
                f"  fragment: {fragment[:160]!r}"
            )


def test_the_decisive_clause_is_quoted_somewhere():
    """Guard the clause the whole finding rests on.

    RFC 5280 6.1 restricts step (3) -- which is 6.1.4, the step that performs
    the path-length decrement -- to certificates 1..n-1. No inherited source
    cited this clause, and without it the acceptance predicate is underivable.
    If a future edit drops it, this fails.
    """
    text = _load_rfc()
    assert (
        "Step (3) is performed for all certificates in the path except the "
        "final certificate." in text
    )


def test_self_issued_exclusion_is_quoted_somewhere():
    text = _load_rfc()
    assert (
        "These self-issued certificates are not counted when evaluating path "
        "length or name constraints." in text
    )


def test_trust_anchor_exclusion_is_quoted_somewhere():
    text = _load_rfc()
    assert (
        "this self-signed certificate is not included as part of the "
        "prospective certification path" in text
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
