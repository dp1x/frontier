"""Regression tests for the two citation-integrity holes this audit found.

Both were demonstrated against the real tool before the fix, with the exact
inputs recorded here, so each test is a pin on a measured defect rather than a
speculation:

``quorum_admits_fabrication``
    ``_best_ratio`` reports a *ratio*, and both locate paths reported
    ``confirmed`` at ``ratio >= LOCATE_QUORUM`` (0.6) without looking at the
    units that were missing.  Measured before the fix, against the real
    recorded RFC 9052 section 9: one fabricated sentence plus two genuine ones
    scored 2/3 = 0.67 and the gate returned ``ALLOW``.  The fabricated sentence
    occurs nowhere in RFC 9052.  A quotation is only as trustworthy as its
    least-sourced sentence, so a unit absent from the whole cited document now
    blocks ``confirmed``.

``fixture_digest_never_verified``
    ``SourceStore.load_fixture`` read ``body_sha256`` and stored it, and
    nothing on the offline path ever recomputed it.  Measured before the fix:
    replacing RFC 9052's digest with a fabricated value changed no observable
    behaviour, and hand-editing the fixture's recorded RFC text was invisible.
    The recorded ``body_sha256`` describes the raw fetched body, which is not
    stored and cannot be re-derived offline, so the fixture now also records a
    ``normalized_sha256`` over the normalized text the gate actually probes --
    that one *can* be recomputed without a network.

No network: every RFC body used here is the repository's own recorded fixture.
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]


def _load_gate():
    name = "frontier_promotion_gate_citation_integrity"
    spec = importlib.util.spec_from_file_location(
        name, REPO / "tools" / "promotion_gate.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GATE, GATE_ERR = None, None
try:
    GATE = _load_gate()
except Exception as exc:  # noqa: BLE001 - a missing dep must skip, not error
    GATE_ERR = f"{type(exc).__name__}: {exc}"

needs_gate = pytest.mark.skipif(GATE is None, reason=f"gate not importable: {GATE_ERR}")
TODAY = datetime.now(UTC).date()

# Genuine RFC 9052 section 9 sentences, verbatim from the recorded fixture.
GENUINE_S9 = [
    "Encoding MUST be done using definite lengths, and the length of the "
    "(encoded) argument MUST be the minimum possible length.",
    "This means that the integer 1 is encoded as \"0x01\" and not \"0x1801\".",
    "Applications MUST NOT generate messages with the same label used twice as "
    "a key in a single map.",
    "Applications MUST NOT parse and process messages with the same label used "
    "twice as a key in a single map.",
]

# Absent from RFC 9052 entirely -- verified, not assumed: asserted below.
FABRICATED = (
    "Every COSE encoder MUST reject a message whose single map contains the "
    "same label twice, and MUST emit a diagnostic identifying the offending "
    "label and its byte offset within the serialised message."
)

SUPPORT_REVIEW = {
    "id": "rev-2026-9201",
    "type": "review",
    "status": "complete",
    "epistemic_status": "verified_conclusion",
    "created_at": "2026-10-01T00:00:00Z",
    "updated_at": "2026-10-01T00:00:00Z",
    "summary": "independent adversarial review that supports",
    "provenance": {"created_by": {"kind": "model-agent", "role": "adversarial-critic"}},
    "links": {},
    "role": "adversarial-critic",
    "verdict": "supports",
    "independent": True,
}


@pytest.fixture(scope="module")
def store():
    s = GATE.SourceStore(online=False, timeout=1.0)
    s.load_fixture()
    return s


@pytest.fixture(scope="module")
def rfc9052(store):
    return store.get(9052)


def _record(quoted: str, section: str = "RFC 9052 section 9") -> dict:
    return {
        "id": "NC-1",
        "source": "https://www.rfc-editor.org/rfc/rfc9052.txt",
        "section": section,
        "quoted": quoted,
        "checked_at": (TODAY - timedelta(days=1)).isoformat(),
        "checker": {"kind": "human", "identity": "independent-checker"},
        "verdict": "confirmed",
        "method": "deterministic-script",
    }


def _finding(quoted: str, claim_key: str = "rfc_9052_section_9") -> dict:
    return {
        "id": "fnd-2026-9201",
        "type": "finding",
        "status": "verified_conclusion",
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z",
        "summary": "citation integrity regression fixture",
        "epistemic_status": "verified_conclusion",
        "classification": "spec-violation",
        "provenance": {
            "created_by": {"kind": "model-agent", "role": "specification-analyst"},
            "sources": ["https://www.rfc-editor.org/rfc/rfc9052.txt"],
        },
        "links": {"reviews": ["rev-2026-9201"]},
        "normative_basis": {claim_key: quoted},
        "normative_checks": [_record(quoted)],
    }


def _gate(doc: dict, store, tmp_path):
    (tmp_path / "knowledge/findings").mkdir(parents=True, exist_ok=True)
    (tmp_path / "knowledge/reviews").mkdir(parents=True, exist_ok=True)
    (tmp_path / "knowledge/reviews/rev-2026-9201.yaml").write_text(
        yaml.safe_dump(SUPPORT_REVIEW, sort_keys=False), encoding="utf-8"
    )
    (tmp_path / "knowledge/findings/fnd-2026-9201.yaml").write_text(
        yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
    )
    artifacts, _broken, by_id = GATE.load_corpus(tmp_path, include_missions=False)
    return GATE.evaluate_artifact(
        artifacts[0], by_id, store, recheck_days=180, today=TODAY, online=False
    )


# --------------------------------------------------------------------------
# Control: the fixture really does not contain the "fabricated" sentence.
# Without this, the refusals below could be an artefact of my own quotation.
# --------------------------------------------------------------------------

@needs_gate
def test_control_fabricated_sentence_is_genuinely_absent(rfc9052):
    assert GATE._normalize_text(FABRICATED) not in rfc9052.full_text
    assert GATE._normalize_text(FABRICATED) not in rfc9052.sections["9"]


@needs_gate
def test_control_genuine_sentences_are_present(rfc9052):
    for sentence in GENUINE_S9:
        assert GATE._normalize_text(sentence) in rfc9052.sections["9"]


# --------------------------------------------------------------------------
# Gap 1: the quorum admitted a fabricated sentence
# --------------------------------------------------------------------------

@needs_gate
@pytest.mark.parametrize("n_genuine", [2, 3, 4])
def test_fabricated_unit_blocks_confirmation(rfc9052, n_genuine):
    """One fabricated sentence must not ride in on genuine ones.

    Measured before the fix: ``n_genuine=2`` scored 2/3 = 0.67 against
    ``LOCATE_QUORUM`` = 0.6 and the gate ALLOWed the artifact.
    """
    quoted = FABRICATED + " " + " ".join(GENUINE_S9[:n_genuine])
    verdict, detail = GATE.locate_quoted_text(quoted, rfc9052, "9")
    assert verdict == "absent-from-all-cited", detail
    # The refusal must name the offending sentence (truncated for legibility),
    # so a reader can see *which* claim was not in the source.
    normalized = GATE._normalize_text(FABRICATED)
    assert GATE._truncate(normalized, 160) in detail, detail


@needs_gate
@pytest.mark.parametrize("n_genuine", [2, 3, 4])
def test_fabricated_unit_refuses_artifact(store, tmp_path, n_genuine):
    quoted = FABRICATED + " " + " ".join(GENUINE_S9[:n_genuine])
    result = _gate(_finding(quoted), store, tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G2_NOT_IN_SOURCE in {r.rule for r in result.blocking}


@needs_gate
def test_genuine_quotation_still_confirms(rfc9052):
    """Non-vacuity control: the tightening must not refuse real quotations."""
    quoted = " ".join(GENUINE_S9)
    verdict, detail = GATE.locate_quoted_text(quoted, rfc9052, "9")
    assert verdict == "confirmed", detail


@needs_gate
def test_genuine_quotation_still_allows_artifact(store, tmp_path):
    quoted = " ".join(GENUINE_S9)
    result = _gate(_finding(quoted), store, tmp_path)
    assert result.decision == GATE.ALLOW, [r.detail for r in result.reasons]


@needs_gate
def test_ellipsis_quotation_within_one_section_still_confirms(rfc9052):
    """A faithful elision must survive the tightening.

    The strict test rejects a *decomposition* that leaves a unit unaccounted
    for; it must not reject a quotation that legitimately elides real text.
    """
    quoted = (
        "Encoding MUST be done using definite lengths, and the length of the "
        "(encoded) argument MUST be the minimum possible length. ... "
        "Applications MUST NOT parse and process messages with the same label "
        "used twice as a key in a single map."
    )
    verdict, detail = GATE.locate_quoted_text(quoted, rfc9052, "9")
    assert verdict == "confirmed", detail


@needs_gate
def test_every_real_corpus_check_is_still_fully_located(store):
    """The tightening must cost nothing on the corpus it is applied to.

    All seven ``normative_checks`` records in the repository locate at 100% of
    their quoted units against their cited document.  If that stops being true
    the tightening has started refusing real quotations.
    """
    artifacts, _broken, by_id = GATE.load_corpus(REPO, include_missions=True)
    partial = []
    for art in artifacts:
        if art.doc.get("type") not in GATE.GATED_TYPES:
            continue
        records, _problems = GATE.collect_check_records(art, by_id)
        for r in records:
            if r.rfc_number is None or not r.quoted:
                continue
            doc = store.get(r.rfc_number)
            if doc is None:
                continue
            _ratio, hits, total = GATE._best_ratio(
                (r.quoted, GATE.VERIFY._quote_probe_sentences(r.quoted)), doc.full_text
            )
            if total and hits < total:
                partial.append((r.origin_id, r.rfc_number, r.section_number, hits, total))
    assert not partial, partial


def _store():
    s = GATE.SourceStore(online=False, timeout=1.0)
    s.load_fixture()
    return s


# --------------------------------------------------------------------------
# Gap 2: the fixture's own digest was never verified offline
# --------------------------------------------------------------------------

@needs_gate
def test_fixture_digest_itself_verifies():
    """The committed fixture must pass its own integrity check.

    A fixture that fails this is worse than no fixture: it makes every section
    check against it unsound while still reporting clean.
    """
    s = GATE.SourceStore(online=False, timeout=1.0)
    s.load_fixture()
    assert not s.fixture_provenance, s.fixture_provenance
    assert s._fixture, "no fixture documents were loaded"


@needs_gate
def test_every_fixture_entry_records_a_verifiable_digest():
    s = GATE.SourceStore(online=False, timeout=1.0)
    s.load_fixture()
    for number, meta in s.fixture_meta.items():
        assert meta.get("normalized_sha256"), f"RFC {number} has no normalized_sha256"
        assert len(meta["normalized_sha256"]) == 64


def _tampered_fixture(mutate, tmp_path):
    """Load a mutated COPY of the real fixture through the real code path."""
    data = yaml.safe_load(GATE.FIXTURE_PATH.read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "rfc_sections.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
                    encoding="utf-8")
    original = GATE.FIXTURE_PATH
    try:
        GATE.FIXTURE_PATH = path
        s = GATE.SourceStore(online=False, timeout=1.0)
        s.load_fixture()
        return list(s.fixture_provenance)
    finally:
        GATE.FIXTURE_PATH = original


@needs_gate
def test_hand_edited_fixture_text_is_detected(tmp_path):
    """Editing the recorded RFC text must not go unnoticed (measured gap)."""
    def mutate(data):
        for entry in data["sources"]:
            if int(entry["rfc"]) == 9052:
                entry["full_text_normalized"] = entry["full_text_normalized"].replace(
                    "minimum possible length",
                    "minimum possible length, and the map keys must be sorted",
                )

    notes = _tampered_fixture(mutate, tmp_path)
    assert notes, "hand-edited fixture text was accepted without complaint"
    assert any("does not match the recorded normalized_sha256" in n for n in notes), notes


@needs_gate
def test_hand_edited_fixture_section_is_detected(tmp_path):
    """Editing one recorded section must not go unnoticed."""
    def mutate(data):
        for entry in data["sources"]:
            if int(entry["rfc"]) == 9052:
                entry["sections"]["9"] = entry["sections"]["9"] + " fabricated rule."

    notes = _tampered_fixture(mutate, tmp_path)
    assert notes, "hand-edited fixture section was accepted without complaint"
    assert any("internally inconsistent" in n for n in notes), notes


@needs_gate
def test_missing_digest_is_reported_as_unverifiable(tmp_path):
    """A fixture entry with no offline-checkable digest must say so."""
    def mutate(data):
        for entry in data["sources"]:
            if int(entry["rfc"]) == 9052:
                entry.pop("normalized_sha256", None)

    notes = _tampered_fixture(mutate, tmp_path)
    assert any("no normalized_sha256" in n for n in notes), notes


@needs_gate
def test_unmodified_fixture_reports_nothing(tmp_path):
    """The control: a clean fixture must produce no integrity complaint."""
    notes = _tampered_fixture(lambda data: None, tmp_path)
    assert not notes, notes