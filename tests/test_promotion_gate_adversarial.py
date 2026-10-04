"""Adversarial tests for the promotion gate against LYING METADATA.

Companion to ``test_promotion_gate_checks.py``, which tests the gate against
*honest* fixtures.  This file tests it against artifacts that lie in their own
metadata: a ``verdict: confirmed`` whose checker is the artifact's author, a
quotation that exists nowhere, a section number nobody read, a stub quote, and
the trivial obfuscations available to a checker who knows the rules.

Why this matters is on the record.  ``fnd-2026-0014`` carried a quotation
presented as RFC 9052 section 9 that does not exist in RFC 9052 -- RFC 8949
section 4.2.1 text spliced into an RFC 9052 attribution -- and it survived two
correction passes and a promotion.  ``spc-2026-0004`` carries fabricated RFC
8949 section 4.2.1 quotations.  The gate exists because a ``verdict: confirmed``
written into a YAML field is a *claim about a check*, not the check.

Conventions (as in ``test_instrument_adversarial.py``)
-------------------------------------------------------
* A ``DEFECT``-marked test asserts the correct fail-closed behaviour and
  therefore fails against current HEAD.  It carries ``xfail(strict=True)``, so
  the suite stays green and a fix surfaces as an XPASS that forces the marker
  off.  Each one is reported as an instrument defect in the session report.
* An unmarked test is a control: behaviour the gate already gets right, which
  is what makes the defect tests meaningful.  Without controls, a gate that
  refused everything would "pass".
* No network.  The ``SourceStore`` is built directly from text held here, which
  is the same construction ``test_promotion_gate_checks.py`` uses.
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
    """Import ``tools/promotion_gate.py`` the way the tool loads its sibling."""
    name = "frontier_promotion_gate_adversarial_under_test"
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

GENUINE_9052_SEC9 = GATE.GENUINE_9052_SEC9 if GATE else ""
SPLICE_8952_421 = GATE.SPLICE_8952_421 if GATE else ""

# A second, genuine RFC 9052 section, so "wrong section" is distinguishable from
# "fabricated".
RFC_9052_SEC3 = (
    "The structure of COSE has been designed to have two buckets of "
    "information that are not considered to be part of the payload itself, "
    "but are used for holding information about content, algorithms, keys, "
    "or evaluation hints for the processing of the layer."
)

RFC_9052 = (
    GENUINE_9052_SEC9 + " " + RFC_9052_SEC3 + " Section 3 discusses the COSE "
    "message structure and the two buckets of information that are not "
    "considered to be part of the payload itself.",
    {
        "9": GENUINE_9052_SEC9,
        "3": RFC_9052_SEC3,
        "4.1": "Reserved for future use by the CBOR encoders and decoders working group.",
    },
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


def _store(documents: dict[int, tuple[str, dict[str, str]]]):
    """A ``SourceStore`` holding the given RFCs, bypassing the network."""
    store = GATE.SourceStore(online=False, timeout=1.0)
    store._fixture = {
        number: GATE.RfcDocument(
            number=number,
            url=f"https://www.rfc-editor.org/rfc/rfc{number}.txt",
            full_text=GATE._normalize_text(full),
            sections={k: GATE._normalize_text(v) for k, v in sections.items()},
            origin="test",
        )
        for number, (full, sections) in documents.items()
    }
    return store


def _record(section: str, quoted: str, **overrides) -> dict:
    base = {
        "id": "NC-1",
        "source": "https://www.rfc-editor.org/rfc/rfc9052.txt",
        "section": section,
        "quoted": quoted,
        "checked_at": (TODAY - timedelta(days=2)).isoformat(),
        "checker": {"kind": "human", "identity": "independent-checker"},
        "verdict": "confirmed",
        "method": "deterministic-script",
    }
    base.update(overrides)
    return base


def _finding(root: Path, *, record: dict, claim: str = GENUINE_9052_SEC9,
             author: dict | None = None, key: str = "rfc_9052_section_9",
             doc_overrides: dict | None = None) -> str:
    doc = {
        "id": "fnd-2026-9201",
        "type": "finding",
        "status": "verified_conclusion",
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z",
        "summary": "test finding",
        "epistemic_status": "verified_conclusion",
        "classification": "spec-violation",
        "provenance": {
            "created_by": author or {"kind": "model-agent",
                                     "role": "specification-analyst"},
            "sources": ["https://www.rfc-editor.org/rfc/rfc9052.txt"],
        },
        "links": {"reviews": ["rev-2026-9201"]},
        "normative_basis": {key: claim},
        "normative_checks": [record],
    }
    doc.update(doc_overrides or {})
    (root / "knowledge/findings").mkdir(parents=True, exist_ok=True)
    (root / "knowledge/reviews").mkdir(parents=True, exist_ok=True)
    (root / "knowledge/reviews/rev-2026-9201.yaml").write_text(
        yaml.safe_dump(SUPPORT_REVIEW, sort_keys=False), encoding="utf-8"
    )
    (root / "knowledge/findings/fnd-2026-9201.yaml").write_text(
        yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
    )
    return doc["id"]


def _evaluate(root: Path, store=None):
    artifacts, _broken, by_id = GATE.load_corpus(root, include_missions=False)
    store = store or _store({9052: RFC_9052})
    return GATE.evaluate_artifact(
        artifacts[0], by_id, store, recheck_days=180, today=TODAY, online=False
    )


def _rules(result) -> set[str]:
    return {r.rule for r in result.blocking}


# ==========================================================================
# Controls: the gate must still allow an honest, independently checked claim
# ==========================================================================


@needs_gate
def test_honest_independent_check_is_still_allowed(tmp_path):
    """The control that makes every refusal below meaningful.

    A gate that refused everything would pass all the attack tests below while
    being useless.  A correct, independent, located check must still ALLOW.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.ALLOW, [r.detail for r in result.reasons]
    assert not result.blocking


@needs_gate
def test_an_existing_section_is_not_mistaken_for_an_invented_one(tmp_path):
    """Control for the G9 machinery: ``4.1`` is a real section of the source.

    Scoped to G9 alone, because this fixture's short quotation is legitimately
    caught by G10 for a different reason -- quoting three words proves no
    retrieval no matter which section is cited.  Asserting only that G9 stays
    quiet keeps the control about the rule it is a control for.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 4.1", "Reserved for future use"))
    assert GATE.G9_SECTION_ABSENT not in _rules(_evaluate(tmp_path))


# ==========================================================================
# 6a. G11 -- the checker is the artifact's own author
# ==========================================================================


@needs_gate
def test_self_certified_claim_is_refused(tmp_path):
    """Attack 6a.  An author who writes its own ``verdict: confirmed``.

    This is the exact shape of failure mode F1: the artifact says it checked
    itself, and ``verdict: confirmed`` discharges nothing.
    """
    author = {"kind": "model-agent", "role": "orchestrator-synthesizer",
              "model": "grok-4.1"}
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9,
                       checker="grok-4.1, read directly from the fetched source"),
        author=author,
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G11_SELF_CHECKED in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_self_certified_checker_dict_is_refused(tmp_path):
    """Same attack with a structured checker rather than free text."""
    author = {"kind": "model-agent", "role": "specification-analyst",
              "model": "grok-4.1", "tool": "pytest"}
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9,
                       checker={"kind": "model-agent", "model": "grok-4.1"}),
        author=author,
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G11_SELF_CHECKED in _rules(result)


@needs_gate
def test_a_second_uncorroborated_record_does_not_discharge_g11(tmp_path):
    """Attack 6a, aggregation: two self-reports are still two self-reports.

    G11 must consider *every* confirming record, not the first or the most
    recent.  An author that adds a second check record still has only checked
    itself, and adding a record must not look like corroboration.
    """
    author = {"kind": "model-agent", "role": "orchestrator-synthesizer",
              "model": "grok-4.1"}
    doc_overrides = {
        "normative_checks": [
            _record("RFC 9052 section 9", GENUINE_9052_SEC9,
                    id="NC-1", checker="grok-4.1, first pass"),
            _record("RFC 9052 section 9", GENUINE_9052_SEC9,
                    id="NC-2", checker="grok-4.1, second look, same author"),
        ]
    }
    _finding(tmp_path,
             record=_record("RFC 9052 section 9", GENUINE_9052_SEC9),
             author=author, doc_overrides=doc_overrides)
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G11_SELF_CHECKED in _rules(result)


@needs_gate
def test_g11_fires_when_the_only_checker_is_the_author_even_with_a_supporting_review(tmp_path):
    """Attack 6a with the strongest-looking paperwork.

    Every other gate input is present and honest -- a supporting independent
    review, a real quotation, a real section, a fresh date.  Only the checker's
    identity is the lie.  The gate must still refuse, because a supporting
    review of the artifact is not a re-fetch of the cited clause.
    """
    author = {"kind": "model-agent", "role": "orchestrator-synthesizer",
              "model": "grok-4.1"}
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9,
                       checker="grok-4.1"),
        author=author,
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G11_SELF_CHECKED in _rules(result)
    assert GATE.G5_NO_REVIEW not in _rules(result), (
        "the review is honest and supporting; refusing on G5 would misattribute "
        "the defect"
    )


@needs_gate
def test_g11_abstains_for_a_checker_naming_a_different_identity(tmp_path):
    """Control: a genuinely different checker is not the author.

    Pins that G11 is a specific-identity rule, not a rule that refuses anything
    with a model name in it.
    """
    author = {"kind": "model-agent", "role": "orchestrator-synthesizer",
              "model": "grok-4.1"}
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9,
                       checker="claude-opus-4.5 specification-analyst, re-fetched"),
        author=author,
    )
    result = _evaluate(tmp_path)
    assert GATE.G11_SELF_CHECKED not in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_g11_abstains_when_the_author_names_nobody(tmp_path):
    """Control: a generic author identity is not an identity to match against."""
    assert GATE.checker_is_author(
        {"kind": "model-agent", "role": "synthesizer"}, ["model-agent, read the RFC"]
    ) == (False, [])


@needs_gate
def test_g11_does_not_match_on_free_text_prose():
    """Control: prose is not identity; only identifier-shaped tokens are."""
    self_checked, tokens = GATE.checker_is_author(
        {"kind": "model-agent", "role": "orchestrator-synthesizer", "model": "grok-4.1"},
        ["grok-4.1, independently re-fetched and read the cited clause"],
    )
    assert self_checked is True
    assert tokens == ["grok-4.1"]


# ==========================================================================
# 6b. G10 -- an unprobeable stub quotation under `verdict: confirmed`
# ==========================================================================


@needs_gate
@pytest.mark.parametrize(
    "quoted",
    [
        "",                                # nothing to probe (G7 territory)
        "definite lengths",                # 2 words
        "RFC 9052 section 9 says",         # 5 words
        "checked; present; confirmed",     # looks like a report, quotes nothing
    ],
    ids=["empty", "two-words", "mentions-section", "status-words"],
)
def test_confirmed_over_a_stub_quotation_is_refused(tmp_path, quoted):
    """Attack 6b.  ``verdict: confirmed`` over text too short to locate.

    A quotation this short can be located in or ruled out of no clause, so the
    record demonstrates no retrieval at all.  ``verdict: confirmed`` over it is
    self-reporting, and self-reporting is what F1 is.

    Which rule fires depends on how degenerate the stub is: G7 owns a record
    whose ``quoted`` field is empty outright, and G10 owns a non-empty stub
    that is merely below the probe floor. Both are refusals; what matters is
    that neither is allowed through.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9", quoted))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    expected = (
        GATE.G7_INCOMPLETE_RECORD if not quoted.strip() else GATE.G10_UNPROBED_QUOTE
    )
    assert expected in _rules(result), [r.detail for r in result.reasons]


@needs_gate
@pytest.mark.parametrize(
    "quoted",
    [
        "the keys in every map must be sorted",   # exactly 8 words: at the floor
        GENUINE_9052_SEC9,
    ],
    ids=["at-the-floor", "genuine"],
)
def test_probeability_control(quoted):
    """The control: at-floor and genuine quotations are probeable."""
    assert GATE.quote_is_probeable(quoted)


@needs_gate
@pytest.mark.parametrize(
    "quoted",
    ["", "decrement max_path_length", "RFC 9052 section 9 says"],
    ids=["empty", "three-words", "five-words"],
)
def test_probeability_threshold(quoted):
    """The boundary itself: text below the probe floor cannot be located."""
    assert not GATE.quote_is_probeable(quoted)


@needs_gate
def test_an_ellipsis_padded_stub_is_still_refused_as_a_stub(tmp_path):
    """Attack 6b, obfuscated: a stub dressed up with ellipses and fragments.

    Both probe decompositions the gate uses -- the ellipsis split and the
    sentence split -- keep only chunks of at least 8 words, so a quoted string
    padded with ellipses and one-word fragments yields no probeable unit at all.
    ``verdict: confirmed`` over it still demonstrates no retrieval.
    """
    stub = "yes ... no ... ok ... confirmed ... checked ... done ... pass"
    assert not GATE.quote_is_probeable(stub), (
        "control: this stub is below the probe floor and must not be probeable"
    )
    _finding(tmp_path, record=_record("RFC 9052 section 9", stub))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G10_UNPROBED_QUOTE in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_an_ellipsis_joined_genuine_quotation_is_probeable(tmp_path):
    """Control for the split above: eliding across genuine text stays probeable.

    A real quotation that joins two passages of one section with an ellipsis must
    not be refused, or the gate would reject faithful quotations.  This is why
    ``_best_ratio`` takes the maximum over both decompositions.
    """
    elided = (
        "This document limits the restrictions it imposes on how the CBOR "
        "Encoder needs to work. ... Encoding MUST be done using definite "
        "lengths, and the length of the (encoded) argument MUST be the minimum "
        "possible length."
    )
    assert GATE.quote_is_probeable(elided), (
        "control: an ellipsis-joined quotation of genuine text must stay probeable"
    )


# ==========================================================================
# 6c. G9 -- an invented section number
# ==========================================================================


@needs_gate
def test_invented_section_number_is_refused(tmp_path):
    """Attack 6c.  A section the source does not contain cannot have been read."""
    _finding(tmp_path, record=_record("RFC 9052 section 9.7.13", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G9_SECTION_ABSENT in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_invented_section_is_refused_even_when_the_quotation_is_genuine(tmp_path):
    """Attack 6c, sharpest: real quote, invented clause.

    The quotation is genuine RFC 9052 text and would be located if the cited
    section were the right one.  Only the section number is a lie, which is
    exactly the situation a checker who quoted a remembered passage and guessed
    the clause is in.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 42.13.9", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G9_SECTION_ABSENT in _rules(result)


@needs_gate
def test_existing_subsection_is_not_an_invented_section(tmp_path):
    """Control: ``4.1`` exists, so citing it is not an invented-section error."""
    _finding(tmp_path, record=_record("RFC 9052 section 4.1", "Reserved for future use"))
    assert GATE.G9_SECTION_ABSENT not in _rules(_evaluate(tmp_path))


@needs_gate
def test_parent_of_a_parsed_subsection_is_accepted(tmp_path):
    """Control: citing ``4`` when only ``4.1`` was parsed is not an error."""
    _finding(tmp_path, record=_record("RFC 9052 section 4", GENUINE_9052_SEC9))
    assert GATE.G9_SECTION_ABSENT not in _rules(_evaluate(tmp_path))


@needs_gate
def test_g9_is_unverifiable_not_refused_when_the_document_is_absent(tmp_path):
    """A source that could not be read is UNVERIFIABLE, never a manufactured refusal.

    A network outage is not a defect in the artifact.  Pinning this keeps G9 from
    being over-read as "the gate knows the section does not exist" when in fact
    the gate only knows it could not check.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9.7.13", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path, store=_store({}))
    assert result.decision == GATE.ALLOW
    assert GATE.G9_SECTION_ABSENT not in _rules(result)


# ==========================================================================
# 6d. G2/G3 -- a fabricated quotation, and a real one in the wrong section
# ==========================================================================


@needs_gate
def test_fabricated_quotation_is_refused(tmp_path):
    """Attack 6d.  A quotation that exists in no RFC 9052 section at all.

    This is the ``fnd-2026-0014`` shape: text attributed to a source that does
    not contain it, with ``verdict: confirmed`` and every provenance field
    present.  The gate must compare the quotation to the source rather than
    believing the verdict.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9", SPLICE_8952_421),
             claim=SPLICE_8952_421)
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G2_NOT_IN_SOURCE in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_entirely_invented_quotation_is_refused(tmp_path):
    """Attack 6d, no real text anywhere: a wholly fabricated passage.

    Not a splice of genuine text from the wrong place, but prose that exists in
    no RFC 9052 section.  The gate can only refute it, not locate it.
    """
    invented = (
        "Every conforming CBOR Encoder shall order the keys of a map by their "
        "encoded length alone, and shall discard any map key whose encoding is "
        "not itself the shortest possible representation of the integer it names."
    )
    _finding(tmp_path, record=_record("RFC 9052 section 9", invented), claim=invented)
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G2_NOT_IN_SOURCE in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_genuine_quotation_attributed_to_the_wrong_section_is_refused(tmp_path):
    """Attack 6d, right document / wrong clause.

    Every word is real RFC 9052 text.  Only the section is wrong.  This is the
    class a document-level "does this RFC contain it" check cannot see, and it
    is the class that actually produced ``fnd-2026-0014``.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9", RFC_9052_SEC3))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G3_MISATTRIBUTED in _rules(result), [r.detail for r in result.reasons]


@needs_gate
@pytest.mark.parametrize(
    "checker",
    [
        "independent-checker",
        "independent-checker, read from the fetched rfc9052.txt",
        {"kind": "human", "identity": "independent-checker"},
    ],
    ids=["bare", "prose", "dict"],
)
def test_verdict_confirmed_does_not_buy_a_fabricated_quotation(tmp_path, checker):
    """Attack 6d against every spelling of an honest-looking checker.

    The refusal must come from comparing the quotation to the source, so it
    must not depend on how the checker field happens to be written.
    """
    _finding(tmp_path,
             record=_record("RFC 9052 section 9", SPLICE_8952_421, checker=checker),
             claim=SPLICE_8952_421)
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G2_NOT_IN_SOURCE in _rules(result)


# ==========================================================================
# 6e. G7/G8 -- incomplete or non-confirming records under assertive statuses
# ==========================================================================


@needs_gate
@pytest.mark.parametrize(
    "field",
    ["source", "quoted", "checked_at", "checker", "verdict", "section"],
)
def test_a_record_missing_a_required_provenance_field_is_refused(tmp_path, field):
    """Attack 6e.  Every required field of a check record is load-bearing.

    A record missing one field is not a check with a gap; it is a claim that
    something was checked, with the part that would make it checkable absent.
    """
    record = _record("RFC 9052 section 9", GENUINE_9052_SEC9)
    record.pop(field)
    _finding(tmp_path, record=record)
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, (
        f"removing {field!r} did not cause a refusal: "
        f"{[r.detail for r in result.reasons]}"
    )


@needs_gate
@pytest.mark.parametrize(
    "verdict",
    ["misattributed", "not-found", "absent", "refuted", "inconclusive", "unchecked"],
)
def test_a_record_that_did_not_confirm_is_refused(tmp_path, verdict):
    """Attack 6e.  A check that reported anything but a confirmation refuses.

    Including the checker saying "inconclusive" or "unchecked": the artifact
    knows it did not establish the claim, and promoting it anyway is the defect.
    """
    _finding(tmp_path,
             record=_record("RFC 9052 section 9", GENUINE_9052_SEC9, verdict=verdict))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, (
        f"verdict={verdict!r} did not cause a refusal"
    )
    assert GATE.G8_VERDICT_NOT_CONFIRMED in _rules(result), [
        r.detail for r in result.reasons
    ]


@needs_gate
def test_a_normative_checks_block_that_is_not_a_list_is_refused(tmp_path):
    """Attack 6e, structural: a malformed ``normative_checks`` is a defect.

    A mapping instead of a list is the shape a hand-edited or template-generated
    YAML file takes.  It must be reported, not skipped: silently ignoring it
    turns a malformed record into an absent one.
    """
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9),
        doc_overrides={"normative_checks": {"NC-1": "not a list"}},
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G7_INCOMPLETE_RECORD in _rules(result), [r.detail for r in result.reasons]


@needs_gate
@pytest.mark.parametrize("entry", ["not a mapping", 42, None])
def test_a_non_mapping_check_entry_is_refused(tmp_path, entry):
    """Attack 6e: a list entry that is not a check record is a defect, not a gap."""
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9),
        doc_overrides={"normative_checks": [entry]},
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G7_INCOMPLETE_RECORD in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_a_live_normative_claim_with_no_record_at_all_is_refused(tmp_path):
    """Attack 6e at the top: nobody recorded re-checking anything.

    The artifact asserts a quotation against a clause and records nothing about
    checking it.  Full provenance, full review chain, still refuses.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9", GENUINE_9052_SEC9),
             doc_overrides={"normative_checks": []})
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G1_NO_CHECK in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_a_stale_check_is_refused(tmp_path):
    """Attack 6e: freshness.  A check older than the window discharges nothing."""
    _finding(
        tmp_path,
        record=_record(
            "RFC 9052 section 9", GENUINE_9052_SEC9,
            checked_at=(TODAY - timedelta(days=400)).isoformat(),
        ),
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G4_STALE_CHECK in _rules(result), [r.detail for r in result.reasons]


@needs_gate
def test_an_unparsable_check_date_is_refused(tmp_path):
    """Attack 6e: a date nobody can read is not a date.

    ``checked_at: "recently"`` is the shape an artifact gets when a field is
    filled in from memory.  It must refuse rather than treat freshness as
    established by default.
    """
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9,
                       checked_at="recently, definitely"),
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G4_STALE_CHECK in _rules(result), [r.detail for r in result.reasons]


# ==========================================================================
# 6f. Obfuscation -- the gate must not be defeated by cosmetics
# ==========================================================================


@needs_gate
@pytest.mark.parametrize(
    "quoted",
    [
        SPLICE_8952_421.lower(),                      # case-folded
        "  " + SPLICE_8952_421 + "\n\n",               # whitespace padded
        SPLICE_8952_421.replace("MUST", "MUST"),      # identical, spelling out the tactic
        "".join(SPLICE_8952_421),                      # no-op control
    ],
    ids=["lowercased", "whitespace-padded", "identical", "noop"],
)
def test_obfuscating_a_fabricated_quotation_does_not_help_it(tmp_path, quoted):
    """Attack 6f.  Trivial obfuscation must not buy a fabricated quotation a pass.

    ``_normalize_text`` lower-cases and collapses whitespace before matching, so
    case and padding are already neutralised by design.  This pins that the
    neutralisation is not an accident that can be undone by an obfuscator, and
    that the same input in a different spelling produces the same refusal.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9", quoted), claim=quoted)
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G2_NOT_IN_SOURCE in _rules(result), [r.detail for r in result.reasons]


@needs_gate
@pytest.mark.xfail(
    strict=True,
    reason="DEFECT tools/promotion_gate.py _is_retracted_path: retraction is decided "
           "by a key-path SUBSTRING test, not by the presence of a marked retraction "
           "block. A key ending in '_original' is exempt from G1 and from clause "
           "location entirely, so naming a live normative claim "
           "'rfc_9052_section_9_original' -- e.g. to record what the artifact "
           "originally cited -- silently removes it from every check",
)
def test_a_live_claim_disguised_as_a_retraction_is_still_checked(tmp_path):
    """Attack 6f, the one that works: name your live claim ``*_original``.

    The corpus convention is that a *retracted* quotation is preserved under
    ``correction_*`` / ``*_original`` keys and is deliberately not re-litigated.
    That exemption is granted on the key's spelling alone, so an author who
    merely records "what the artifact originally cited" loses the claim from G1
    and from clause location with nothing else changed.  The gate then ALLOWs an
    artifact carrying an unchecked live normative claim.
    """
    disguised = "rfc_9052_section_9_original"
    _finding(tmp_path, record=_record("RFC 9052 section 9", GENUINE_9052_SEC9),
             key=disguised, doc_overrides={"status": "verified_conclusion"})
    result = _evaluate(tmp_path)
    assert result.claims_seen > 0, (
        f"the live claim under {disguised!r} was treated as retracted and never "
        "examined; the field carries no retraction marker and no correction block"
    )
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]


@needs_gate
def test_control_a_genuinely_retracted_claim_is_not_re_litigated(tmp_path):
    """Control: a real retraction is not re-litigated.

    ``fnd-2026-0014`` keeps its retracted quotation under ``*_original`` keys as
    preserved evidence of the error.  Re-checking that text on every run would be
    noise, and would also make the gate report a defect that is already recorded
    and corrected.
    """
    _finding(
        tmp_path,
        record=_record("RFC 9052 section 9", GENUINE_9052_SEC9),
        key="correction_2026_10_02_rfc_9052_section_9",
        claim=SPLICE_8952_421,
    )
    result = _evaluate(tmp_path)
    assert result.claims_seen == 0, (
        "a genuinely retracted claim should not be re-litigated: "
        f"claims_seen={result.claims_seen}"
    )


@needs_gate
def test_retracted_text_needs_a_real_marker_not_just_a_suspicious_key(tmp_path):
    """Control for the attack above: what makes a retraction a retraction.

    The convention that earns the exemption is a key the gate can recognise as a
    correction, plus a recorded retraction.  Pinned so the exemption is not
    widened further by any future change to the substring test.
    """
    doc = {
        "id": "fnd-2026-9201",
        "type": "finding",
        "status": "verified_conclusion",
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z",
        "summary": "test finding",
        "epistemic_status": "verified_conclusion",
        "classification": "spec-violation",
        "provenance": {"created_by": {"kind": "model-agent",
                                     "role": "specification-analyst"}},
        "links": {"reviews": ["rev-2026-9201"]},
        "normative_basis": {"rfc_9052_section_9": GENUINE_9052_SEC9},
        "correction_note": {
            "text": (
                "As previously quoted, the RFC 9052 section 9 text was believed to "
                "say something about ordering map keys by length alone; it does not."
            )
        },
        "normative_checks": [
            _record("RFC 9052 section 9", GENUINE_9052_SEC9)
        ],
    }
    (tmp_path / "knowledge/findings").mkdir(parents=True, exist_ok=True)
    (tmp_path / "knowledge/reviews").mkdir(parents=True, exist_ok=True)
    (tmp_path / "knowledge/reviews/rev-2026-9201.yaml").write_text(
        yaml.safe_dump(SUPPORT_REVIEW, sort_keys=False), encoding="utf-8"
    )
    (tmp_path / "knowledge/findings/fnd-2026-9201.yaml").write_text(
        yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.ALLOW, [r.detail for r in result.reasons]


# ==========================================================================
# 6g. The gate's own selftest must stay green
# ==========================================================================


@needs_gate
def test_tool_selftest_passes():
    """The tool's regression suite must stay green under this attack set."""
    assert GATE.run_selftest(online=False) == GATE.EXIT_ALLOW
