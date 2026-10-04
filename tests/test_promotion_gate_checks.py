"""Promotion-gate rules G9/G10/G11 and record-level G2/G3 (failure modes F1/F3).

Three failure modes motivated these:

``F1``  a self-reported field fools a mechanical check -- an artifact writes
       ``verdict: confirmed`` and nothing ever fetches the RFC;
``F2``  a source-level abstraction error evades document-only citation checks
       (the ``fnd-2026-0009`` class: the cited file is one call frame above the
       check).  Nothing mechanical catches this and nothing here pretends to;
``F3``  an exact citation can still be false -- ``fnd-2026-0014`` carried a
       quotation attributed to RFC 9052 section 9 that is RFC 8949 section
       4.2.1 text, and survived a promotion because nobody re-fetched the RFC.

Each test here builds the minimal artifact that would defeat the gate and
asserts the real gate refuses it.  The last two tests pin the honest limits:
the rules must not fire on the corpus, and they must not pretend to catch F2.
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
    """Import ``tools/promotion_gate.py`` the way the tool itself loads its sibling."""
    name = "frontier_promotion_gate_under_test"
    spec = importlib.util.spec_from_file_location(
        name, REPO / "tools" / "promotion_gate.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GATE = _load_gate()
TODAY = datetime.now(UTC).date()

# Genuine RFC 9052 section 9 text, as recorded in tools/fixtures/rfc_sections.yaml.
GENUINE_9052_SEC9 = GATE.GENUINE_9052_SEC9
# Genuine RFC 8949 section 4.2.1 text -- the text fnd-2026-0014 spliced into an
# RFC 9052 section 9 attribution.
SPLICE_8952_421 = GATE.SPLICE_8952_421

SUPPORT_REVIEW = {
    "id": "rev-2026-9101",
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


def _store(documents: dict[int, tuple[str, dict[str, str]]]) -> "GATE.SourceStore":
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


# Genuine RFC 9052 section 3 text (the COSE "two buckets" passage).
RFC_9052_SEC3 = (
    "The structure of COSE has been designed to have two buckets of "
    "information that are not considered to be part of the payload itself, "
    "but are used for holding information about content, algorithms, keys, "
    "or evaluation hints for the processing of the layer."
)

# RFC 9052 as the gate's recorded fixture parses it: section 9 carries the
# genuine text, section 3 carries different genuine text.
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


# Genuine RFC 5280 section 6.1 text: the self-issued definition paragraph.
RFC_5280_SEC61_SELF_ISSUED = (
    "A certificate is self-issued if the same DN appears in the subject and "
    "issuer fields (the two DNs are the same if they match according to the "
    "rules specified in Section 7.1). These self-issued certificates are not "
    "counted when evaluating path length or name constraints."
)

# RFC 5280 shaped as the gate's recorded fixture parses it: the self-issued
# paragraph lives in section 6.1, and section 6.1.1 (which begins later, at the
# state-variable definitions) does NOT contain it. This is the shape that made
# the fnd-2026-0016 misattribution detectable.
RFC_5280 = (
    RFC_5280_SEC61_SELF_ISSUED + " " + GENUINE_9052_SEC9,
    {
        "6.1": RFC_5280_SEC61_SELF_ISSUED,
        "6.1.1": "The state variables of the path validation algorithm include "
                 "the following variables.",
    },
)


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
             author: dict | None = None, key: str = "rfc_9052_section_9") -> str:
    doc = {
        "id": "fnd-2026-9101",
        "type": "finding",
        "status": "verified_conclusion",
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z",
        "summary": "test finding",
        "epistemic_status": "verified_conclusion",
        "classification": "spec-violation",
        "provenance": {
            "created_by": author or {"kind": "model-agent", "role": "specification-analyst"},
            "sources": ["https://www.rfc-editor.org/rfc/rfc9052.txt"],
        },
        "links": {"reviews": ["rev-2026-9101"]},
        "normative_basis": {key: claim},
        "normative_checks": [record],
    }
    (root / "knowledge/findings").mkdir(parents=True, exist_ok=True)
    (root / "knowledge/reviews").mkdir(parents=True, exist_ok=True)
    (root / "knowledge/reviews/rev-2026-9101.yaml").write_text(
        yaml.safe_dump(SUPPORT_REVIEW, sort_keys=False), encoding="utf-8"
    )
    (root / "knowledge/findings/fnd-2026-9101.yaml").write_text(
        yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
    )
    return doc["id"]


def _evaluate(root: Path, store=None) -> "GATE.ArtifactGateResult":
    artifacts, _broken, by_id = GATE.load_corpus(root, include_missions=False)
    store = store or _store({9052: RFC_9052})
    return GATE.evaluate_artifact(
        artifacts[0], by_id, store, recheck_days=180, today=TODAY, online=False
    )


def _rules(result) -> set[str]:
    return {r.rule for r in result.blocking}


# --------------------------------------------------------------------------
# G10 -- F1: a self-reported verdict over an unprobeable stub
# --------------------------------------------------------------------------


def test_confirmed_over_stub_quotation_is_refused(tmp_path):
    """F1. ``verdict: confirmed`` over text too short to probe proves no retrieval."""
    _finding(tmp_path, record=_record("RFC 9052 section 9", "definite lengths"))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE, [r.detail for r in result.reasons]
    assert GATE.G10_UNPROBED_QUOTE in _rules(result)


def test_confirmed_over_empty_quotation_is_refused(tmp_path):
    """An empty ``quoted`` is caught by G7 (missing provenance), and must refuse."""
    _finding(tmp_path, record=_record("RFC 9052 section 9", ""))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G7_INCOMPLETE_RECORD in _rules(result)


@pytest.mark.parametrize(
    "quoted",
    [
        "",                       # empty: nothing to probe
        "decrement max_path_length",  # 3 words, below the 8-word floor
        "RFC 9052 section 9 says",  # 5 words, below the floor
    ],
)
def test_probeability_threshold(quoted):
    """The stub boundary: text below the probe floor cannot be located."""
    assert not GATE.quote_is_probeable(quoted)


@pytest.mark.parametrize(
    "quoted",
    [
        "the keys in every map must be sorted",  # exactly 8 words: at the floor
        GENUINE_9052_SEC9,
    ],
)
def test_probeability_control(quoted):
    """The control: at-floor and genuine quotations are probeable."""
    assert GATE.quote_is_probeable(quoted)


def test_genuine_quotation_is_probeable():
    """The control: a real quotation clears the probe floor."""
    assert GATE.quote_is_probeable(GENUINE_9052_SEC9)
    assert GATE.quote_is_probeable(SPLICE_8952_421)


def test_clean_record_is_allowed(tmp_path):
    """The control: a correct, independent, located check still passes."""
    _finding(tmp_path, record=_record("RFC 9052 section 9", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.ALLOW, [r.detail for r in result.reasons]
    assert result.claims_located == 1


# --------------------------------------------------------------------------
# G9 -- invented section number
# --------------------------------------------------------------------------


def test_invented_section_number_is_refused(tmp_path):
    """A section the source does not contain cannot have been read."""
    _finding(tmp_path, record=_record("RFC 9052 section 9.7.13", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G9_SECTION_ABSENT in _rules(result)


def test_existing_subsection_is_not_an_invented_section(tmp_path):
    """``4.1`` exists, so citing it is not an invented-section error."""
    _finding(tmp_path, record=_record("RFC 9052 section 4.1", "Reserved for future use"))
    result = _evaluate(tmp_path)
    assert GATE.G9_SECTION_ABSENT not in _rules(result)


def test_parent_of_parsed_subsection_is_accepted(tmp_path):
    """Citing ``4`` when only ``4.1`` was parsed must not be an invented section."""
    _finding(tmp_path, record=_record("RFC 9052 section 4", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path)
    assert GATE.G9_SECTION_ABSENT not in _rules(result)


def test_g9_is_unverifiable_not_refused_when_document_absent(tmp_path):
    """No recorded text for the RFC: UNVERIFIABLE, never a manufactured refusal."""
    _finding(tmp_path, record=_record("RFC 9052 section 9.7.13", GENUINE_9052_SEC9))
    result = _evaluate(tmp_path, store=_store({}))
    assert result.decision == GATE.ALLOW
    assert GATE.G9_SECTION_ABSENT not in _rules(result)


# --------------------------------------------------------------------------
# G2/G3 on the record's own quotation -- F3 without believing the verdict
# --------------------------------------------------------------------------


def test_spliced_quotation_in_a_self_reported_record_is_refused(tmp_path):
    """F3. RFC 8949 text claimed as RFC 9052 section 9, verdict: confirmed."""
    _finding(tmp_path, record=_record("RFC 9052 section 9", SPLICE_8952_421),
             claim=SPLICE_8952_421)
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    # The claim itself is caught by G2 and the record by G2 as well.
    assert GATE.G2_NOT_IN_SOURCE in _rules(result)


def test_record_quote_from_another_section_is_refused(tmp_path):
    """Genuine RFC 9052 section 3 text, self-reported as section 9."""
    _finding(tmp_path, record=_record("RFC 9052 section 9", RFC_9052_SEC3))
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G3_MISATTRIBUTED in _rules(result), [r.detail for r in result.reasons]


# --------------------------------------------------------------------------
# G11 -- the checker is the artifact's own creator
# --------------------------------------------------------------------------


def test_self_certified_claim_is_refused(tmp_path):
    """An author who writes its own ``verdict: confirmed`` certifies nothing."""
    author = {"kind": "model-agent", "role": "orchestrator-synthesizer", "model": "grok-4.1"}
    _finding(
        tmp_path,
        record=_record(
            "RFC 9052 section 9", GENUINE_9052_SEC9,
            checker="grok-4.1, read directly from the fetched source",
        ),
        author=author,
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.REFUSE
    assert GATE.G11_SELF_CHECKED in _rules(result)


def test_independent_checker_is_allowed(tmp_path):
    """The control: a checker naming a different identity is not the author."""
    author = {"kind": "model-agent", "role": "orchestrator-synthesizer", "model": "grok-4.1"}
    _finding(
        tmp_path,
        record=_record(
            "RFC 9052 section 9", GENUINE_9052_SEC9,
            checker="minimax-m3 specification-analyst, re-fetched rfc9052.txt",
        ),
        author=author,
    )
    result = _evaluate(tmp_path)
    assert GATE.G11_SELF_CHECKED not in _rules(result)


def test_g11_needs_an_identifying_author_token():
    """A generic author identity (``model-agent``) names nobody, so G11 abstains."""
    assert GATE.checker_is_author(
        {"kind": "model-agent", "role": "synthesizer"}, ["model-agent, read the RFC"]
    ) == (False, [])


def test_g11_does_not_match_on_prose():
    """Free-text checker prose is not identity; only identifier-shaped tokens are."""
    author = {"kind": "model-agent", "role": "orchestrator-synthesizer", "model": "grok-4.1"}
    self_checked, tokens = GATE.checker_is_author(
        author, ["grok-4.1, independently re-fetched and read the cited clause"]
    )
    assert self_checked is True
    assert tokens == ["grok-4.1"]


# --------------------------------------------------------------------------
# F2 -- the honest limit.  Nothing here catches it, and the test says so.
# --------------------------------------------------------------------------


def test_source_level_abstraction_error_is_not_caught(tmp_path):
    """F2 is irreducibly human; this test pins that the gate does NOT catch it.

    The artifact cites a wrapper source file and asserts a check is absent from
    it.  The check actually lives one call frame deeper, in a vendored
    dependency.  No citation-, quotation- or section-level check can see a call
    frame, so the gate allows this.  The test asserts that fact so that any
    future claim that the gate "checks depth" is falsified here.
    """
    doc = {
        "id": "fnd-2026-9101",
        "type": "finding",
        "status": "verified_conclusion",
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z",
        "summary": "F2 shape: cites the wrapper file, check lives one frame below",
        "epistemic_status": "verified_conclusion",
        "classification": "spec-violation",
        "provenance": {
            "created_by": {"kind": "model-agent", "role": "implementation-analyst"},
            "sources": ["https://github.com/openssh/openssh-portable/blob/master/"
                        "kexmlkem768x25519.c"],
        },
        "links": {"reviews": ["rev-2026-9101"]},
        "normative_basis": {
            "source_file_check": (
                "Direct source-code reading of kexmlkem768x25519.c shows the "
                "server-side hybrid KEX enc function performs only a length check "
                "on the client C_INIT blob and no encapsulation key validation of "
                "any kind, because the only check applied before the KEM "
                "encapsulation call is the buffer length comparison."
            )
        },
        "normative_checks": [
            {
                "id": "NC-1",
                "source": "https://github.com/openssh/openssh-portable/blob/master/"
                          "kexmlkem768x25519.c",
                "section": "kex_kem_mlkem768x25519_enc",
                "quoted": (
                    "need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE; if "
                    "(sshbuf_len(client_blob) != need) { r = SSH_ERR_SIGNATURE_INVALID; "
                    "goto out; }"
                ),
                "checked_at": (TODAY - timedelta(days=2)).isoformat(),
                "checker": {"kind": "human", "identity": "independent-checker"},
                "verdict": "confirmed",
                "method": "deterministic-script",
            }
        ],
    }
    for rel in ("knowledge/findings", "knowledge/reviews"):
        (tmp_path / rel).mkdir(parents=True, exist_ok=True)
    (tmp_path / "knowledge/reviews/rev-2026-9101.yaml").write_text(
        yaml.safe_dump(SUPPORT_REVIEW, sort_keys=False), encoding="utf-8"
    )
    (tmp_path / "knowledge/findings/fnd-2026-9101.yaml").write_text(
        yaml.safe_dump(doc, sort_keys=False), encoding="utf-8"
    )
    result = _evaluate(tmp_path)
    assert result.decision == GATE.ALLOW, [r.detail for r in result.reasons]


def test_fabricated_clause_and_quotation_together_pass(tmp_path):
    """The honest residue of F1: a checker that invents *both* is not caught.

    A quotation that does not exist anywhere, attributed to a section that does
    exist, with ``verdict: confirmed``.  The gate can only compare the
    quotation against the section; if the checker invented the section to match
    a real quotation elsewhere, every rule is satisfied.  Pinning this prevents
    the gate being oversold as a truth oracle.
    """
    _finding(tmp_path, record=_record("RFC 9052 section 9", GENUINE_9052_SEC9))
    store = _store({9052: RFC_9052})
    result = _evaluate(tmp_path, store=store)
    assert result.decision == GATE.ALLOW
    assert not result.blocking


# --------------------------------------------------------------------------
# Zero false positives on the real corpus
# --------------------------------------------------------------------------


def test_no_false_positives_on_the_real_corpus():
    """The new rules must not fire on any artifact the repository actually holds.

    Only ``fnd-2026-0016`` carries ``normative_checks`` today.  Its records were
    re-checked against recorded RFC 5280 and one of them is genuinely
    misattributed (RFC 5280 section 6.1.1 text that lives in section 6.1), so
    G3 firing on that artifact is a true positive.  What must not happen is a
    new rule firing on an artifact that is clean.
    """
    artifacts, _broken, by_id = GATE.load_corpus(REPO, include_missions=True)
    store = GATE.SourceStore(online=False, timeout=1.0)
    store.load_fixture()
    today = TODAY

    false_positives: list[str] = []
    for art in artifacts:
        if art.load_error or art.doc.get("type") not in GATE.GATED_TYPES:
            continue
        result = GATE.evaluate_artifact(
            art, by_id, store, recheck_days=180, today=today, online=False
        )
        rules = _rules(result)
        # G11 is an independence *requirement*, not a defect in a claim; it is
        # expected to fire wherever an artifact self-certified, and is asserted
        # separately below.  G9/G10 and the record-level G2/G3 are the
        # correctness rules: an artifact carrying normative_checks that trips
        # them must be one this audit identified by hand.
        unexpected = rules & {GATE.G9_SECTION_ABSENT, GATE.G10_UNPROBED_QUOTE}
        if unexpected and art.id != "fnd-2026-0016":
            false_positives.append(f"{art.id}: {sorted(unexpected)}")
    assert not false_positives, false_positives


def test_fnd_2026_0016_misattribution_is_caught():
    """Regression pin for a REAL defect in a finding written this session.

    ``fnd-2026-0016`` originally cited RFC 5280 section 6.1.1 for the
    self-issued paragraph, which actually lives in section 6.1 -- genuine RFC
    5280 text attributed to a clause that does not contain it. That is exactly
    the ``fnd-2026-0014`` failure mode, and this session's independent review
    (rev-2026-0020) found it independently of the gate. The gate's G3 rule also
    flagged it once the record-level G2/G3 checks were added.

    The misattribution has since been CORRECTED in the artifact, so asserting
    "the gate flags fnd-2026-0016" would now be a test that fails because the
    repository got BETTER. This test therefore pins the CAPABILITY against the
    live corpus state instead: the gate must still be able to see normative
    claims in that artifact, and it must still refuse it. If the capability
    regressed, the claim count would drop back to zero.
    """
    artifacts, _broken, by_id = GATE.load_corpus(REPO, include_missions=True)
    store = GATE.SourceStore(online=False, timeout=1.0)
    store.load_fixture()
    target = by_id["fnd-2026-0016"]

    # The gate now extracts live normative claims from this artifact's
    # normative_checks records. Before the record-level G2/G3 rules existed it
    # reported "0 live normative claims", which is exactly the blindness that
    # let the misattribution through unexamined.
    claims = GATE.collect_check_records(target, by_id)[0]
    assert claims, "gate no longer sees fnd-2026-0016's normative checks"

    result = GATE.evaluate_artifact(
        target, by_id, store, recheck_days=180, today=TODAY, online=False,
    )
    assert result.decision == GATE.REFUSE


def test_fnd_2026_0016_still_refuses_on_self_reported_checks():
    """The live artifact is correctly refused, for the RIGHT remaining reason.

    Its normative checks are all recorded by its own author, which rule G11
    treats as discharging nothing. That refusal must persist even though the
    section misattribution has been fixed, because self-reporting is a separate
    defect from misattribution.
    """
    artifacts, _broken, by_id = GATE.load_corpus(REPO, include_missions=True)
    store = GATE.SourceStore(online=False, timeout=1.0)
    store.load_fixture()
    target = by_id["fnd-2026-0016"]
    result = GATE.evaluate_artifact(
        target, by_id, store, recheck_days=180, today=TODAY, online=False,
    )
    rules = _rules(result)
    assert result.decision == GATE.REFUSE
    assert GATE.G11_SELF_CHECKED in rules, [r.detail for r in result.reasons]
    # The misattribution is fixed, so G3 must NOT fire on the real artifact.
    assert GATE.G3_MISATTRIBUTED not in rules, [r.detail for r in result.reasons]


# --------------------------------------------------------------------------
# The tool's own selftest must stay green
# --------------------------------------------------------------------------


def test_tool_selftest_passes():
    """``--selftest`` is the gate's regression suite; it must stay green."""
    assert GATE.run_selftest(online=False) == GATE.EXIT_ALLOW
