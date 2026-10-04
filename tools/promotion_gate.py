#!/usr/bin/env python3
"""Promotion gate: may this artifact be promoted to ``verified``?

The rule this enforces, stated by the human on 2026-10-03:

    A normative claim cannot be promoted unless the exact cited
    specification clause has been independently checked against the
    authoritative source during verification.

Two real failures motivated it.  ``fnd-2026-0014`` carried a quotation
presented as RFC 9052 section 9 that does not exist in RFC 9052 -- the
map-key-sorting sentence was RFC 8949 section 4.2.1 text spliced into an
RFC 9052 attribution.  It survived two correction passes and a promotion
because every session re-checked the measurement and nobody re-fetched the
RFC.  ``spc-2026-0004`` carries fabricated RFC 8949 section 4.2.1
quotations, and its ``map_key_sort`` axis is defined against section 4.2.3.

What this gate is for
---------------------
``tools/verify_citations.py`` extracts quotations and can tell whether a
quote appears *somewhere* in the cited RFC.  It cannot tell whether the
quote is from the right *section*, and it has no notion of whether anybody
re-fetched the source before a promotion.  This module adds both, plus the
record-keeping that makes the check auditable.

Provenance mechanism
--------------------
The repo already has a place for this and this tool uses it rather than
inventing a parallel schema.

*Primary*: a ``verification`` artifact (``vrf-*``) linked in the promoted
artifact's ``links.verifications``, carrying a ``normative_checks`` block.
``vrf-*`` artifacts already carry free-form sub-blocks (``verification_steps``,
``byte_evidence_chain``, ``promotion_decision`` in ``vrf-2026-0016``), so a
``normative_checks`` block is idiomatic.  ``method`` must stay inside
``frontier.validate.VERIFICATION_METHODS``; ``deterministic-script`` is
correct here because the check *is* a deterministic script run against the
fetched source, and using it means the gate needs no change to
``src/frontier/validate.py`` or to ``localdocs/schemas/verification.schema.json``.

*Secondary (inline)*: a ``normative_checks`` block directly on the artifact.
Specifications are not on the promotion ladder -- ``spc-*`` artifacts carry no
``links.verifications`` and are not required to by ``_validate_finding`` -- so
for them the inline block is the natural home.  Both spellings are read.

Each check record carries: the source URL, the section/clause, the fetch date,
the checker identity, the method, and the verdict.

Rules
-----
``G1`` no recorded normative check for a normative claim           REFUSE
``G2`` a normative quotation is not in its cited source section    REFUSE (online)
``G3`` a normative quotation is attributed to a source that does
      not contain it (found in another cited source)               REFUSE (online)
``G4`` normative text not re-checked within the window             REFUSE
``G5`` no independent review linked                                REFUSE
``G6`` every linked review is disputes/inconclusive                REFUSE
``G7`` a check record is missing required provenance fields         REFUSE
``G8`` a recorded verdict is not a confirmation                     REFUSE

``G2``/``G3`` need the source bytes.  Without them they degrade to
``UNVERIFIABLE`` and never block: a network outage is not a defect.
The offline rules (G1, G4-G8) refuse on their own, because a missing or stale
provenance record is a defect whether or not the network is up.

``G9``/``G10``/``G11`` exist because a ``verdict: confirmed`` written into a
YAML field is a *claim about a check*, not the check.  They reduce failure mode
F1 (self-reported fields fooling mechanical checks) to the residue that is
actually mechanical:

* ``G10`` refuses a confirmed verdict whose ``quoted`` text is too short to
  locate in or rule out of any clause -- a stub quotation demonstrates no
  retrieval;
* ``G9`` refuses a confirmed verdict citing a section the source does not
  contain -- an invented section number cannot have been read;
* ``G2``/``G3`` applied to the record's own ``quoted`` text refuse a
  self-reported confirmation whose quotation is absent from, or belongs to a
  different section than, the one it names.  This is the fnd-2026-0014 class
  checked without believing the verdict;
* ``G11`` refuses a normative claim whose only recorded checker is the
  artifact's own creator.

What none of them can do is establish that the checker actually read the
source.  A model that invents a quotation *and* the clause it lives in passes
every rule here.  That residue is irreducibly human and is named as such in
``docs`` below and in ``docs/gate_limits.md``.

Exit codes: ``0`` allow, ``1`` refuse, ``2`` tool error.  Network failure alone
never produces ``1``.

Hard limits, stated up front
----------------------------
This gate checks *attribution*: that text attributed to a clause is text of
that clause.  It cannot check *depth*: whether a source citation points one
abstraction layer too shallow.  ``fnd-2026-0009`` cited
``kexmlkem768x25519.c`` when the FIPS 203 section 7.2 check lived one call
frame below in vendored ``libcrux-mlkem-mldsa.c``.  Nothing mechanical catches
that, and nothing here pretends to.  See ``docs`` in the report.

Residue that no rule here can close
-----------------------------------
A checker that invents both the quotation *and* the clause it appears in is
consistent with every rule in this file: the invented section will be one that
exists, the invented quote will be one that appears in it, and ``verdict`` is
whatever the checker wrote.  The gate's reach is therefore bounded by the
honesty of the independent checker, which is why ``G5``/``G6``/``G11`` exist
and why ``AGENTS.md`` requires the independent review to be a non-synthesizer
role.  Automated checking can prove a claim was checked; it cannot prove the
checker read anything.

Usage::

    tools/promotion_gate.py --finding fnd-2026-0014 [--online] [--json]
    tools/promotion_gate.py [--all] [--strict] [--recheck-days N]
    tools/promotion_gate.py --selftest [--selftest-network]
    tools/promotion_gate.py --record-fixtures
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

TOOL_NAME = "promotion_gate"
TOOL_VERSION = "1.0.0"

EXIT_ALLOW = 0
EXIT_REFUSE = 1
EXIT_ERROR = 2

DEFAULT_RECHECK_DAYS = 180

# Artifact statuses that assert a conclusion has been established.  These are
# the artifacts whose promotion this gate is ratifying, so they are what the
# corpus exit code is driven by.
ASSERTIVE_STATUSES = frozenset(
    {
        "verified",
        "verified_conclusion",
        "pass",
        "supported",
        "support",
        "reproduced",
        "complete",
        "final",
        "proved",
    }
)

# Spec-violation classifications: a finding so classified asserts a
# normative claim by definition, even when no RFC token is in the string.
SPEC_VIOLATION_CLASSES = frozenset(
    {
        "spec-violation",
        "spec_violation",
        "specification-violation",
        "spec-violation-draft",
        "implementation-spec-mismatch",
        "spec-ambiguity",
    }
)


# --------------------------------------------------------------------------
# Reuse verify_citations rather than duplicating its fetch/normalise logic
# --------------------------------------------------------------------------


def _load_sibling(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
VERIFY = _load_sibling("frontier_verify_citations", HERE / "verify_citations.py")

Artifact = VERIFY.Artifact
walk_strings = VERIFY.walk_strings
extract_urls = VERIFY.extract_urls
_find_rfc_body = VERIFY._find_rfc_body
_normalize_text = VERIFY._normalize_text
_truncate = VERIFY._truncate
_quote_probe_sentences = VERIFY._quote_probe_sentences

FIXTURE_PATH = HERE / "fixtures" / "rfc_sections.yaml"


# --------------------------------------------------------------------------
# Rule identifiers and verdicts
# --------------------------------------------------------------------------

G1_NO_CHECK = "G1_no_normative_check"
G2_NOT_IN_SOURCE = "G2_quote_not_in_cited_source"
G3_MISATTRIBUTED = "G3_quote_attributed_to_source_lacking_it"
G4_STALE_CHECK = "G4_normative_check_stale"
G5_NO_REVIEW = "G5_no_independent_review"
G6_REVIEWS_DISPUTE = "G6_all_reviews_dispute"
G7_INCOMPLETE_RECORD = "G7_incomplete_check_record"
G8_VERDICT_NOT_CONFIRMED = "G8_verdict_not_confirmed"
G9_SECTION_ABSENT = "G9_cited_section_absent"
G10_UNPROBED_QUOTE = "G10_check_quotes_nothing_probeable"
G11_SELF_CHECKED = "G11_checker_is_the_author"

RULE_TITLES = {
    G1_NO_CHECK: "normative claim has no recorded independent source check",
    G2_NOT_IN_SOURCE: "normative quotation not located in its cited source",
    G3_MISATTRIBUTED: "normative quotation attributed to a source that does not contain it",
    G4_STALE_CHECK: "normative text not re-checked within the window",
    G5_NO_REVIEW: "no independent review linked",
    G6_REVIEWS_DISPUTE: "every linked review disputes or is inconclusive",
    G7_INCOMPLETE_RECORD: "normative check record is missing required provenance",
    G8_VERDICT_NOT_CONFIRMED: "a recorded normative check did not confirm",
    G9_SECTION_ABSENT: "a normative check cites a section the source does not contain",
    G10_UNPROBED_QUOTE: "a normative check quotes too little text to be probeable",
    G11_SELF_CHECKED: "the only checker of a normative claim is its own author",
}

# ``G9`` needs the source's section table, which is available offline from the
# recorded fixture -- unlike ``G2``/``G3``, which need the body text.  A fixture
# that does not hold the document degrades this rule to UNVERIFIABLE.
RULE_ONLINE_REQUIRED = frozenset({G2_NOT_IN_SOURCE, G3_MISATTRIBUTED})

# Fraction of quoted units that must appear verbatim in the cited section.
# Mirrors the 0.6 sentence quorum verify_citations already uses, so the two
# tools do not disagree about the same quotation on a technicality.
LOCATE_QUORUM = 0.6

CONFIRMED_VERDICTS = frozenset({"confirmed", "verified", "pass", "supported", "match", "located"})
MISATTRIBUTED_VERDICTS = frozenset({"misattributed", "not-found", "notfound", "absent", "refuted"})
UNVERIFIABLE_VERDICTS = frozenset(
    {"unverifiable", "unknown", "inconclusive", "unchecked", "partial"}
)

# Review verdicts that count as support for the surviving claim.  The corpus is
# not uniform -- ``support`` and ``supports`` both appear, as do the qualified
# ``SUPPORT_WITH_MAGNITUDE_CORRECTION`` and ``PARTIAL_SUPPORT`` forms -- so the
# vocabulary is matched by prefix rather than by exact string.  Review
# *statuses* vary the same way (``complete`` / ``completed``).
SUPPORTING_REVIEW_VERDICTS = ("support", "affirm", "confirm", "endorse", "accept")
DISPUTING_REVIEW_VERDICTS = ("dispute", "refute", "reject", "inconclusive", "disprov")
REVIEW_COMPLETE_STATUSES = frozenset({"complete", "completed"})

# Artifact types that assert a normative claim of their own and are therefore
# in the gate's scope.  ``finding`` and ``specification`` make claims; the
# other evidence types (experiment, observation, reproducer, ...) *support*
# claims and are not promoted themselves, so gating them would punish the
# evidence chain for the claimant's missing check.  ``report`` is included: it
# is a synthesis product that can carry a normative claim of its own.
GATED_TYPES = frozenset({"finding", "specification", "report"})

ALLOW = "ALLOW"
REFUSE = "REFUSE"
NA = "NOT-APPLICABLE"
UNVERIFIABLE = "UNVERIFIABLE"


# --------------------------------------------------------------------------
# Normative claim extraction
# --------------------------------------------------------------------------

# ``RFC 9052 section 9`` / ``RFC 9052 §9`` / ``FIPS 203 §7.2`` /
# ``draft-ietf-sshm-mlkem-hybrid-kex-10 s2.1``
SPEC_CITATION_RE = re.compile(
    r"(?P<doc>rfc\s*(?P<rfc>\d{3,5})|fips\s*(?P<fips>\d{3})|"
    r"draft-[a-z0-9.-]*-[a-z0-9-]+\d*)"
    r"[^\w]{0,6}"
    r"(?:§{1,2}\s*|section\s+|sec(?:tion)?\.?\s+|s\s*)"
    r"(?P<sec>\d+(?:\.\d+)*)",
    re.IGNORECASE,
)
RFC_NUMBER_RE = re.compile(r"\brfc[\s-]*(\d{3,5})\b", re.IGNORECASE)

NORMATIVE_KEY_RE = re.compile(
    r"normative|rule_ref|spec_text|quoted_text|clause|excerpt|quote",
    re.IGNORECASE,
)

MUST_KEYWORDS = frozenset(
    {"must", "must not", "shall", "should", "required", "requires", "requirement", "m须"}
)

QUOTE_MIN_WORDS = 25

# Field names that store specification text, as opposed to fields that merely
# discuss it.  ``fnd-2026-0014.normative_basis.rfc_9052_section_9`` and
# ``spc-2026-0004.normative_extract`` qualify; ``summary`` and ``notes`` do
# not, because a correction that says "RFC 9052 section 9 does not contain
# this" would otherwise be reported as a misquotation of RFC 9052 section 9.
_QUOTE_KEY_RE = re.compile(
    r"normative|extract|rule_ref|quote|quoted|clause|spec_text|excerpt|"
    r"verbatim|as_previously_quoted|original",
    re.IGNORECASE,
)

# Quotation intent expressed in the string itself: an explicit claim that the
# text IS what the source says.
_QUOTE_INTENT_RE = re.compile(
    r"(?:^|[\s\"'(])(?:says|states|reads|specifies|requires|provides|"
    r"quoted|quotation|verbatim|wording|text\s+is|is\s+quoted)(?:\b)",
    re.IGNORECASE,
)


def _is_retracted_path(path: Sequence[str]) -> bool:
    """True when a field sits under a retracted / corrected-away block.

    The corpus convention (see ``fnd-2026-0014``) keeps a retracted quotation
    verbatim under ``*_original`` keys and under ``correction_*`` blocks.  That
    text is deliberately preserved as evidence of the error; it must not be
    re-litigated as a live normative claim, and the repo's own convention is
    that it is marked.  ``verify_citations`` already flags unmarked
    retractions; this gate only declines to *require* a live check for them.
    """
    for element in path:
        text = str(element)
        low = text.lower()
        if low.startswith("correction"):
            return True
        if low.endswith("_original") or low.endswith("_as_previously_quoted"):
            return True
        if any(
            marker in low
            for marker in ("retract", "as_previously_quoted", "superseded_text", "do_not_cite")
        ):
            return True
    return False


@dataclass
class Locator:
    """Which clause of which document a claim is attributed to."""

    rfc_number: int | None
    section: str | None
    text: str

    def display(self) -> str:
        if self.rfc_number and self.section:
            return f"RFC {self.rfc_number} section {self.section}"
        if self.rfc_number:
            return f"RFC {self.rfc_number}"
        return self.text


def _parse_locator(token: str) -> Locator:
    match = SPEC_CITATION_RE.search(token)
    if match:
        if match.group("rfc"):
            return Locator(int(match.group("rfc")), match.group("sec"), token.strip())
        return Locator(None, match.group("sec"), token.strip())
    number = RFC_NUMBER_RE.search(token)
    if number:
        return Locator(int(number.group(1)), None, token.strip())
    return Locator(None, None, token.strip())


# ``rfc_9052_section_9`` -> RFC 9052 section 9.  This is the spelling the real
# corpus uses (fnd-2026-0014's normative_basis keys, spc-2026-0005's axes), so
# resolving it from the key is what makes the gate see those citations at all.
_KEY_LOCATOR_RE = re.compile(
    r"(?P<doc>rfc|fips|draft)[\s_-]*(?P<num>\d{3,5})"
    r"(?:[\s_-]*(?:section|sec|s|clause)[\s_-]*)?"
    r"(?P<sec>\d+(?:\.\d+)*)?"
    r"(?:_section_(?P<sec2>\d+(?:\.\d+)*))?",
    re.IGNORECASE,
)
_SECTION_NUM_RE = re.compile(
    r"(?:^|[\s_-])(?:section|sec|s|clause|§{1,2})[\s_-]*(\d+(?:\.\d+)*)",
    re.IGNORECASE,
)


def _locator_from_path(path: Sequence[str]) -> tuple[Locator | None, bool]:
    """Resolve a clause locator from a field's key path.

    Returns ``(locator, from_key)``.  Walks the path from the innermost key
    outwards so a specific key beats a general one.
    """
    for element in reversed(list(path)):
        text = str(element)
        if not re.search(r"rfc|fips|draft|section|clause|§", text, re.IGNORECASE):
            continue
        match = _KEY_LOCATOR_RE.search(text)
        if match:
            number = match.group("num")
            section = match.group("sec2") or match.group("sec")
            doc = match.group("doc").lower()
            if doc == "rfc":
                return Locator(int(number), section, f"RFC {number} section {section}"
                               if section else f"RFC {number}"), True
            return Locator(None, section, f"{doc.upper()} {number} section {section}"
                           if section else f"{doc.upper()} {number}"), True
        section_only = _SECTION_NUM_RE.search(text)
        if section_only:
            return Locator(None, section_only.group(1), f"section {section_only.group(1)}"), True
    return None, False


@dataclass
class NormativeClaim:
    """A sentence the artifact asserts is what some specification says."""

    claim_id: str
    field_path: str
    text: str
    source_hint: str = ""
    rfc_number: int | None = None
    section: str | None = None
    retracted: bool = False
    locator_found: bool = False
    locator_from_key: bool = False

    @property
    def display_locator(self) -> str:
        if self.rfc_number and self.section:
            return f"RFC {self.rfc_number} section {self.section}"
        if self.source_hint:
            return self.source_hint
        return "<unlocated claim>"


def _classify_spec_violation(doc: dict[str, Any]) -> bool:
    classification = doc.get("classification")
    if isinstance(classification, str):
        return classification.strip().lower().replace(" ", "-") in SPEC_VIOLATION_CLASSES
    if isinstance(classification, dict):
        primary = classification.get("primary")
        if isinstance(primary, str):
            low = primary.lower()
            return "spec_violation" in low or "spec-violation" in low
    return False


def _has_spec_citation(text: str) -> bool:
    return bool(SPEC_CITATION_RE.search(text))


def extract_normative_claims(art: Artifact) -> list[NormativeClaim]:
    """Find text the artifact asserts is specification text.

    A claim is a stretch of prose attributed to a *clause*, and attribution
    comes from two places:

    * the field's key path -- ``normative_basis.rfc_9052_section_9`` names the
      clause, which is how the corpus actually records most citations; or
    * the value itself, which is split into segments at each citation so a
      multi-clause extract is checked clause by clause.

    In both cases the text must show *quotation intent*: it sits under a
    quotation field (``normative_extract``, ``rule_ref``, ``normative_basis``,
    ``*_original``) or the string says it is what the source says.  Without
    that test, a correction reading "RFC 9052 section 9 does not contain this"
    would be reported as a misquotation of RFC 9052 section 9.

    Retracted text (``correction_*``, ``*_original``) is deliberately excluded:
    it is preserved evidence of a past error, already policed by
    ``verify_citations``, and re-litigating it on every run is noise.
    """
    claims: list[NormativeClaim] = []
    counter = 0
    for path, value in walk_strings(art.doc):
        retracted = _is_retracted_path(path)
        long_enough = len(value.split()) >= QUOTE_MIN_WORDS
        if not long_enough:
            continue
        # Retracted text is preserved evidence of the error, not a live claim
        # to re-litigate; verify_citations already polices that it is marked.
        if retracted:
            continue

        # The citation is usually in the *field name*, not the value:
        # ``normative_basis.rfc_9052_section_9``,
        # ``audit_axes[].rule_ref: "RFC 9052 §9"``.  So the locator is
        # resolved from the key first, then from the value.
        key_locator, from_key = _locator_from_path(path)

        if from_key:
            # The key names the clause, so text under it is attributed to that
            # clause.  Whether it contains "MUST" is irrelevant: the citation
            # itself is the claim.  This is what makes a right-document /
            # wrong-section error visible at all.
            #
            # But the key must actually be a *quotation* field.  A key like
            # ``summary`` or ``rationale`` carries the artifact talking about
            # a clause -- "RFC 9052 section 9 does not contain this" -- and
            # checking that prose against the RFC would flag the gate's own
            # description of an error as a misquotation.  The whole key path is
            # consulted, not just the leaf, because the corpus nests the
            # locator under a quotation field
            # (``normative_basis.rfc_9052_section_9``).
            quote_field = any(_QUOTE_KEY_RE.search(str(part)) for part in path)
            if not (quote_field or _QUOTE_INTENT_RE.search(value)):
                continue
            counter += 1
            claims.append(
                NormativeClaim(
                    claim_id=f"{art.id}#NC{counter}",
                    field_path=".".join(path),
                    text=value,
                    source_hint=key_locator.text,
                    rfc_number=key_locator.rfc_number,
                    section=key_locator.section,
                    locator_from_key=True,
                )
            )
            continue

        # No clause in the key: attribute each sentence to the citation it
        # sits nearest under, so a block that names several clauses is checked
        # against the right one instead of the first one mentioned.
        counter = _claims_from_text(art, path, value, claims, counter)
    return claims


def _claims_from_text(
    art: Artifact,
    path: Sequence[str],
    value: str,
    claims: list[NormativeClaim],
    counter: int,
) -> int:
    """Attribute each sentence of ``value`` to the citation it sits nearest.

    A normative extract looks like this (spc-2026-0005)::

        RFC 9052 §9 (CBOR Encoding):
          Integers MUST use shortest form.
        RFC 9338 §3.3 (Countersign_structure):
          Countersign_structure = [ ... ]

    Checking the whole block against the first citation mentioned would
    misattribute every later clause.  So the text is split into segments at
    each citation, and each segment is checked against the citation that
    introduces it.
    """
    matches = list(SPEC_CITATION_RE.finditer(value))
    if not matches:
        return counter
    # Prose that merely names a clause is not a quotation of it.  The
    # introducing citation must read as quotation intent ("RFC 9052 §9
    # (CBOR Encoding): Integers MUST ...") or the enclosing field must be a
    # quotation field, otherwise a correction explaining that a clause was
    # misquoted is itself reported as a misquotation.
    quote_field = bool(_QUOTE_KEY_RE.search(str(path[-1])))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
        segment = value[start:end].strip()
        if len(segment.split()) < 8:
            continue
        lead = value[match.end() : match.end() + 80]
        if not (quote_field or _QUOTE_INTENT_RE.search(lead)):
            continue
        locator = _parse_locator(match.group(0))
        counter += 1
        claims.append(
            NormativeClaim(
                claim_id=f"{art.id}#NC{counter}",
                field_path=".".join(path),
                text=segment,
                source_hint=locator.text,
                rfc_number=locator.rfc_number,
                section=locator.section,
                locator_from_key=False,
            )
        )
    return counter


# --------------------------------------------------------------------------
# Check-record reading
# --------------------------------------------------------------------------

_SOURCE_KEYS = ("source", "source_url", "url", "citation", "document")
_SECTION_KEYS = ("section", "clause", "locator", "section_ref", "anchor")
_QUOTED_KEYS = ("quoted", "quotation", "quote", "text", "excerpt", "verbatim", "as_quoted")
_DATE_KEYS = ("checked_at", "checked_on", "fetch_date", "fetched_at", "date", "checked")
_CHECKER_KEYS = ("checker", "checked_by", "verifier", "by", "identity")
_VERDICT_KEYS = ("verdict", "result", "outcome")
_METHOD_KEYS = ("method", "check_method", "how")


def _first(doc: dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in doc and doc[key] not in (None, ""):
            return doc[key]
    return None


@dataclass
class CheckRecord:
    """One ``normative_checks`` entry, normalized."""

    raw: dict[str, Any]
    origin_id: str
    origin_kind: str  # 'inline' | artifact id
    check_id: str = ""
    source: str = ""
    section: str = ""
    quoted: str = ""
    checked_at: date | None = None
    checker: str = ""
    verdict: str = ""
    method: str = ""

    @property
    def rfc_number(self) -> int | None:
        match = RFC_NUMBER_RE.search(self.source) or RFC_NUMBER_RE.search(self.section)
        if match:
            return int(match.group(1))
        return None

    @property
    def section_number(self) -> str | None:
        match = SPEC_CITATION_RE.search(self.section) or SPEC_CITATION_RE.search(self.source)
        if match:
            return match.group("sec")
        if re.fullmatch(r"\d+(?:\.\d+)*", self.section.strip()):
            return self.section.strip()
        return None

    def missing_fields(self) -> list[str]:
        missing = []
        if not self.source:
            missing.append("source")
        if not self.quoted:
            missing.append("quoted")
        if self.checked_at is None:
            missing.append("checked_at")
        if not self.checker:
            missing.append("checker")
        if not self.verdict:
            missing.append("verdict")
        if self.rfc_number is not None and not self.section_number:
            missing.append("section")
        return missing


def _normalize_checker(value: Any) -> str:
    if isinstance(value, dict):
        parts = [
            str(value[key])
            for key in ("kind", "role", "model", "tool", "identity", "name")
            if value.get(key)
        ]
        return "; ".join(parts)
    return str(value) if value else ""


# Minimum quoted words for a ``quoted`` field to be *probeable* against a source.
# Mirrors ``_split_ellipsis`` (8 words) with margin, so a check that merely
# quotes a fragment like "decrement max_path_length" -- which cannot be located
# in or ruled out of any section with confidence -- is refused rather than
# credited as an independent check.  A record whose ``quoted`` is too short (or
# whose every sentence is too short to probe) has demonstrated no retrieval:
# G10 exists so ``verdict: confirmed`` cannot be self-reported over a stub.
QUOTE_PROBE_MIN_WORDS = 8


def quote_is_probeable(quoted: str) -> bool:
    """True when ``quoted`` carries enough text for a locate probe to mean anything.

    Mirrors the probe decompositions ``_best_ratio`` uses: a whole-string
    match only counts if it is at least ``QUOTE_PROBE_MIN_WORDS`` long, or if
    the ellipsis/sentence splits yield at least one probeable unit.

    The whole-string count is taken over the ellipsis-fragment REMOVED text.
    Counting the fragments inflated it: ``"yes ... no ... ok ... confirmed
    ... checked ... done ... pass"`` is nine whitespace-separated tokens and so
    passed the floor as a bare word count, while ``_split_ellipsis`` returned
    no unit for it (every chunk is a single word). An artifact could therefore
    satisfy G10 with seven one-word fragments and no quotation at all.
    Verified 2026-10-05: such a record was ALLOWED end-to-end before this fix.
    """
    text = (quoted or "").strip()
    if not text:
        return False
    if len(_strip_ellipsis(text).split()) >= QUOTE_PROBE_MIN_WORDS:
        return True
    return bool(_split_ellipsis(text)) or bool(VERIFY._quote_probe_sentences(text))


# --------------------------------------------------------------------------
# G11: the checker must not be the artifact's own author
# --------------------------------------------------------------------------

# Only *structural* identity fields are compared.  ``checker`` in the wild is
# free text ("orchestrator (grok-4.1), read directly from the fetched source"),
# so token-matching the whole string would fire on ordinary English words like
# "directly" or "independent".  An explicit model/tool/name disagreement is a
# real signal; prose is not.
_IDENTITY_KEYS = ("kind", "model", "tool", "name", "identity")
_IDENTITY_TOKEN_RE = re.compile(r"[a-z0-9_.\-]+")

# Values that name a *kind* of actor rather than a particular one.  ``kind:
# model-agent`` is the corpus default on almost every artifact, so treating it
# as an identity would make G11 fire on artifacts whose author never claimed to
# be a distinct checker.
_GENERIC_IDENTITY_TOKENS = frozenset(
    {
        "model", "agent", "tool", "kind", "name", "identity", "none", "null",
        "human", "agentic", "modelagent", "orchestrator", "synthesizer",
        "model-agent", "model_agent", "deterministic-tool", "tooling",
    }
)


def _identity_tokens(value: Any) -> set[str]:
    """Identifying tokens for a ``provenance.created_by`` mapping.

    Only explicit ``kind``/``model``/``tool``/``name``/``identity`` fields are
    used.  ``role`` is excluded: the corpus writes it descriptively
    ("orchestrator-synthesizer") and the same role word turns up in unrelated
    checkers, so matching on it would accuse artifacts their authors did not
    write.  Generic values (``model-agent``, ``human``) are excluded because
    they identify nobody.
    """
    if not isinstance(value, dict):
        return set()
    tokens: set[str] = set()
    for key in _IDENTITY_KEYS:
        raw = value.get(key)
        if not raw:
            continue
        tokens.update(
            t for t in _IDENTITY_TOKEN_RE.findall(str(raw).lower())
            if len(t) >= 4 and t not in _GENERIC_IDENTITY_TOKENS
        )
    return tokens


# An identifier-shaped token: contains a digit, a dot or a hyphen.  Checkers in
# the corpus are free text ("orchestrator (grok-4.1), read directly from the
# fetched source"), so prose words carry no identity and must not be compared.
# A dot or a digit is required -- a bare hyphenated English word ("re-fetched")
# is prose, not an identifier.
_IDENTIFIER_LIKE_RE = re.compile(r"^(?=.*[\d.])[a-z0-9_.\-]+$")


def _checker_identifiers(checker: Any) -> set[str]:
    """Identifier-shaped tokens of a checker, structured or free text."""
    if isinstance(checker, dict):
        return _identity_tokens(checker)
    return {
        t for t in _IDENTITY_TOKEN_RE.findall(str(checker or "").lower())
        if _IDENTIFIER_LIKE_RE.match(t)
    }


def checker_is_author(
    author: Any, checkers: Sequence[Any]
) -> tuple[bool, list[str]]:
    """Is every recorded checker the artifact's own creator?

    Returns ``(self_checked, matching_tokens)``.

    A check is treated as self-certified when the checker names an identity the
    author already holds and names *nothing else* -- i.e. every
    identifier-shaped token the checker carries is one the author also carries.
    Prose in a free-text checker ("read directly from the fetched source") is
    not identifier-shaped and so is ignored; a checker that names a different
    model or tool introduces a token the author does not have and is therefore
    treated as a different checker.

    This is a deliberately weak check.  It catches the gross case -- one agent
    writing ``verdict: confirmed`` about its own quotation while naming itself
    -- and nothing subtler.  Two different models of the same vendor, or an
    honest author, both pass.  It is not a proof of independence and is not
    claimed to be.
    """
    author_tokens = _identity_tokens(author)
    if not author_tokens:
        return False, []
    checked = [t for c in checkers if (t := _checker_identifiers(c))]
    if not checked:
        return False, []
    for tokens in checked:
        if not tokens <= author_tokens:
            return False, []
    return True, sorted({t for tokens in checked for t in tokens})


def parse_check_record(raw: Any, origin_id: str, origin_kind: str) -> CheckRecord | None:
    if not isinstance(raw, dict):
        return None
    checked = _first(raw, _DATE_KEYS)
    return CheckRecord(
        raw=raw,
        origin_id=origin_id,
        origin_kind=origin_kind,
        check_id=str(_first(raw, ("id", "check_id")) or ""),
        source=str(_first(raw, _SOURCE_KEYS) or ""),
        section=str(_first(raw, _SECTION_KEYS) or ""),
        quoted=str(_first(raw, _QUOTED_KEYS) or ""),
        checked_at=VERIFY._parse_date(str(checked) if checked else None),
        checker=_normalize_checker(_first(raw, _CHECKER_KEYS)),
        verdict=str(_first(raw, _VERDICT_KEYS) or "").strip().lower(),
        method=str(_first(raw, _METHOD_KEYS) or "").strip().lower(),
    )


def collect_check_records(
    art: Artifact, by_id: dict[str, Artifact]
) -> tuple[list[CheckRecord], list[str]]:
    """Read the artifact's ``normative_checks`` from both accepted spellings."""
    records: list[CheckRecord] = []
    problems: list[str] = []

    inline = art.doc.get("normative_checks")
    if inline is not None and not isinstance(inline, list):
        problems.append(f"{art.id}: normative_checks must be a list, got {type(inline).__name__}")
        inline = None
    for entry in inline or []:
        record = parse_check_record(entry, art.id, "inline")
        if record is None:
            problems.append(f"{art.id}: normative_checks entry is not a mapping: {entry!r}")
        else:
            records.append(record)

    for ref in _iter_links(art, "verifications"):
        linked = by_id.get(ref)
        if linked is None:
            continue
        block = linked.doc.get("normative_checks")
        if not isinstance(block, list):
            continue
        for entry in block:
            record = parse_check_record(entry, ref, "verification")
            if record is None:
                problems.append(f"{ref}: normative_checks entry is not a mapping: {entry!r}")
            else:
                records.append(record)
    return records, problems


def _iter_links(art: Artifact, key: str) -> Iterator[str]:
    links = art.doc.get("links")
    if not isinstance(links, dict):
        return
    for value in links.get(key) or []:
        if isinstance(value, str) and value:
            yield value


# --------------------------------------------------------------------------
# Source store: live fetch, or the recorded offline fixture
# --------------------------------------------------------------------------


@dataclass
class Section:
    number: str
    text: str


@dataclass
class RfcDocument:
    number: int
    url: str
    full_text: str
    sections: dict[str, str] = field(default_factory=dict)
    origin: str = "live"

    def section_text(self, number: str | None) -> str | None:
        if not number:
            return None
        if number in self.sections:
            return self.sections[number]
        # Tolerate a citation of a subsection when only the parent is present,
        # and vice versa: 4.2.1 is inside 4.2.
        for key, text in self.sections.items():
            if number == key or number.startswith(key + ".") or key.startswith(number + "."):
                return text
        return None

    @property
    def section_numbers(self) -> list[str]:
        return sorted(self.sections)


_RFC_HEADING_RE = re.compile(r"^(\d+(?:\.\d+)*)\.\s\s+\S", re.M)
# RFC plain text: the table of contents occupies the first few thousand bytes
# and repeats every heading.  Body headings start at column 0.
_TOC_BODY_OFFSET = 6000


def parse_rfc_sections(body: str) -> dict[str, str]:
    """Split an RFC plain-text body into section-number -> text.

    ``verify_citations`` explicitly could not do this: it checked a quote
    appeared *somewhere* in the RFC.  Body headings in RFC plain text sit at
    column 0 and start with the section number; the table of contents indents
    them, so dropping everything before the first body heading also drops the
    TOC.  A section runs until the next heading that is neither itself nor one
    of its subsections, so a quote in 4.2.1 is found under both 4.2 and 4.2.1.
    """
    marks = [
        (m.group(1), m.start())
        for m in _RFC_HEADING_RE.finditer(body)
        if m.start() > _TOC_BODY_OFFSET
    ]
    if not marks:
        return {}
    sections: dict[str, str] = {}
    for index, (number, start) in enumerate(marks):
        end = len(body)
        for later_number, later_start in marks[index + 1:]:
            if later_number == number or later_number.startswith(number + "."):
                continue
            end = later_start
            break
        sections[number] = body[start:end]
    return sections


class SourceStore:
    """RFC text, from the network or from the recorded fixture.

    The fixture exists so ``--selftest`` is deterministic and needs no
    network.  It is a *recording* of real authoritative text, not a mock: each
    entry records the URL it came from, the fetch date, and the SHA-256 of the
    whole body.  Under ``--online`` the live body is used and the recorded hash
    is re-checked, so a fixture that has drifted from the real RFC is reported
    rather than trusted.
    """

    def __init__(self, online: bool, timeout: float, cache_dir: Path | None = None):
        self.online = online
        self.timeout = timeout
        self.cache_dir = cache_dir
        self._live: dict[int, RfcDocument | None] = {}
        self._fixture: dict[int, RfcDocument] | None = None
        self.fixture_meta: dict[int, dict[str, Any]] = {}
        self.provenance_notes: list[str] = []

    # -- fixture -----------------------------------------------------------

    def load_fixture(self) -> None:
        if self._fixture is not None:
            return
        self._fixture = {}
        if not FIXTURE_PATH.is_file():
            self.provenance_notes.append(
                f"no recorded fixture at {FIXTURE_PATH}; offline section checks "
                "will be UNVERIFIABLE"
            )
            return
        data = yaml.safe_load(FIXTURE_PATH.read_text(encoding="utf-8")) or {}
        for entry in data.get("sources") or []:
            number = int(entry["rfc"])
            sections = {
                str(k): str(v) for k, v in (entry.get("sections") or {}).items()
            }
            self._fixture[number] = RfcDocument(
                number=number,
                url=str(entry.get("url") or f"https://www.rfc-editor.org/rfc/rfc{number}.txt"),
                full_text=str(entry.get("full_text_normalized") or ""),
                sections={k: _normalize_text(v) for k, v in sections.items()},
                origin="fixture",
            )
            self.fixture_meta[number] = {
                "recorded_at": entry.get("recorded_at"),
                "body_sha256": entry.get("body_sha256"),
                "url": entry.get("url"),
            }
        self.provenance_notes.append(
            f"offline RFC text from recorded fixture {FIXTURE_PATH.name} "
            f"({len(self._fixture)} document(s)); recorded authoritative text, "
            "not a mock"
        )

    # -- access ------------------------------------------------------------

    def get(self, number: int) -> RfcDocument | None:
        if number in self._live:
            return self._live[number]
        document: RfcDocument | None = None
        if self.online:
            document = self._fetch_live(number)
        if document is None:
            self.load_fixture()
            document = (self._fixture or {}).get(number)
        self._live[number] = document
        return document

    def _fetch_live(self, number: int) -> RfcDocument | None:
        probe = _find_rfc_body(f"https://www.rfc-editor.org/rfc/rfc{number}", self.timeout)
        if probe.state != "reachable" or not probe.body:
            self.provenance_notes.append(
                f"RFC {number}: live fetch returned {probe.state}; falling back to "
                "recorded fixture or UNVERIFIABLE"
            )
            return None
        meta = self.fixture_meta.get(number) or {}
        if not meta:
            self.load_fixture()
            meta = self.fixture_meta.get(number) or {}
        recorded_hash = meta.get("body_sha256")
        if recorded_hash:
            live_hash = hashlib.sha256(probe.body.encode("utf-8")).hexdigest()
            if live_hash != recorded_hash:
                # Not fatal: the live text is authoritative.  But say so,
                # because a drifted fixture is exactly the failure this repo
                # exists to prevent.
                self.provenance_notes.append(
                    f"RFC {number}: live body SHA-256 {live_hash[:12]} differs from the "
                    f"recorded fixture {str(recorded_hash)[:12]}; using live text and "
                    "reporting the fixture as stale"
                )
        return RfcDocument(
            number=number,
            url=probe.url,
            full_text=_normalize_text(probe.body),
            sections={k: _normalize_text(v) for k, v in parse_rfc_sections(probe.body).items()},
            origin="live",
        )


# --------------------------------------------------------------------------
# Gate decisions
# --------------------------------------------------------------------------


@dataclass
class RuleOutcome:
    rule: str
    severity: str  # REFUSE | UNVERIFIABLE | INFO
    detail: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "title": RULE_TITLES.get(self.rule, self.rule),
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class ArtifactGateResult:
    artifact_id: str
    path: str
    status: str | None
    decision: str
    reasons: list[RuleOutcome] = field(default_factory=list)
    claims_seen: int = 0
    live_claims: int = 0
    claims_located: int = 0
    unverifiable: int = 0
    in_scope: bool = True
    # Claims whose locator was resolved but which cite a non-RFC source
    # (an I-D, FIPS PDF, or a source file).  These have no deterministic
    # section locator, so the gate can only demand a recorded human check.
    nonlocal_claims: int = 0

    @property
    def blocking(self) -> list[RuleOutcome]:
        return [r for r in self.reasons if r.severity == REFUSE]

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact_id,
            "path": self.path,
            "status": self.status,
            "decision": self.decision,
            "in_scope": self.in_scope,
            "claims_seen": self.claims_seen,
            "claims_live": self.live_claims,
            "claims_located_in_cited_section": self.claims_located,
            "claims_non_rfc_source": self.nonlocal_claims,
            "unverifiable": self.unverifiable,
            "reasons": [r.to_dict() for r in self.reasons],
        }


def _best_ratio(
    claim_units_source: tuple[str, Sequence[str]], haystack: str
) -> tuple[float | None, int, int]:
    """Best verbatim-match ratio of a claim's quoted text against ``haystack``.

    Quotation style varies, so two decompositions are tried and the better one
    wins:

    * ``ellipsis`` -- chunks split at ``...`` / ``…``, for a quotation that
      joins two passages from one section.  Necessary because a single probe
      unit spanning an elision can never match, and would make a faithful
      quotation look fabricated.
    * ``sentence`` -- the existing sentence split, for a quotation that runs
      several sentences together without an ellipsis.

    Taking the maximum is the conservative choice for a *gate*: it can only
    make a claim look better sourced, never worse, so it never manufactures a
    refusal.  It cannot manufacture a pass either, because the ratio still
    requires most units to be found verbatim in the cited section.
    """
    best = (0.0, 0, 0)
    for units in (_split_ellipsis(claim_units_source[0]), list(claim_units_source[1])):
        if not units:
            continue
        hits = sum(1 for unit in units if unit in haystack)
        ratio = hits / len(units)
        # "Better" means a higher ratio, but a decomposition that found
        # nothing still counts as a decomposition: total is the witness that a
        # probe was possible.  Comparing only the ratio would leave total at
        # 0 when every hit count is zero, which is indistinguishable from
        # "nothing to probe".
        if best[2] == 0 or ratio > best[0]:
            best = (ratio, hits, len(units))
    # No decomposition produced a probeable unit.  Returning 0.0 here would
    # make a caller that divides by it report "0/0 units found", which reads
    # as a fabricated quotation when the truth is that there was nothing to
    # check.  Signal that explicitly instead.
    return best if best[2] else (None, 0, 0)


def _strip_ellipsis(text: str) -> str:
    """``text`` with the ellipsis separators removed and fragments dropped.

    A whole-string word count must not be satisfiable by the fragments an
    ellipsis split would throw away, or the count stops measuring anything.
    """
    return " ".join(chunk for chunk in re.split(r"\.{3}|…", text) if chunk.strip(" \"'"))


def _split_ellipsis(text: str) -> list[str]:
    """Split at ellipses only, keeping each side long enough to probe."""
    units: list[str] = []
    for chunk in re.split(r"\.{3}|…", text):
        chunk = chunk.strip(" \"'")
        if len(chunk.split()) >= 8:
            units.append(chunk)
    return units


def locate_quoted_text(
    quoted: str, document: RfcDocument | None, section: str | None
) -> tuple[str, str]:
    """Locate a check record's ``quoted`` text, as ``(verdict, detail)``.

    Same verdict vocabulary as :func:`_locate`, but the haystack is chosen by
    the record rather than by a claim's key path.  This is what lets the gate
    test a record's own quotation instead of taking ``verdict: confirmed`` on
    trust (failure mode F1): a record that claims RFC 9052 section 9 and quotes
    text from section 4.2.1 is caught even though the record asserts it was
    confirmed.
    """
    units = (quoted, _quote_probe_sentences(quoted))
    if not quoted.strip():
        return "unverifiable", "empty quoted text"
    if document is None:
        return "unverifiable", "no text source for the cited document"

    section_text = document.section_text(section) if section else None
    if section_text is not None:
        ratio, hits, total = _best_ratio(units, section_text)
        if ratio is None:
            return "unverifiable", "quoted text has no probeable unit"
        if ratio >= LOCATE_QUORUM:
            return (
                "confirmed",
                f"{hits}/{total} quoted units found in RFC {document.number} "
                f"section {section} (text from {document.origin})",
            )
    elif not section:
        return "unverifiable", "record names a source but no section, so no clause to check"
    else:
        return (
            "unverifiable",
            f"RFC {document.number} has no parsed section {section}",
        )

    doc_ratio, doc_hits, doc_total = _best_ratio(units, document.full_text)
    if doc_ratio is None:
        return "unverifiable", "quoted text has no probeable unit"
    if doc_ratio >= LOCATE_QUORUM:
        where = _which_section(document, units)
        return (
            "in-section-elsewhere",
            f"{doc_hits}/{doc_total} quoted units are in RFC {document.number} "
            f"but not in section {section}; found in {where}",
        )
    return (
        "absent-from-all-cited",
        f"only {doc_hits}/{doc_total} quoted units occur anywhere in "
        f"RFC {document.number} ({document.origin})",
    )


def _locate(claim: NormativeClaim, store: SourceStore) -> tuple[str, str]:
    """Locate a claim's quoted text.  Returns ``(verdict, detail)``.

    ``verdict`` is one of ``confirmed`` / ``not-in-section`` /
    ``in-section-elsewhere`` / ``absent-from-all-cited`` / ``unverifiable``.
    """
    claim_units_source = (
        claim.text,
        _quote_probe_sentences(claim.text),
    )
    if not claim_units_source[0]:
        return "unverifiable", "empty claim text"

    cited = store.get(claim.rfc_number) if claim.rfc_number else None
    if claim.rfc_number and cited is None:
        return "unverifiable", f"RFC {claim.rfc_number} text unavailable (no text source)"

    if cited is not None:
        section_text = cited.section_text(claim.section)
        if section_text is not None:
            ratio, hits, total = _best_ratio(claim_units_source, section_text)
            if ratio is None:
                return (
                    "unverifiable",
                    "no quoted sentence long enough to probe against the cited "
                    "section; this is not a quotation check",
                )
            if ratio >= LOCATE_QUORUM:
                return (
                    "confirmed",
                    f"{hits}/{total} quoted units found in RFC {claim.rfc_number} "
                    f"section {claim.section} (text from {cited.origin})",
                )
            # Present in the RFC but not in the cited section?
            doc_ratio, doc_hits, doc_total = _best_ratio(claim_units_source, cited.full_text)
            if doc_ratio is not None and doc_ratio >= LOCATE_QUORUM:
                where = _which_section(cited, claim_units_source)
                return (
                    "in-section-elsewhere",
                    f"{doc_hits}/{doc_total} quoted units are in RFC "
                    f"{claim.rfc_number} but not in section {claim.section}; found in "
                    f"{where}",
                )
            if doc_ratio is None:
                return "unverifiable", "no quoted sentence long enough to probe"
            return (
                "absent-from-all-cited",
                f"only {doc_hits}/{doc_total} quoted units occur anywhere in "
                f"RFC {claim.rfc_number} ({cited.origin})",
            )
        if not claim.section:
            return "unverifiable", "claim names an RFC but no section, so no clause to check"
        return "unverifiable", f"RFC {claim.rfc_number} has no parsed section {claim.section}"

    # Non-RFC source (draft, FIPS, source file): no deterministic section
    # locator.  A human or a recorded check must carry this one.
    return "unverifiable", f"non-RFC source {claim.source_hint!r}: no deterministic section locator"


def _which_section(document: RfcDocument, claim_units_source: tuple[str, Sequence[str]]) -> str:
    """Name the section that actually carries a misattributed quotation."""
    for number in document.section_numbers:
        ratio, hits, total = _best_ratio(claim_units_source, document.sections[number])
        if ratio is not None and ratio >= LOCATE_QUORUM:
            return f"section {number} ({hits}/{total} quoted units)"
    return "no single section"


def evaluate_artifact(
    art: Artifact,
    by_id: dict[str, Artifact],
    store: SourceStore,
    *,
    recheck_days: int,
    today: date,
    online: bool,
) -> ArtifactGateResult:
    result = ArtifactGateResult(
        artifact_id=art.id, path=art.rel, status=art.status, decision=ALLOW
    )

    # Only claim-making types are gated.  An experiment or observation is
    # evidence for someone else's claim; requiring it to carry a normative
    # check of its own would punish the evidence chain for the claimant's
    # omission, and would make the gate's report mostly noise.
    if art.doc.get("type") not in GATED_TYPES:
        result.decision = NA
        result.in_scope = False
        return result
    result.in_scope = True

    claims = extract_normative_claims(art)
    result.claims_seen = len(claims)
    live = [c for c in claims if not c.retracted]
    result.live_claims = len(live)

    records, problems = collect_check_records(art, by_id)
    for problem in problems:
        result.reasons.append(RuleOutcome(G7_INCOMPLETE_RECORD, REFUSE, problem))

    # ---- G7: record completeness -------------------------------------
    for record in records:
        missing = record.missing_fields()
        if missing:
            result.reasons.append(
                RuleOutcome(
                    G7_INCOMPLETE_RECORD,
                    REFUSE,
                    f"normative check {record.check_id or '<unnamed>'} from "
                    f"{record.origin_id} is missing required provenance: "
                    f"{', '.join(missing)}",
                    evidence=_truncate(str(record.raw), 200),
                )
            )

    # ---- G8: recorded verdicts ---------------------------------------
    for record in records:
        if record.missing_fields():
            continue  # already reported by G7
        verdict = record.verdict
        if verdict in CONFIRMED_VERDICTS:
            continue
        if verdict in MISATTRIBUTED_VERDICTS:
            severity, label = REFUSE, "the check itself did not find the text"
        elif verdict in UNVERIFIABLE_VERDICTS:
            severity, label = REFUSE, "the check did not confirm"
        elif not verdict:
            continue
        else:
            severity, label = REFUSE, f"unrecognised verdict {verdict!r}"
        result.reasons.append(
            RuleOutcome(
                G8_VERDICT_NOT_CONFIRMED,
                severity,
                f"normative check {record.check_id or '<unnamed>'} recorded "
                f"verdict={verdict!r} for {record.source}"
                f"{' section ' + record.section_number if record.section_number else ''}: "
                f"{label}",
                evidence=_truncate(record.quoted, 200),
            )
        )

    # ---- G10: a confirmed verdict over an unprobeable stub --------------
    # F1.  A record that quotes a fragment too short to locate in or rule out
    # of any section has demonstrated no retrieval, so ``verdict: confirmed``
    # over it is self-reporting and must not discharge the gate.
    for record in records:
        if record.missing_fields():
            continue  # already reported by G7 (an empty `quoted` is caught there)
        if record.verdict not in CONFIRMED_VERDICTS:
            continue  # G8 already refuses a non-confirmation
        if quote_is_probeable(record.quoted):
            continue
        result.reasons.append(
            RuleOutcome(
                G10_UNPROBED_QUOTE,
                REFUSE,
                f"normative check {record.check_id or '<unnamed>'} from "
                f"{record.origin_id} records verdict={record.verdict!r} but its "
                f"quoted text ({_truncate(record.quoted, 80)!r}) is too short to "
                f"locate in or rule out of any clause; a stub quotation proves no "
                f"retrieval, so this is a self-reported check (failure mode F1)",
                evidence=_truncate(str(record.raw), 200),
            )
        )

    # ---- G9 + record-quote location: do not take a verdict on trust ----
    # Two mechanical reductions of F1/F3, both driven by the record's OWN
    # fields rather than by the artifact talking about a clause:
    #
    #   G9  the cited section does not exist in the cited document (an
    #        invented section number -- mechanically detectable from the
    #        section table the recorded fixture supplies offline);
    #   G2/G3  the record's quoted text is not in the section it names, or is
    #        in a different section of the same document -- the fnd-2026-0014
    #        class, now testable without believing `verdict: confirmed`.
    for record in records:
        if record.missing_fields():
            continue
        number = record.rfc_number
        section = record.section_number
        if number is None:
            continue  # a non-RFC source has no deterministic section locator
        document = store.get(number)
        if document is None:
            continue  # no text source for this RFC: UNVERIFIABLE, not a failure

        known = document.section_numbers
        # Stricter than ``RfcDocument.section_text``: a section exists if it is
        # itself a parsed heading, or if a *descendant* of it is (which covers
        # citing "4.2" when only "4.2.1" was parsed).  Accepting merely that
        # the citation is a descendant of some parsed heading would let
        # "RFC 9052 section 9.7.13" pass on the strength of section 9, which
        # is exactly the invented-section-number error G9 exists to catch.
        section_exists = bool(section) and any(
            section == key or key.startswith(section + ".") for key in known
        )
        if section and not section_exists:
            result.reasons.append(
                RuleOutcome(
                    G9_SECTION_ABSENT,
                    REFUSE,
                    f"normative check {record.check_id or '<unnamed>'} from "
                    f"{record.origin_id} cites RFC {number} section {section}, which "
                    f"does not exist in the recorded source ({document.origin}); "
                    f"RFC {number} has {len(known)} parsed sections "
                    f"({', '.join(known[:8])}{' ...' if len(known) > 8 else ''}). An "
                    f"invented section number cannot have been read from the source",
                    evidence=f"section={section}",
                )
            )
            continue

        verdict, detail = locate_quoted_text(record.quoted, document, section)
        if verdict == "unverifiable":
            # A record whose quote cannot be probed is G10's business; a
            # document whose section table is absent is not a finding.
            continue
        if verdict == "confirmed":
            continue
        if verdict == "in-section-elsewhere":
            result.reasons.append(
                RuleOutcome(
                    G3_MISATTRIBUTED,
                    REFUSE,
                    f"normative check {record.check_id or '<unnamed>'} from "
                    f"{record.origin_id} records verdict={record.verdict!r} for "
                    f"RFC {number} section {section}, but its quoted text is real "
                    f"RFC {number} text attributed to the wrong clause -- {detail}. "
                    f"A verdict recorded without re-reading the source is exactly "
                    f"the fnd-2026-0014 failure mode",
                    evidence=_truncate(record.quoted, 240),
                )
            )
            continue
        result.reasons.append(
            RuleOutcome(
                G2_NOT_IN_SOURCE,
                REFUSE,
                f"normative check {record.check_id or '<unnamed>'} from "
                f"{record.origin_id} records verdict={record.verdict!r} for "
                f"RFC {number} section {section}, but its quoted text is not in "
                f"that source -- {detail}",
                evidence=_truncate(record.quoted, 240),
            )
        )

    # ---- G11: the checker must not be the artifact's own author ---------
    # F1 again, at the level automation cannot reach further.  A check whose
    # only checker is the creator is *not* falsified by this rule -- a creator
    # can fetch an RFC honestly -- but it carries no independence, and under
    # AGENTS.md ("an independent review by a non-synthesizer role") a
    # self-certified normative claim is not promotion-grade evidence.  Stated
    # as a refusal, not a warning, because the alternative is that a rule set
    # is written once and never exercised against the person it constrains.
    confirming = [r for r in records
                  if r.verdict in CONFIRMED_VERDICTS and r.checker]
    if confirming:
        author = (art.doc.get("provenance") or {}).get("created_by")
        self_checked, tokens = checker_is_author(author, [r.checker for r in confirming])
        if self_checked:
            result.reasons.append(
                RuleOutcome(
                    G11_SELF_CHECKED,
                    REFUSE,
                    f"every normative check on {art.id} was recorded by the artifact's "
                    f"own creator (shared identity token(s): "
                    f"{', '.join(tokens)}); a self-reported check discharges nothing "
                    f"-- an independent checker must re-fetch the cited clause",
                    evidence=_truncate(str(confirming[0].raw), 200),
                )
            )

    # ---- G4: staleness -------------------------------------------------
    if records:
        dates = [r.checked_at for r in records if r.checked_at is not None]
        if not dates:
            result.reasons.append(
                RuleOutcome(
                    G4_STALE_CHECK,
                    REFUSE,
                    f"{len(records)} normative check record(s) carry no parsable "
                    "checked_at date, so freshness cannot be established",
                )
            )
        else:
            newest = max(dates)
            age = (today - newest).days
            if age > recheck_days:
                result.reasons.append(
                    RuleOutcome(
                        G4_STALE_CHECK,
                        REFUSE,
                        f"newest normative check is dated {newest.isoformat()} "
                        f"({age} days old); window is --recheck-days={recheck_days}",
                        evidence=f"checked_at={newest.isoformat()}",
                    )
                )
    elif live:
        result.reasons.append(
            RuleOutcome(
                G1_NO_CHECK,
                REFUSE,
                f"{len(live)} live normative claim(s) and no normative_checks record "
                "anywhere (neither inline nor on a linked verification): nobody "
                "re-fetched the cited clause",
            )
        )

    # ---- G2/G3: live clause location -----------------------------------
    for claim in live:
        if claim.rfc_number is None:
            result.nonlocal_claims += 1
        verdict, detail = _locate(claim, store)
        if verdict == "confirmed":
            result.claims_located += 1
            continue
        if verdict == "unverifiable":
            result.unverifiable += 1
            result.reasons.append(
                RuleOutcome(
                    G2_NOT_IN_SOURCE,
                    UNVERIFIABLE,
                    f"{claim.field_path}: cannot locate ({detail}); this is "
                    "UNVERIFIABLE, not a failure",
                    evidence=_truncate(claim.text, 200),
                )
            )
            continue
        if verdict == "in-section-elsewhere":
            result.reasons.append(
                RuleOutcome(
                    G3_MISATTRIBUTED,
                    REFUSE,
                    f"{claim.field_path}: text is real but attributed to the wrong "
                    f"clause -- cited as {claim.display_locator}, actually {detail}. "
                    "This is the fnd-2026-0014 failure mode",
                    evidence=_truncate(claim.text, 240),
                )
            )
            continue
        result.reasons.append(
            RuleOutcome(
                G2_NOT_IN_SOURCE,
                REFUSE,
                f"{claim.field_path}: quotation attributed to {claim.display_locator} "
                f"is not in that source -- {detail}",
                evidence=_truncate(claim.text, 240),
            )
        )

    # ---- G5/G6: independent review ------------------------------------
    reviews = [by_id[ref] for ref in _iter_links(art, "reviews") if ref in by_id]
    if reviews:
        independent = [
            r
            for r in reviews
            if r.doc.get("independent") is True
            and str(r.doc.get("role") or "").strip().lower() != "synthesizer"
        ]
        if not independent:
            result.reasons.append(
                RuleOutcome(
                    G5_NO_REVIEW,
                    REFUSE,
                    "no linked review is independent: "
                    + ", ".join(
                        f"{r.id}(independent={r.doc.get('independent')!r},"
                        f"role={r.doc.get('role')!r})"
                        for r in reviews
                    ),
                )
            )
        else:
            supporting = []
            for review in independent:
                verdict = str(review.doc.get("verdict") or "").strip().lower()
                status = str(review.doc.get("status") or "").strip().lower()
                # An open or unfinished review has not discharged the gate
                # either way, so it neither supports nor disputes.
                if status not in REVIEW_COMPLETE_STATUSES:
                    continue
                if not any(verdict.startswith(prefix) for prefix in SUPPORTING_REVIEW_VERDICTS):
                    continue
                if any(verdict.startswith(prefix) for prefix in DISPUTING_REVIEW_VERDICTS):
                    continue
                supporting.append(review)
            if not supporting:
                result.reasons.append(
                    RuleOutcome(
                        G6_REVIEWS_DISPUTE,
                        REFUSE,
                        "no completed independent review supports the surviving claim: "
                        + ", ".join(
                            f"{r.id}(status={r.doc.get('status')!r},"
                            f"verdict={r.doc.get('verdict')!r})"
                            for r in independent
                        ),
                    )
                )
    elif live or records:
        result.reasons.append(
            RuleOutcome(
                G5_NO_REVIEW,
                REFUSE,
                "links.reviews is empty: no independent review has checked the "
                "surviving normative claim",
            )
        )

    if result.blocking:
        result.decision = REFUSE
    elif result.unverifiable:
        result.decision = ALLOW
    return result


# --------------------------------------------------------------------------
# Corpus driver
# --------------------------------------------------------------------------


def load_corpus(root: Path, include_missions: bool = True):
    artifacts, broken = VERIFY.load_artifacts(root, include_missions=include_missions)
    by_id = {a.id: a for a in artifacts}
    return artifacts, broken, by_id


def run_corpus(
    root: Path,
    *,
    artifact_ids: Sequence[str] | None = None,
    online: bool = False,
    recheck_days: int = DEFAULT_RECHECK_DAYS,
    timeout: float = 25.0,
    strict: bool = False,
    today: date | None = None,
) -> tuple[list[ArtifactGateResult], SourceStore, list[str]]:
    today = today or datetime.now(UTC).date()
    artifacts, broken, by_id = load_corpus(root)
    store = SourceStore(online=online, timeout=timeout)

    if artifact_ids:
        selected = []
        for wanted in artifact_ids:
            match = by_id.get(wanted)
            if match is None:
                match = next((a for a in artifacts if a.path == wanted), None)
            if match is not None:
                selected.append(match)
        artifacts = selected

    results = []
    for art in artifacts:
        if art.load_error:
            continue
        results.append(
            evaluate_artifact(
                art,
                by_id,
                store,
                recheck_days=recheck_days,
                today=today,
                online=online,
            )
        )
    notes = list(store.provenance_notes)
    for b in broken:
        notes.append(f"unparseable (citation checks skipped): {b.rel}: {b.load_error}")
    return results, store, notes


def blocking_results(
    results: Sequence[ArtifactGateResult], *, strict: bool
) -> list[ArtifactGateResult]:
    """Which refusals count against the exit code.

    By default only artifacts that already assert a conclusion count: the gate
    exists to ratify promotions, and a ``rejected`` finding that documents its
    own misquotation is doing its job.  ``--strict`` widens this to every
    scanned artifact.
    """
    out = []
    for result in results:
        if not result.in_scope or result.decision != REFUSE:
            continue
        if strict or result.status in ASSERTIVE_STATUSES:
            out.append(result)
    return out


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def render_report(
    results: Sequence[ArtifactGateResult],
    *,
    online: bool,
    recheck_days: int,
    notes: Sequence[str],
    strict: bool,
    today: date,
) -> str:
    lines: list[str] = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION}")
    lines.append(
        "rule: a normative claim cannot be promoted unless the exact cited "
        "specification clause has been independently checked against the "
        "authoritative source during verification"
    )
    lines.append(
        f"mode: {'online' if online else 'offline (recorded RFC fixture)'}   "
        f"recheck-days={recheck_days}   today={today.isoformat()}   "
        f"exit-blocking={'all artifacts (--strict)' if strict else 'assertive-status artifacts'}"
    )
    for note in notes:
        lines.append(f"note: {note}")
    lines.append("")

    in_scope = [r for r in results if r.in_scope]
    out_of_scope = [r for r in results if not r.in_scope]
    refused = [r for r in in_scope if r.decision == REFUSE]
    allowed = [r for r in in_scope if r.decision == ALLOW and r.live_claims]
    quiet = [r for r in in_scope if r.decision != REFUSE and not r.live_claims]

    lines.append(f"artifacts scanned: {len(results)}   gated (claim-making types): {len(in_scope)}")
    lines.append(
        f"  {len(refused)} REFUSE   {len(allowed)} ALLOW-with-normative-claims   "
        f"{len(quiet)} in-scope with no normative claim   "
        f"{len(out_of_scope)} not gated (evidence types: "
        f"{', '.join(sorted(GATED_TYPES))} only)"
    )
    lines.append("")

    if refused:
        lines.append("== REFUSED")
        for result in sorted(refused, key=lambda r: r.artifact_id):
            lines.append(f"  {result.artifact_id}  ({result.path})")
            lines.append(f"    status={result.status}  "
                         f"normative claims: {result.live_claims} live / "
                         f"{result.claims_located} located in cited clause")
            for reason in result.blocking:
                lines.append(f"    [{reason.rule}] {reason.detail}")
                if reason.evidence:
                    lines.append(f"        evidence: {reason.evidence}")
            unverifiable = [r for r in result.reasons if r.severity == UNVERIFIABLE]
            if unverifiable:
                lines.append(f"    ({len(unverifiable)} UNVERIFIABLE row(s), non-blocking)")
                for reason in unverifiable[:3]:
                    lines.append(f"        {reason.rule}: {_truncate(reason.detail, 150)}")
            lines.append("")

    if allowed:
        lines.append("== ALLOWED (has normative claims)")
        for result in sorted(allowed, key=lambda r: r.artifact_id):
            lines.append(
                f"  {result.artifact_id}  status={result.status}  "
                f"claims={result.live_claims} located={result.claims_located} "
                f"unverifiable={result.unverifiable}"
            )
        lines.append("")

    counts: dict[str, int] = defaultdict(int)
    for result in refused:
        for reason in result.blocking:
            counts[reason.rule] += 1
    if counts:
        lines.append("== refusal reasons")
        for rule in sorted(counts, key=lambda r: (-counts[r], r)):
            lines.append(f"  {rule}  x{counts[rule]}  -- {RULE_TITLES.get(rule, '')}")
        lines.append("")

    unverifiable_total = sum(r.unverifiable for r in results)
    if unverifiable_total:
        lines.append(
            f"note: {unverifiable_total} clause-location check(s) were UNVERIFIABLE. "
            "These never block: a source that could not be read is not evidence of "
            "a bad citation."
        )
        lines.append("")
    return "\n".join(lines)


def results_json(
    results: Sequence[ArtifactGateResult],
    *,
    online: bool,
    recheck_days: int,
    today: date,
    blocking: Sequence[ArtifactGateResult],
) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "online": online,
        "recheck_days": recheck_days,
        "today": today.isoformat(),
        "summary": {
            "evaluated": len(results),
            "refused": len([r for r in results if r.decision == REFUSE]),
            "exit_blocking": len(blocking),
        },
        "artifacts": [r.to_dict() for r in results],
    }


# --------------------------------------------------------------------------
# Selftest fixtures
# --------------------------------------------------------------------------

# Genuine RFC 8949 section 4.2.1 text.  This is the sentence that
# fnd-2026-0014 spliced into an RFC 9052 section 9 attribution.
SPLICE_8952_421 = (
    "Encoding restrictions are aligned with Core Deterministic Encoding "
    "Requirements specified in Section 4.2.1 of RFC 8949. In particular: encoding "
    "MUST be done using definite lengths, the length of the encoded argument MUST "
    "be the minimum possible length, the keys in every map MUST be sorted in the "
    "bytewise lexicographic order of their deterministic encodings."
)

# Genuine RFC 9052 section 9 text, for the clean fixture.
GENUINE_9052_SEC9 = (
    "This document limits the restrictions it imposes on how the CBOR Encoder needs "
    "to work. The new encoding restrictions are aligned with the Core Deterministic "
    "Encoding Requirements specified in Section 4.2.1 of RFC 8949 [STD94]. It has "
    "been narrowed down to the following restrictions: The restriction applies to "
    "the encoding of the Sig_structure, the Enc_structure, and the MAC_structure. "
    "Encoding MUST be done using definite lengths, and the length of the (encoded) "
    "argument MUST be the minimum possible length."
)

FIXTURE_REVIEW_SUPPORT = {
    "id": "rev-2026-9001",
    "type": "review",
    "status": "complete",
    "epistemic_status": "verified_conclusion",
    "created_at": "2026-10-01T00:00:00Z",
    "updated_at": "2026-10-01T00:00:00Z",
    "summary": "independent adversarial review, supports",
    "provenance": {"created_by": {"kind": "model-agent", "role": "adversarial-critic"}},
    "links": {},
    "role": "adversarial-critic",
    "verdict": "supports",
    "independent": True,
    "attempts_disproof": True,
}

FIXTURE_REVIEW_DISPUTES = dict(
    FIXTURE_REVIEW_SUPPORT,
    id="rev-2026-9002",
    summary="independent adversarial review, disputes",
    verdict="disputes",
)


def _recent(days: int, today: date) -> str:
    return (today - __import__("datetime").timedelta(days=days)).isoformat()


def build_selftest_corpus(root: Path, today: date) -> dict[str, Any]:
    """Fixtures reproducing both real failure modes, plus controls.

    * ``fnd-2026-9001`` SPLICE -- RFC 8949 section 4.2.1 text attributed to
      RFC 9052 section 9.  Reproduces fnd-2026-0014.  The text is absent from
      RFC 9052 entirely, so this trips G2 rather than G3.
    * ``fnd-2026-9006`` WRONG-SECTION -- genuine RFC 9052 text, but attributed
      to the wrong section of the right RFC.  Trips G3, which is the error class
      a document-level "does this RFC contain it" check cannot see.
    * ``fnd-2026-9002`` NEVER-RECHECKED -- full evidence chain, fresh,
      supporting independent review, but nobody re-fetched the clause.
      Reproduces the second half of fnd-2026-0014's history and every
      normative claim promoted without a source check.
    * ``fnd-2026-9003`` CLEAN -- inline ``normative_checks``, fresh, quote
      located in the cited section, supporting review.  Must ALLOW.
    * ``fnd-2026-9004`` ALL-DISPUTE -- clean checks, but every review disputes.
    * ``fnd-2026-9005`` STALE -- clean checks, but last checked far outside the
      window.
    * ``fnd-2026-9007`` SELF-REPORTED -- ``verdict: confirmed`` with a stub
      ``quoted`` string.  Trips G10: the check quotes nothing probeable, so it
      demonstrated no retrieval.  Reproduces failure mode F1.
    * ``fnd-2026-9008`` INVENTED-SECTION -- ``verdict: confirmed`` citing an
      RFC 9052 section that does not exist.  Trips G9.
    * ``fnd-2026-9009`` RECORD-MISATTRIBUTED -- ``verdict: confirmed`` whose
      quoted text is genuine RFC 9052 section 9 text but the record claims a
      different section.  Trips G3 on the record itself (F3 caught without
      believing the verdict).
    * ``fnd-2026-9010`` SELF-CHECKED -- a clean, located record, but the only
      checker is the artifact's own creator.  Trips G11.
    """
    findings = root / "knowledge" / "findings"
    reviews = root / "knowledge" / "reviews"
    observations = root / "knowledge" / "observations"

    def envelope(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "id": "fnd-2026-9000",
            "type": "finding",
            "status": "under-review",
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
            "summary": "selftest fixture",
            "epistemic_status": "hypothesis",
            "classification": "implementation-spec-mismatch",
            "disclosure": "embargoed",
            "provenance": {
                "created_by": {"kind": "model-agent", "role": "synthesizer"},
                "sources": ["https://www.rfc-editor.org/rfc/rfc9052"],
            },
            "links": {
                "experiments": ["exp-2026-9001"],
                "observations": ["obs-2026-9001"],
                "reproducers": ["rpr-2026-9001"],
                "reviews": ["rev-2026-9001"],
                "verifications": ["vrf-2026-9001"],
            },
        }
        base.update(overrides)
        return base

    def write(path: Path, doc: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )

    write(reviews / "rev-2026-9001.yaml", FIXTURE_REVIEW_SUPPORT)
    write(reviews / "rev-2026-9002.yaml", FIXTURE_REVIEW_DISPUTES)
    write(
        observations / "obs-2026-9001.yaml",
        {
            "id": "obs-2026-9001",
            "type": "observation",
            "status": "current",
            "epistemic_status": "observation",
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
            "summary": "selftest observation",
            "provenance": {"created_by": {"kind": "model-agent", "role": "scout"}},
            "links": {},
        },
    )

    # --- A: the spliced / misattributed quotation ------------------------
    write(
        findings / "fnd-2026-9001.yaml",
        envelope(
            id="fnd-2026-9001",
            summary="SPLICE: quotes RFC 8949 section 4.2.1 text as RFC 9052 section 9",
            normative_basis={
                "rfc_9052_section_9": SPLICE_8952_421,
            },
        ),
    )

    # --- B: normative claim never re-checked ----------------------------
    write(
        findings / "fnd-2026-9002.yaml",
        envelope(
            id="fnd-2026-9002",
            summary="NEVER-RECHECKED: full evidence chain, nobody re-fetched the clause",
            normative_basis={
                "rfc_9052_section_9": (
                    "RFC 9052 section 9 narrows the deterministic-encoding restrictions "
                    "it imposes on the CBOR encoder, and this finding relies on that "
                    "clause being the operative normative text for COSE message "
                    "construction, so the clause must be checked against the RFC."
                )
            },
        ),
    )

    # --- C: clean, must ALLOW -------------------------------------------
    write(
        findings / "fnd-2026-9003.yaml",
        envelope(
            id="fnd-2026-9003",
            summary="CLEAN: inline normative check, fresh, quote in the cited clause",
            normative_basis={"rfc_9052_section_9": GENUINE_9052_SEC9},
            normative_checks=[
                {
                    "id": "NC-1",
                    "source": "https://www.rfc-editor.org/rfc/rfc9052.html#section-9",
                    "section": "RFC 9052 section 9",
                    "quoted": GENUINE_9052_SEC9,
                    "method": "section-scoped-substring",
                    "checked_at": _recent(7, today),
                    "checker": {
                        "kind": "model-agent",
                        "role": "specification-analyst",
                        "model": "selftest",
                    },
                    "verdict": "confirmed",
                    "detail": "Fetched rfc9052.txt and located every clause in section 9.",
                }
            ],
        ),
    )

    # --- D: clean checks, but every review disputes ---------------------
    write(
        findings / "fnd-2026-9004.yaml",
        envelope(
            id="fnd-2026-9004",
            summary="ALL-DISPUTE: clean normative checks, every review disputes",
            links={
                "experiments": ["exp-2026-9001"],
                "observations": ["obs-2026-9001"],
                "reproducers": ["rpr-2026-9001"],
                "reviews": ["rev-2026-9002"],
                "verifications": ["vrf-2026-9001"],
            },
            normative_basis={"rfc_9052_section_9": GENUINE_9052_SEC9},
            normative_checks=[
                {
                    "id": "NC-1",
                    "source": "https://www.rfc-editor.org/rfc/rfc9052.html#section-9",
                    "section": "RFC 9052 section 9",
                    "quoted": GENUINE_9052_SEC9,
                    "method": "section-scoped-substring",
                    "checked_at": _recent(7, today),
                    "checker": {"kind": "human", "identity": "selftest"},
                    "verdict": "confirmed",
                }
            ],
        ),
    )

    # --- E: clean checks, but stale --------------------------------------
    write(
        findings / "fnd-2026-9005.yaml",
        envelope(
            id="fnd-2026-9005",
            summary="STALE: clean normative checks, last checked long ago",
            normative_basis={"rfc_9052_section_9": GENUINE_9052_SEC9},
            normative_checks=[
                {
                    "id": "NC-1",
                    "source": "https://www.rfc-editor.org/rfc/rfc9052.html#section-9",
                    "section": "RFC 9052 section 9",
                    "quoted": GENUINE_9052_SEC9,
                    "method": "section-scoped-substring",
                    "checked_at": _recent(400, today),
                    "checker": {"kind": "human", "identity": "selftest"},
                    "verdict": "confirmed",
                }
            ],
        ),
    )

    # --- F: right RFC, wrong section ------------------------------------
    write(
        findings / "fnd-2026-9006.yaml",
        envelope(
            id="fnd-2026-9006",
            summary="WRONG-SECTION: genuine RFC 9052 text attributed to the wrong clause",
            normative_basis={
                # Two verbatim RFC 9052 section 3 passages joined with an
                # ellipsis, presented as section 9.  A document-level "does
                # this RFC contain it" check passes it; only a section-scoped
                # check refuses it.  This is the error class that survives
                # every check verify_citations already performs.
                "rfc_9052_section_9": (
                    "The structure of COSE has been designed to have two buckets of "
                    "information that are not considered to be part of the payload itself, "
                    "but are used for holding information about content, algorithms, keys, "
                    "or evaluation hints for the processing of the layer. ... This avoids "
                    "the problem of all parties needing to be able to do a common "
                    "canonical encoding of the map for input to cryptographic "
                    "operations."
                )
            },
        ),
    )

    # --- G: F1 stub quotation, self-reported as confirmed ---------------
    write(
        findings / "fnd-2026-9007.yaml",
        envelope(
            id="fnd-2026-9007",
            summary="SELF-REPORTED: verdict confirmed over a stub quotation",
            normative_basis={"rfc_9052_section_9": GENUINE_9052_SEC9},
            normative_checks=[
                {
                    "id": "NC-1",
                    "source": "https://www.rfc-editor.org/rfc/rfc9052.html#section-9",
                    "section": "RFC 9052 section 9",
                    "quoted": "definite lengths",  # too short to probe anywhere
                    "checked_at": _recent(7, today),
                    "checker": {"kind": "human", "identity": "selftest"},
                    "verdict": "confirmed",
                }
            ],
        ),
    )

    # --- H: invented section number, self-reported as confirmed --------
    write(
        findings / "fnd-2026-9008.yaml",
        envelope(
            id="fnd-2026-9008",
            summary="INVENTED-SECTION: verdict confirmed citing a nonexistent section",
            normative_basis={"rfc_9052_section_9": GENUINE_9052_SEC9},
            normative_checks=[
                {
                    "id": "NC-1",
                    "source": "https://www.rfc-editor.org/rfc/rfc9052.html#section-9",
                    "section": "RFC 9052 section 9.7.13",
                    "quoted": GENUINE_9052_SEC9,
                    "checked_at": _recent(7, today),
                    "checker": {"kind": "human", "identity": "selftest"},
                    "verdict": "confirmed",
                }
            ],
        ),
    )

    # --- I: record's own quotation attributed to the wrong clause ------
    write(
        findings / "fnd-2026-9009.yaml",
        envelope(
            id="fnd-2026-9009",
            summary="RECORD-MISATTRIBUTED: confirmed, but the quote is section 9 text "
                    "claimed as section 4.2.1",
            normative_basis={"rfc_9052_section_9": GENUINE_9052_SEC9},
            normative_checks=[
                {
                    "id": "NC-1",
                    "source": "https://www.rfc-editor.org/rfc/rfc9052.html",
                    "section": "RFC 9052 section 4.1",  # a real section, wrong one
                    "quoted": GENUINE_9052_SEC9,
                    "checked_at": _recent(7, today),
                    "checker": {"kind": "human", "identity": "selftest"},
                    "verdict": "confirmed",
                }
            ],
        ),
    )

    # --- J: the only checker is the artifact's own creator --------------
    write(
        findings / "fnd-2026-9010.yaml",
        envelope(
            id="fnd-2026-9010",
            summary="SELF-CHECKED: clean, located record, but checked by its own author",
            provenance={
                "created_by": {
                    "kind": "model-agent",
                    "role": "specification-analyst",
                    "model": "probe-4.1",
                },
                "sources": ["https://www.rfc-editor.org/rfc/rfc9052"],
            },
            normative_basis={"rfc_9052_section_9": GENUINE_9052_SEC9},
            normative_checks=[
                {
                    "id": "NC-1",
                    "source": "https://www.rfc-editor.org/rfc/rfc9052.html#section-9",
                    "section": "RFC 9052 section 9",
                    "quoted": GENUINE_9052_SEC9,
                    "checked_at": _recent(7, today),
                    "checker": "probe-4.1, read directly from the fetched source",
                    "verdict": "confirmed",
                }
            ],
        ),
    )

    return {
        "splice": "fnd-2026-9001",
        "never_rechecked": "fnd-2026-9002",
        "clean": "fnd-2026-9003",
        "all_dispute": "fnd-2026-9004",
        "stale": "fnd-2026-9005",
        "wrong_section": "fnd-2026-9006",
        "self_reported": "fnd-2026-9007",
        "invented_section": "fnd-2026-9008",
        "record_misattributed": "fnd-2026-9009",
        "self_checked": "fnd-2026-9010",
    }


def run_selftest(online: bool = False, recheck_days: int = DEFAULT_RECHECK_DAYS) -> int:
    import shutil
    import tempfile

    today = datetime.now(UTC).date()
    temp_root = Path(tempfile.mkdtemp(prefix="promotion_gate_selftest_"))
    results_log: list[tuple[bool, str]] = []
    try:
        ids = build_selftest_corpus(temp_root, today)
        artifacts, _broken, by_id = load_corpus(temp_root, include_missions=False)
        store = SourceStore(online=online, timeout=25.0)
        store.load_fixture()

        evaluated: dict[str, ArtifactGateResult] = {}
        for art in artifacts:
            if art.load_error:
                continue
            evaluated[art.id] = evaluate_artifact(
                art,
                by_id,
                store,
                recheck_days=recheck_days,
                today=today,
                online=online,
            )

        def check(label: str, fixture: str, want_decision: str, want_rules: set[str]) -> None:
            result = evaluated.get(fixture)
            if result is None:
                results_log.append((False, f"{label}: fixture {fixture} not evaluated"))
                return
            rules = {r.rule for r in result.blocking}
            ok = result.decision == want_decision
            detail = f"{label} [{fixture}]: decision={result.decision} rules={sorted(rules)}"
            if not ok:
                detail += f" EXPECTED {want_decision}"
                results_log.append((False, detail))
                return
            missing = want_rules - rules
            if missing:
                detail += f" MISSING {sorted(missing)}"
                results_log.append((False, detail))
                return
            results_log.append((True, detail))

        # Failure mode 1: spliced / misattributed quotation.
        check(
            "failure mode 1 (fnd-2026-0014 class): RFC 8949 4.2.1 text spliced into "
            "an RFC 9052 section 9 attribution",
            ids["splice"],
            REFUSE,
            {G2_NOT_IN_SOURCE},
        )
        # The same error class, but the text is genuinely in the cited RFC at a
        # different section: only a section-scoped check sees this.
        check(
            "right RFC, wrong section (invisible to a document-level check)",
            ids["wrong_section"],
            REFUSE,
            {G3_MISATTRIBUTED},
        )
        # Failure mode 2: normative text never re-checked.
        check(
            "failure mode 2: normative claim never re-checked",
            ids["never_rechecked"],
            REFUSE,
            {G1_NO_CHECK},
        )
        check("every review disputes", ids["all_dispute"], REFUSE, {G6_REVIEWS_DISPUTE})
        check("stale normative check", ids["stale"], REFUSE, {G4_STALE_CHECK})
        # F1: a self-reported verdict over a stub proves no retrieval.
        check(
            "self-reported confirmed over an unprobeable stub quotation (F1)",
            ids["self_reported"],
            REFUSE,
            {G10_UNPROBED_QUOTE},
        )
        check(
            "self-reported confirmed citing an invented section number",
            ids["invented_section"],
            REFUSE,
            {G9_SECTION_ABSENT},
        )
        check(
            "self-reported confirmed whose quote belongs to another clause (F3)",
            ids["record_misattributed"],
            REFUSE,
            {G3_MISATTRIBUTED},
        )
        check(
            "the only checker is the artifact's own creator",
            ids["self_checked"],
            REFUSE,
            {G11_SELF_CHECKED},
        )
        check("clean fixture", ids["clean"], ALLOW, set())

        passed = all(ok for ok, _ in results_log)
        print(f"== promotion_gate selftest ({'online' if online else 'offline'}) ==")
        for note in store.provenance_notes:
            print(f"   note: {note}")
        for ok, message in results_log:
            print(f"   [{'PASS' if ok else 'FAIL'}] {message}")
        if online:
            for fixture in (ids["splice"], ids["clean"]):
                result = evaluated.get(fixture)
                if result:
                    print(f"   {fixture}: {result.claims_located}/{result.live_claims} "
                          f"claim(s) located in the cited clause")
        print(f"   selftest: {'PASS' if passed else 'FAIL'}")
        return EXIT_ALLOW if passed else EXIT_REFUSE
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


# --------------------------------------------------------------------------
# Fixture recording (authoritative text, not mock data)
# --------------------------------------------------------------------------


# RFCs the offline fixture records.  9052/8949 are the two the original
# selftest fixtures are built from; the rest are the documents the current
# corpus actually cites, so their clause checks are deterministic offline
# instead of silently degrading to UNVERIFIABLE.  Extend this when a new RFC
# becomes load-bearing -- an uncited document is exactly how F1 hides.
FIXTURE_RFCS = (9052, 8949, 5280, 9591, 8032, 9496, 9053, 9338, 9180)


def record_fixtures(out_path: Path, timeout: float = 30.0) -> int:
    """Fetch real RFC text and record it so ``--selftest`` is offline-stable.

    This writes recorded authoritative text with provenance (URL, fetch date,
    whole-body SHA-256).  It never invents text: an RFC that cannot be fetched
    is skipped and reported, not filled in.
    """
    sources: list[dict[str, Any]] = []
    skipped: list[int] = []
    for number in FIXTURE_RFCS:
        probe = _find_rfc_body(f"https://www.rfc-editor.org/rfc/rfc{number}", timeout)
        if probe.state != "reachable" or not probe.body:
            skipped.append(number)
            print(
                f"{TOOL_NAME}: RFC {number} not fetched ({probe.state}); not recorded",
                file=sys.stderr,
            )
            continue
        body = probe.body
        sections = parse_rfc_sections(body)
        sources.append(
            {
                "rfc": number,
                "url": probe.url,
                "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "body_bytes": len(body.encode("utf-8")),
                "section_count": len(sections),
                "sections": sections,
                "full_text_normalized": _normalize_text(body),
            }
        )
    if not sources:
        print(f"{TOOL_NAME}: no RFC could be fetched; fixture not written", file=sys.stderr)
        return EXIT_ERROR
    payload = {
        "fixture_version": 1,
        "recorded_by": f"{TOOL_NAME} {TOOL_VERSION} --record-fixtures",
        "purpose": (
            "Recorded excerpts of authoritative RFC text so the promotion gate's "
            "section-scoped clause check can be exercised deterministically offline. "
            "This is recorded real text with provenance, not mock data."
        ),
        "note": (
            "Regenerate with `tools/promotion_gate.py --record-fixtures`. Under "
            "--online the gate fetches live and re-checks body_sha256; a mismatch is "
            "reported rather than trusted."
        ),
        "sources": sources,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=10**6),
        encoding="utf-8",
    )
    print(
        f"{TOOL_NAME}: recorded {len(sources)} document(s) to {out_path}"
        + (f"; skipped {skipped}" if skipped else "")
    )
    return EXIT_ALLOW


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def detect_root(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    here = Path(__file__).resolve().parent
    for candidate in [here, *here.parents]:
        if (candidate / "knowledge").is_dir() and (candidate / "src").is_dir():
            return candidate
    return here.parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promotion_gate.py",
        description=(
            "Refuse promotion of an artifact whose normative claims lack an "
            "independent, recorded, in-window check of the exact cited clause."
        ),
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--finding", action="append", metavar="ID", default=None,
                       help="evaluate specific artifact id or path (repeatable)")
    scope.add_argument("--all", action="store_true", help="evaluate the whole corpus")
    parser.add_argument("--online", action="store_true",
                        help="fetch cited sources live instead of the recorded fixture")
    parser.add_argument("--recheck-days", type=int, default=DEFAULT_RECHECK_DAYS, metavar="N",
                        help=f"normative re-check window in days (default {DEFAULT_RECHECK_DAYS})")
    parser.add_argument("--strict", action="store_true",
                        help="let refusals from non-assertive artifacts affect the exit code too")
    parser.add_argument("--today", metavar="YYYY-MM-DD", default=None,
                        help="override today's date (deterministic runs)")
    parser.add_argument("--timeout", type=float, default=25.0, help="per-request timeout (s)")
    parser.add_argument("--json", action="store_true", help="emit JSON on stdout")
    parser.add_argument("--report", metavar="PATH", help="write the text report to PATH")
    parser.add_argument("--selftest", action="store_true", help="run fixtures and exit")
    parser.add_argument("--selftest-network", action="store_true",
                        help="with --selftest, fetch the real RFCs instead of the fixture")
    parser.add_argument("--record-fixtures", action="store_true",
                        help="re-record the offline RFC text fixture, then exit")
    parser.add_argument("--root", metavar="PATH", default=None,
                        help="repository root (default: autodetect)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.selftest:
        return run_selftest(
            online=args.selftest_network or args.online, recheck_days=args.recheck_days
        )

    root = detect_root(args.root)
    if args.record_fixtures:
        return record_fixtures(FIXTURE_PATH, timeout=args.timeout)

    if not (root / "knowledge").is_dir():
        print(f"{TOOL_NAME}: no knowledge/ directory under {root}", file=sys.stderr)
        return EXIT_ERROR

    today = (
        date.fromisoformat(args.today) if args.today else datetime.now(UTC).date()
    )

    try:
        results, store, notes = run_corpus(
            root,
            artifact_ids=args.finding,
            online=args.online,
            recheck_days=args.recheck_days,
            timeout=args.timeout,
            strict=args.strict,
            today=today,
        )
    except Exception as exc:  # a gate that crashes must not look like a pass
        print(f"{TOOL_NAME}: internal error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    blocking = blocking_results(results, strict=args.strict or bool(args.finding))

    if args.json:
        print(json.dumps(results_json(
            results, online=args.online, recheck_days=args.recheck_days,
            today=today, blocking=blocking), indent=2))
    else:
        text = render_report(
            results, online=args.online, recheck_days=args.recheck_days,
            notes=notes, strict=args.strict or bool(args.finding), today=today,
        )
        print(text)

    if args.report:
        path = Path(args.report)
        text = render_report(
            results, online=args.online, recheck_days=args.recheck_days,
            notes=notes, strict=args.strict or bool(args.finding), today=today,
        )
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"{TOOL_NAME}: could not write report: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if blocking:
        print(
            f"{TOOL_NAME}: REFUSE promotion for {len(blocking)} artifact(s): "
            f"{', '.join(sorted(r.artifact_id for r in blocking))}",
            file=sys.stderr,
        )
        return EXIT_REFUSE
    print(f"{TOOL_NAME}: promotion allowed for all {len(results)} evaluated artifact(s)")
    return EXIT_ALLOW


if __name__ == "__main__":
    raise SystemExit(main())
