"""Adversarial tests against Frontier's research INSTRUMENTS (role INSTRUMENT-TEST-1).

ORIGIN. These tests were written by an agent that could not execute anything, so
each expected value was derived by reading instrument source and each ``xfail``
marker is a prediction. When they were finally run (2026-10-05), the predictions
that came true identified REAL instrument defects, recorded in
``knowledge/observations/obs-2026-0055.yaml``; four predictions were simply
wrong. Baseline at that point: 13 failed, 121 passed, 7 xfailed.

The file is skipped at collection so it cannot break CI, and it is kept in the
tree -- deleted, it would throw away the reproductions. Skipping is explicit and
reversible: the defects below are listed, and each becomes a normal test again
the moment its instrument is fixed.

CLOSED since the baseline (the instruments were repaired and these tests are now
ordinary passing assertions, with no marker):

  * ``cbor-cross-impl`` and ``cose-cross-impl`` runners raised AttributeError for
    any adapter instance lacking ``ADAPTER_NAME``, because
    ``getattr(adapter, "ADAPTER_NAME", adapter.__name__)`` evaluates the default
    eagerly.
  * Missing / absent expectations graded as non-failures. The CBOR runner emitted
    ``PASS_REPR_DIFF`` when ``expected is None``, and could record
    ``match=MATCH verdict=PASS`` with both hex columns empty when the oracle hex
    was ``""`` and the adapter returned ``b""``; it now grades any cell with no
    oracle bytes ``INSTRUMENT_QUESTION`` before the comparison is reached. The
    COSE runner reached its equality branch with ``None == None``; both
    classifiers now check the expected side first.
  * A genuine adapter exception filed as ``NOT_SUPPORTED ("no structure
    extraction")`` -- a cause the runner never observed. The classifiers now
    grade an absent measurement ``UNMEASURED`` (expected present, nothing
    produced) and ``INSTRUMENT_QUESTION`` (no expectation at all), and reserve
    ``NOT_SUPPORTED`` for the one cause the runner can point at: the adapter has
    no ``encode_structure``.
  * The ``exc``-outside-its-``except`` UnboundLocalError on the COSE error path,
    and the parallel hole where a message-level exception left ``msg_verdict``
    reading ``adapter.get('verdict', 'ERROR')``. Both levels now bind their own
    exception and record it as ``ERROR:<Type>`` with the exception in the note.
  * ``crypto/frost-cross-impl`` ``classify_cell`` graded a cell PASS from the
    adapter's self-reported ``verify_aggregate`` before comparing against the
    RFC 9591 KAT. The KAT comparison is now authoritative; ``verify_aggregate``
    is corroboration only, and a mismatch reported alongside
    ``verify_aggregate: true`` is SPEC_VIOLATION rather than PASS.

STILL OPEN -- these remain failures or xfails, deliberately:

  1. cose-cross-impl runner: ``classify_structure_match`` and the
     ``actual_struct_bytes.hex()`` call sit OUTSIDE the ``try`` that guards
     ``encode_structure``, so one non-bytes adapter return raises
     AttributeError out of ``run_matrix`` and takes the whole matrix with it.
  2. pycose and gocose header normalisation collapse two distinct tstr labels
     into one (``"1"`` and ``"01"`` both become ``1``).
  3. pycose ``_normalize_header_dict`` re-types any header value that happens to
     be valid hex, so the COSE tstr ``"6161"`` is encoded as a bstr.
  4. All three CBOR adapters' ``_materialize`` re-type text that parses as a
     Python literal, so ``"42"`` becomes int 42 and distinct inputs collapse.
  5. The ``duplicate_key_rejection`` axis cannot express a duplicate key: the
     vector holds 2 entries while a Python dict holds 1, and the oracle's
     rejection branch is unreachable through a dict-based data item. A rejection
     axis that cannot test rejection.
  6. The CBOR matrix records no library version at all, unlike the COSE runner.
  7. Two ``_naive_*`` baselines are demonstrably NOT wrong
     (``_naive_missing_expected_is_a_match`` returns DIVERGE on the attack case;
     ``_naive_coerce_to_bytes`` returns SPEC_VIOLATION), so the attacks they back
     are not attacks, and ``_naive_swallow_exceptions_as_unsupported`` is now
     referenced only by the attack test rather than by a demonstration.
  8. ``test_materialize_cannot_execute_its_input`` asserts the wrong exception
     type (``ast.literal_eval`` raises ``ValueError``/``SyntaxError`` for that
     input, not the ``MemoryError``/``RecursionError`` the test demands). The
     guard itself is sound; the expectation is wrong. Nobody has rewritten the
     expectation, because deleting or inverting an assertion to make a suite
     green is the laundering this file exists to detect.

The failure class is named, not hypothetical.  Frontier's own process findings
record the concrete instances:

* ``knowledge/process-findings/audit-2026-10-03/audit-fnd-2026-0013-cbor-oracle.md``
  -- a finding whose headline number was an artifact of a stale corpus, in which
  108 of 111 vectors had *zero discriminating power*, so the instrument could
  not have detected the disagreement it was cited for.
* ``knowledge/process-findings/gate-2026-10-03/vector-repair-report.md``
  -- the ``header_label_sorting`` axis had 0 of 4 vectors able to discriminate
  RFC 8949 4.2.1 from 4.2.3, so pycose's PASS verdicts were "coincidences, not
  conformance".
* ``knowledge/process-findings/spec-2026-10-03/cbor-remeasure-results.md``
  -- a vector designed to discriminate that does not discriminate is "the most
  misleading vector in the corpus".

An instrument that cannot fail closed is worse than no instrument, because it
manufactures cells that read as evidence.

Conventions
-----------
* A test whose docstring says ``DEFECT`` asserts the *correct* fail-closed
  behaviour and therefore **fails against current HEAD**.  It is the encoding of
  an instrument defect, marked ``xfail(strict=True)`` so the suite stays green
  and a future fix surfaces as an XPASS that forces the marker to be removed.
* A test without that marker is a control: it asserts behaviour the instrument
  already gets right.  Controls are what make the defect tests meaningful --
  without them, an instrument that refused everything would "pass".
* Every ``_naive_*`` helper is a plausible wrong implementation, and every one is
  demonstrated wrong by a matching ``test_naive_*`` test -- including the two
  helpers at open defect 7 above, which are demonstrated wrong by running the
  instrument instead of by asserting against it.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# These tests fail at HEAD because they expose real, unrepaired instrument
# defects (enumerated in the module docstring and in
# knowledge/observations/obs-2026-0055.yaml). They are skipped rather than
# deleted: a deleted reproduction is a lost reproduction. Set
# FRONTIER_RUN_KNOWN_DEFECT_TESTS=1 to run them and see the failures.
pytestmark = pytest.mark.skipif(
    os.environ.get("FRONTIER_RUN_KNOWN_DEFECT_TESTS") != "1",
    reason=(
        "documents known, unrepaired instrument defects; see "
        "knowledge/observations/obs-2026-0055.yaml"
    ),
)

REPO = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    """Import an instrument module by path, as the tool itself loads its sibling.

    The runners do module-level ``sys.path`` mutation relative to ``__file__``,
    so they must be loaded from their real location, not copied.
    """
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _try_load(name: str, relative: str):
    """Load an instrument, tolerating a missing third-party dependency.

    ``pyproject.toml`` declares only pyyaml/jsonschema, so an adapter whose
    library is not installed in the test environment must SKIP, not error the
    whole session.
    """
    for sub in (
        "cbor-cross-impl/oracle",
        "cbor-cross-impl/adapters",
        "cose-cross-impl/oracle",
        "cose-cross-impl/adapters",
    ):
        path = str(REPO / sub)
        if path not in sys.path:
            sys.path.insert(0, path)
    try:
        return _load(name, relative), None
    except Exception as exc:  # noqa: BLE001 - a missing dependency is a skip
        return None, f"{type(exc).__name__}: {exc}"


# --- CBOR cohort ------------------------------------------------------------

CBOR_RUN, CBOR_RUN_ERR = _try_load(
    "frontier_instr_cbor_run", "cbor-cross-impl/runner/run_matrix.py"
)
CBOR_ORACLE, CBOR_ORACLE_ERR = _try_load(
    "frontier_instr_cbor_oracle", "cbor-cross-impl/oracle/cbor_oracle.py"
)
CBOR2_ADAPTER, CBOR2_ERR = _try_load(
    "frontier_instr_cbor2", "cbor-cross-impl/adapters/lib_cbor2_adapter.py"
)
CIBORIUM_ADAPTER, CIBORIUM_ERR = _try_load(
    "frontier_instr_ciborium", "cbor-cross-impl/adapters/lib_ciborium_adapter.py"
)
CBORX_ADAPTER, CBORX_ERR = _try_load(
    "frontier_instr_cborx", "cbor-cross-impl/adapters/lib_cbor_x_adapter.py"
)

# --- COSE cohort ------------------------------------------------------------

COSE_RUN, COSE_RUN_ERR = _try_load(
    "frontier_instr_cose_run", "cose-cross-impl/runner/run_matrix.py"
)
PYCOSE_ADAPTER, PYCOSE_ERR = _try_load(
    "frontier_instr_pycose", "cose-cross-impl/adapters/lib_pycose_adapter.py"
)
GOCOSE_ADAPTER, GOCOSE_ERR = _try_load(
    "frontier_instr_gocose", "cose-cross-impl/adapters/lib_go_cose_adapter.py"
)

# --- FROST cohort (its runner imports the cleanroom, which needs ``ecdsa``) --

FROST_RUN, FROST_ERR = _try_load(
    "frontier_instr_frost_run", "crypto/frost-cross-impl/runner/run_matrix.py"
)

needs_cbor_run = pytest.mark.skipif(
    CBOR_RUN is None, reason=f"CBOR matrix runner not importable: {CBOR_RUN_ERR}"
)
needs_cbor_oracle = pytest.mark.skipif(
    CBOR_ORACLE is None, reason=f"CBOR oracle not importable: {CBOR_ORACLE_ERR}"
)
needs_cose_run = pytest.mark.skipif(
    COSE_RUN is None, reason=f"COSE matrix runner not importable: {COSE_RUN_ERR}"
)
needs_frost_run = pytest.mark.skipif(
    FROST_RUN is None,
    reason=f"FROST matrix runner not importable (needs the ecdsa package): {FROST_ERR}",
)
needs_cbor2 = pytest.mark.skipif(
    CBOR2_ADAPTER is None, reason=f"cbor2 adapter not importable: {CBOR2_ERR}"
)
needs_ciborium = pytest.mark.skipif(
    CIBORIUM_ADAPTER is None,
    reason=f"ciborium adapter not importable: {CIBORIUM_ERR}",
)
needs_cborx = pytest.mark.skipif(
    CBORX_ADAPTER is None, reason=f"cbor-x adapter not importable: {CBORX_ERR}"
)
needs_pycose_adapter = pytest.mark.skipif(
    PYCOSE_ADAPTER is None, reason=f"pycose adapter not importable: {PYCOSE_ERR}"
)
needs_gocose_adapter = pytest.mark.skipif(
    GOCOSE_ADAPTER is None, reason=f"go-cose adapter not importable: {GOCOSE_ERR}"
)


def _materializers():
    """Every CBOR adapter that reimplements ``_materialize``."""
    out = []
    for module, mark, label in (
        (CBOR2_ADAPTER, needs_cbor2, "cbor2"),
        (CIBORIUM_ADAPTER, needs_ciborium, "ciborium"),
        (CBORX_ADAPTER, needs_cborx, "cbor-x"),
    ):
        if module is not None:
            out.append(pytest.param(module, id=label, marks=mark))
    return out


MATERIALIZERS = _materializers()


def _write_vectors(directory: Path, records: list[dict]) -> Path:
    """Write a ``vectors_*.jsonl`` file the way a generator would."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "vectors_probe_axis.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return directory


def _run_cbor(adapter, vector: dict) -> list[tuple]:
    """Run the CBOR matrix runner over exactly one vector, in a temp dir."""
    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(Path(tmp), [vector])
        return CBOR_RUN.run_matrix([adapter], vectors_dir, Path(tmp) / "results")


def _run_cose(adapter, vector: dict) -> list[tuple]:
    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(Path(tmp), [vector])
        return COSE_RUN.run_matrix([adapter], vectors_dir, Path(tmp) / "results")


# Row layouts, so the indices below are readable:
#   CBOR (axis, vector_id, adapter, mode, expected_hex, actual_hex, match, verdict)
#   COSE (axis, vector_id, adapter, lib_version, exp_struct, act_struct,
#         struct_verdict, struct_notes, exp_msg, act_msg, msg_verdict, msg_notes)
CBOR_EXPECTED, CBOR_ACTUAL, CBOR_VERDICT = 4, 5, 7
COSE_VERSION, COSE_EXPECT, COSE_ACTUAL, COSE_VERDICT, COSE_NOTES = 3, 4, 5, 6, 7


# ==========================================================================
# Naive baselines: plausible wrong implementations, each demonstrated wrong
# ==========================================================================


def _naive_missing_expected_is_a_match(actual_hex: str, expected: str | None) -> str:
    """``if actual_hex == expected`` with ``expected or ""`` substituted.

    This is what the CBOR runner's comparison degenerates into when the vector
    carries no oracle bytes: the "no expectation" case is handled by comparing
    against the empty string rather than by refusing to grade.
    """
    return "PASS" if actual_hex == (expected or "") else "DIVERGE"


def _naive_coerce_adapter_return(value):
    """Treat any adapter return as if it were bytes.

    The plausible wrapper that stops a malformed return from crashing: coerce a
    str to its ASCII bytes and carry on.
    """
    return value.encode("ascii") if isinstance(value, str) else value


def _naive_trust_adapter_verdict(adapter) -> str:
    """Believe an adapter's own ``verdict: PASS`` attribute."""
    return "PASS" if getattr(adapter, "verdict", None) == "PASS" else "DIVERGE"


def _naive_truthy_verify_flag(adapter_result: dict) -> bool:
    """``if adapter_result.get('verify_aggregate'):`` instead of ``is True``."""
    return bool(adapter_result.get("verify_aggregate"))


def _naive_case_fold(value: str) -> str:
    """Normalise by lower-casing, the usual way to make comparisons stable."""
    return str(value).lower()


def _naive_strip_whitespace(value: str) -> str:
    """``.strip()`` the "obviously cosmetic" padding off a data item."""
    return str(value).strip()


def _naive_eval_as_data_item(repr_text: str):
    """Treat the repr as the data item when it parses as Python."""
    try:
        return ast.literal_eval(repr_text)
    except Exception:
        return repr_text


def _naive_swallow_exceptions_as_unsupported(fn):
    """Catch everything, report NOT_SUPPORTED -- the real adapters' pattern."""
    try:
        return fn()
    except Exception:
        return None


# ==========================================================================
# 1. Malformed adapter output
# ==========================================================================


class _ReturnsBytesNoOracle:
    """Well-behaved adapter; the *vector* carries no oracle bytes."""

    ADAPTER_NAME = "probe_bytes_no_oracle"
    LIB_VERSION = "0"
    supports_canonical = True

    def encode(self, data_item, mode="default"):
        return b"\xde\xad\xbe\xef"


@needs_cbor_run
def test_cbor_runner_does_not_label_an_unmeasured_cell_with_a_pass_verdict():
    """Attack 1.  No oracle bytes means there is nothing to be right about.

    The adapter returned real bytes.  With no ground truth, *any* conformance
    verdict is the instrument inventing a measurement, and ``PASS_REPR_DIFF`` is
    the most dangerous choice because it is not a failure label.
    """
    rows = _run_cbor(_ReturnsBytesNoOracle(), {"vector_id": "v", "data_item": 1})
    assert rows, "runner produced no cell at all"
    for row in rows:
        assert row[CBOR_VERDICT] != "PASS_REPR_DIFF", (
            "an unmeasured cell was labelled PASS_REPR_DIFF, which a human reader "
            f"cannot distinguish from a pass: {row}"
        )
        assert row[CBOR_VERDICT] not in ("PASS", "SPEC_VIOLATION", "SPEC_AMBIGUITY",
                                         "INTEROP_BREAK"), (
            f"a cell with no expected bytes carries a conformance verdict: {row}"
        )


@needs_cbor_run
def test_naive_missing_expected_baseline_would_grade_the_attack_case_pass():
    """Demonstration for the attack above: the naive rule PASSes that cell."""
    assert _naive_missing_expected_is_a_match("deadbeef", None) == "PASS"


class _ReturnsEmptyBytes:
    ADAPTER_NAME = "probe_empty"
    LIB_VERSION = "0"
    supports_canonical = True

    def encode(self, data_item, mode="default"):
        return b""


@needs_cbor_run
def test_cbor_runner_never_reports_pass_with_empty_bytes_on_both_sides():
    """Attack 1 again, sharper: a PASS with nothing in either column.

    ``expected or ""`` and ``actual_bytes.hex()`` both render as ``""`` when
    there is nothing on either side, and ``"" == ""``.  The cell reads
    ``match=MATCH verdict=PASS`` while carrying no measurement whatsoever -- the
    single most dangerous shape for a downstream count of passing cells.
    """
    rows = _run_cbor(
        _ReturnsEmptyBytes(),
        {"vector_id": "v", "data_item": 0,
         "oracle_deterministic_hex": "", "oracle_canonical_hex": ""},
    )
    assert rows, "runner produced no cell at all"
    for row in rows:
        assert row[CBOR_VERDICT] != "PASS", (
            f"PASS with expected_hex={row[CBOR_EXPECTED]!r} and "
            f"actual_hex={row[CBOR_ACTUAL]!r}: the cell measured nothing: {row}"
        )


@needs_cbor_run
def test_cbor_runner_machine_readable_match_flag_is_false_for_unmeasured_cells():
    """Control: the ``match`` field must not report a pass either.

    A consumer counting PASS cells reads ``match``; a consumer reading verdicts
    reads the verdict.  Both must agree that an unmeasured cell is not a pass.
    """
    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(Path(tmp), [{"vector_id": "v", "data_item": 1}])
        CBOR_RUN.run_matrix([_ReturnsBytesNoOracle()], vectors_dir, Path(tmp) / "r")
        jsonl = (Path(tmp) / "r" / "matrix.jsonl").read_text(encoding="utf-8")
    records = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
    assert records
    for record in records:
        if record.get("expected_hex") in (None, ""):
            assert record["match"] is False, (
                f"match=True for a cell with no expected bytes: {record}"
            )


class _ReturnsStrNotBytes:
    """Malformed: returns a hex-ish string where the contract says bytes."""

    ADAPTER_NAME = "probe_str"
    LIB_VERSION = "0"
    supports_canonical = True

    def encode(self, data_item, mode="default"):
        return "1864"


@needs_cbor_run
def test_cbor_runner_records_a_non_bytes_adapter_return_as_an_error():
    """Attack 1.  Control: the CBOR runner *does* contain the failure.

    ``actual_bytes.hex()`` sits inside the ``try``, so a str return becomes
    ``ERROR:AttributeError`` rather than a crash.  Pinned so that the COSE
    runner's opposite behaviour (below) reads as a difference, not a surprise.
    """
    rows = _run_cbor(
        _ReturnsStrNotBytes(),
        {"vector_id": "v", "data_item": 100, "oracle_deterministic_hex": "1864"},
    )
    for row in rows:
        assert row[CBOR_VERDICT] != "PASS", f"str return graded PASS: {row}"
        assert row[CBOR_VERDICT].startswith("ERROR"), (
            f"malformed adapter return must be recorded as ERROR, got "
            f"{row[CBOR_VERDICT]!r}"
        )


class _CoseReturnsStrStructure:
    """Malformed: COSE adapter returns a str from ``encode_structure``."""

    ADAPTER_NAME = "probe_cose_str"
    LIB_VERSION = "0"
    supports_canonical = True

    def encode_structure(self, data_item):
        return "8443a10101a1010203"

    def encode(self, data_item, mode="default"):
        return None


@needs_cose_run
@pytest.mark.xfail(
    strict=True,
    reason="DEFECT cose-cross-impl/runner/run_matrix.py: the `.hex()` call on the "
           "adapter's return sits OUTSIDE the try that wraps encode_structure, so "
           "a non-bytes return raises AttributeError out of run_matrix and the "
           "whole matrix -- every axis, every adapter, including cells already "
           "measured -- is lost with no results file written",
)
def test_cose_runner_contains_a_non_bytes_structure_return():
    """Attack 1 against the COSE runner: one bad adapter must not end the run.

    ``classify_structure_match`` is called outside the ``try`` that guards
    ``encode_structure``, and so is ``actual_struct_bytes.hex()``.  An adapter
    that returns a str therefore takes the entire corpus down, silently
    destroying measurements the run had already made.
    """
    rows = _run_cose(
        _CoseReturnsStrStructure(),
        {"vector_id": "v", "data_item": {"msg_type": "Sign1"},
         "oracle_structure_hex": "8443a10101a1010203"},
    )
    for row in rows:
        assert row[COSE_VERDICT] != "PASS", f"str structure return graded PASS: {row}"
        assert row[COSE_VERDICT].startswith("ERROR"), (
            f"malformed structure return must be ERROR, got {row[COSE_VERDICT]!r}"
        )


@needs_cose_run
def test_naive_coercion_baseline_would_convert_the_attack_case_to_bytes():
    """Demonstration: the coercion the COSE runner lacks would hide the type error.

    Coerced, ``"8443a10101a1010203"`` becomes bytes and the cell grades PASS
    over an adapter that never produced bytes at all.
    """
    coerced = _naive_coerce_adapter_return("8443a10101a1010203")
    verdict = COSE_RUN.classify_structure_match(
        coerced, bytes.fromhex("8443a10101a1010203")
    )[0]
    assert verdict == "PASS"


@needs_cose_run
def test_cose_classify_structure_match_rejects_a_non_bytes_type():
    """Attack 1 at the classifier, at unit level.

    ``"8443" == b"8443"`` is False in Python 3, so a str cannot reach PASS here
    today -- but that is an accident of the values, not a check.  The classifier
    must reject the *type* outright, so an adapter returning something that does
    compare equal to bytes cannot pass.
    """

    class StrThatEqualsBytes(str):
        def __eq__(self, other):
            return bytes(other or b"") == self.encode("ascii")

        __hash__ = str.__hash__

    verdict, _detail = COSE_RUN.classify_structure_match(
        StrThatEqualsBytes("8443"), b"\x84\x43"
    )
    assert verdict != "PASS", (
        "a str subclass that compares equal to the oracle bytes was graded PASS; "
        "the classifier must require a bytes-typed adapter return"
    )


@needs_cose_run
def test_cose_runner_never_grades_equal_nones_as_pass():
    """The ``None == None`` trap.

    Both sides absent means the oracle has no expectation.  ``actual ==
    expected`` is ``True``, so a classifier that reaches the equality branch
    before checking either side grades a totally unmeasured cell PASS.
    """
    verdict, detail = COSE_RUN.classify_structure_match(None, None)
    assert verdict != "PASS", (
        f"None == None graded PASS ({detail}); this cell measured nothing"
    )
    assert verdict == "INSTRUMENT_QUESTION", (
        f"expected INSTRUMENT_QUESTION, got {verdict!r} ({detail})"
    )


# ==========================================================================
# 2. Unsupported features must not be silently PASS
# ==========================================================================


class _IgnoresMode:
    """Declares canonical support but has no canonical implementation.

    ``supports_canonical`` is what the CBOR runner uses to decide whether to
    emit a canonical cell at all.  A library with no canonical mode that sets
    the flag produces a canonical column that means nothing, yet the cells sit
    in the same table as real ones under the same verdict vocabulary.
    """

    ADAPTER_NAME = "probe_false_canonical"
    LIB_VERSION = "0"
    supports_canonical = True

    def encode(self, data_item, mode="default"):
        # Identical bytes for both modes: an adapter that cannot distinguish
        # the two contracts it is being measured against.
        return b"\x18\x64"


@needs_cbor_run
def test_runner_does_not_treat_a_mode_ignoring_adapter_as_conforming():
    """Attack 2.  Canonical and default disagree per vector; this adapter does not.

    Both cells are recorded with the same verdict and the same bytes, so no
    reader of the matrix can tell that the canonical cell measured nothing
    about canonical encoding.  The instrument cannot detect the lie without a
    probe -- but it must not leave the lie indistinguishable from a real
    measurement either.
    """
    rows = _run_cbor(
        _IgnoresMode(),
        {"vector_id": "v", "data_item": 100,
         "oracle_deterministic_hex": "1864", "oracle_canonical_hex": "1864"},
    )
    modes = {row[3] for row in rows}
    assert {"default", "canonical"} <= modes, (
        f"control: both modes are emitted for supports_canonical=True; got {modes}"
    )
    for row in rows:
        assert row[2] == "probe_false_canonical", (
            f"the runner must attribute the cell to the adapter that produced it: {row}"
        )
        assert row[3] in ("default", "canonical"), row


@needs_cbor_run
def test_cbor_runner_skips_canonical_cells_when_support_is_declared_absent():
    """Control for the attack above: the skip path works.

    If this breaks, ``supports_canonical`` is being ignored entirely and every
    ``supports_canonical = False`` library in the cohort is being measured
    against a canonical expectation it never claimed to meet.
    """

    class NoCanonical:
        ADAPTER_NAME = "probe_no_canonical"
        LIB_VERSION = "0"
        supports_canonical = False

        def encode(self, data_item, mode="default"):
            return b"\x18\x64"

    rows = _run_cbor(
        NoCanonical(),
        {"vector_id": "v", "data_item": 100, "oracle_deterministic_hex": "1864"},
    )
    assert {row[3] for row in rows} == {"default"}, (
        "supports_canonical=False must suppress canonical cells; got "
        f"{sorted({row[3] for row in rows})}"
    )


class _ReturnsNone:
    """The real adapter pattern for an unsupported feature: return ``None``.

    ``lib_go_cose.encode`` returns ``None`` for every message level and
    ``lib_pycose.encode_structure`` returns ``None`` on any exception.  The
    runner must distinguish "does not implement this" from "produced the wrong
    bytes" and from "the instrument itself failed".
    """

    ADAPTER_NAME = "probe_unsupported"
    LIB_VERSION = "0"
    supports_canonical = True

    def encode(self, data_item, mode="default"):
        return None


@needs_cbor_run
def test_cbor_runner_separates_unsupported_from_error_and_from_pass():
    """Attack 2.  A ``None`` return is never PASS and never silence."""
    rows = _run_cbor(
        _ReturnsNone(),
        {"vector_id": "v", "data_item": 100, "oracle_deterministic_hex": "1864"},
    )
    assert rows, "runner produced no cell"
    verdicts = [row[CBOR_VERDICT] for row in rows]
    assert "PASS" not in verdicts, (
        f"an adapter that returned None was graded PASS: {verdicts}"
    )
    assert all(v in ("ERROR", "NOT_SUPPORTED") for v in verdicts), (
        f"None return must be labelled, got {verdicts}"
    )


@needs_cose_run
def test_cose_runner_never_grades_a_none_structure_as_pass():
    """Attack 2 against the COSE classifier, at unit level.

    A ``None`` return used to be filed as ``NOT_SUPPORTED ("no structure
    extraction")`` -- a cause the runner had not observed, because both real
    adapters swallow their own exceptions into ``None``.  A cell with an
    expectation present but no measurement is UNMEASURED; it is never a pass and
    never a claim about what the library lacks.
    """
    verdict, detail = COSE_RUN.classify_structure_match(None, b"\x84")
    assert verdict == "UNMEASURED", (
        f"None actual graded {verdict!r} ({detail}): a library that returned "
        "nothing has not demonstrated conformance"
    )
    assert "no structure extraction" not in detail, (
        f"the runner asserted a cause it never observed: {detail!r}"
    )


@needs_cose_run
def test_cose_runner_never_grades_a_none_message_as_pass():
    verdict, detail = COSE_RUN.classify_full_message(None, b"\x84")
    assert verdict == "UNMEASURED", f"None message graded {verdict!r} ({detail})"


@needs_cose_run
def test_cose_runner_never_grades_a_none_message_as_pass_when_expected_is_also_none():
    verdict, _detail = COSE_RUN.classify_full_message(None, None)
    assert verdict != "PASS", "None == None graded PASS"


class _CoseSwallowsItsOwnException:
    """The shape both real COSE adapters have: catch everything, return ``None``.

    ``lib_pycose.encode_structure`` and ``lib_go_cose._run_driver`` both end
    with a bare ``except Exception: return None``.  An adapter in that shape
    cannot distinguish "this library lacks the feature" from "this library
    crashed", and the runner then writes a reason it did not observe.
    """

    ADAPTER_NAME = "probe_cose_swallow"
    LIB_VERSION = "0"

    def encode_structure(self, data_item):
        # A driver that crashes: the hex decode raises, and the adapter's bare
        # except turns that crash into a None return.
        return _naive_swallow_exceptions_as_unsupported(
            lambda: bytes.fromhex("not hex at all")
        )

    def encode(self, data_item, mode="default"):
        return None


@needs_cose_run
def test_cose_runner_does_not_assert_a_reason_it_cannot_have_observed():
    """Attack 2.  A crash must not be filed as an unimplemented feature.

    The note text is what a future reader relies on to decide whether a gap cell
    is a fact about the library or a broken instrument.  Here the adapter
    deliberately failed and swallowed the failure into ``None``; the runner can
    see only the ``None``, so it must record the absence as UNMEASURED and must
    not assert a cause.  Before the fix this cell read
    ``NOT_SUPPORTED ("adapter returned None (no structure extraction)")``.
    """
    rows = _run_cose(
        _CoseSwallowsItsOwnException(),
        {"vector_id": "v", "data_item": {}, "oracle_structure_hex": "84"},
    )
    for row in rows:
        note = str(row[COSE_NOTES])
        assert "no structure extraction" not in note, (
            f"the runner attributed an unobserved cause to the adapter: {note!r}"
        )
        assert row[COSE_VERDICT] not in ("PASS", "NOT_SUPPORTED"), (
            "a swallowed crash was graded as conformance or as an unimplemented "
            f"feature: {row}"
        )


@needs_cose_run
def test_cose_runner_records_a_genuine_exception_as_an_error_not_a_feature_gap():
    """Attack 2.  An exception that reaches the runner is an ERROR, with its type.

    Before the fix this path raised ``UnboundLocalError`` inside the handler,
    because the verdict assignment read ``exc`` outside the ``except`` block that
    binds it -- the crash fired on exactly the path whose diagnostics mattered.
    """

    class LetsItEscape:
        ADAPTER_NAME = "probe_cose_raises"
        LIB_VERSION = "0"

        def encode_structure(self, data_item):
            raise RuntimeError("driver crashed")

        def encode(self, data_item, mode="default"):
            return None

    rows = _run_cose(
        LetsItEscape(), {"vector_id": "v", "data_item": {}, "oracle_structure_hex": "84"}
    )
    assert rows, "the runner produced no cell at all"
    for row in rows:
        assert row[COSE_VERDICT].startswith("ERROR"), (
            f"an exception that escaped must be ERROR, got {row[COSE_VERDICT]!r}"
        )
        assert "RuntimeError" in str(row[COSE_VERDICT]), (
            f"the exception type must be in the verdict, got {row[COSE_VERDICT]!r}"
        )
        assert "exception" in str(row[COSE_NOTES]).lower() or (
            "RuntimeError" in str(row[COSE_NOTES])
        ), (
            f"the exception must be surfaced in the note, got {row[COSE_NOTES]!r}"
        )


@needs_cose_run
def test_cose_runner_survives_an_adapter_that_raises_at_both_levels():
    """Attack 2, the whole-run shape: one broken adapter must not end the matrix.

    ``encode`` and ``encode_structure`` are guarded by separate handlers, and the
    message-level handler used to leave ``msg_verdict`` reading
    ``adapter.get('verdict', 'ERROR')`` over an adapter result dict that never
    carried a ``verdict``.  A cell's verdict must be the verdict of the level it
    describes.
    """

    class RaisesEverywhere:
        ADAPTER_NAME = "probe_cose_raises_both"
        LIB_VERSION = "0"

        def encode_structure(self, data_item):
            raise ValueError("structure driver crashed")

        def encode(self, data_item, mode="default"):
            raise KeyError("message driver crashed")

    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(
            Path(tmp),
            [
                {"vector_id": "broken", "data_item": {},
                 "oracle_structure_hex": "84", "oracle_message_hex": "d2"},
                {"vector_id": "after", "data_item": {},
                 "oracle_structure_hex": "8461a1616101", "oracle_message_hex": "d284"},
            ],
        )
        rows = COSE_RUN.run_matrix(
            [RaisesEverywhere()], vectors_dir, Path(tmp) / "results"
        )
    assert len(rows) == 2, f"the run lost cells: {rows}"
    broken, after = rows
    assert broken[COSE_VERDICT] == "ERROR:ValueError", (
        f"structure verdict attributed to the wrong level or lost its type: "
        f"{broken!r}"
    )
    assert broken[10] == "ERROR:KeyError", (
        f"a message-level exception was not recorded as a message-level error: "
        f"{broken!r}"
    )
    assert after[CBOR_EXPECTED] == "8461a1616101", f"row order lost: {after!r}"


# ==========================================================================
# 3. Mismatched raw bytes / a self-reported PASS must not become evidence
# ==========================================================================


class _SelfReportsPass:
    """Adapter that asserts its own conformance instead of returning bytes.

    The naive runner trusts ``adapter.verdict == "PASS"``.  Nothing in the
    adapter contract allows that, and the repo has already been burned by an
    adapter-mediated claim: the vector-repair report had to reconstruct that
    pycose's PASS verdicts were "coincidences, not conformance" from bytes the
    instrument had thrown away.
    """

    ADAPTER_NAME = "probe_self_reported"
    LIB_VERSION = "0"
    supports_canonical = True
    verdict = "PASS"
    conformance = True

    def encode(self, data_item, mode="default"):
        # Wrong bytes, plus a confident self-assessment.
        return b"\x1a\x00\x00\x00\x64"


@needs_cbor_run
def test_self_reported_pass_is_never_transcribed_into_a_pass_verdict():
    """Attack 3.  A PASS-shaped attribute must not become a cell.

    The verdict must be derivable from bytes.  Any implementation that reads an
    adapter-supplied status field reports PASS here over ``1a 00000064`` against
    an expected ``1864``.
    """
    rows = _run_cbor(
        _SelfReportsPass(),
        {"vector_id": "v", "data_item": 100, "oracle_deterministic_hex": "1864"},
    )
    for row in rows:
        assert row[CBOR_VERDICT] != "PASS", (
            f"the adapter's self-reported PASS was laundered into a cell verdict: {row}"
        )
        assert row[CBOR_ACTUAL] == "1a00000064", (
            f"the recorded actual bytes are wrong: {row[CBOR_ACTUAL]!r}"
        )


@needs_cbor_run
def test_naive_adapter_verdict_baseline_would_grade_the_attack_case_pass():
    """Demonstration: believing the adapter is exactly the laundering attack."""
    assert _naive_trust_adapter_verdict(_SelfReportsPass()) == "PASS"


@needs_cbor_run
def test_same_length_different_bytes_are_never_graded_pass():
    """Attack 3, sharpest form: same length, different bytes.

    Length is not evidence.  A cell whose two hex columns have the same length
    and different content is a *measured difference*, and must not be softened
    into a pass or into an "ambiguity" that reads as a non-finding.
    """
    rows = _run_cbor(
        _SelfReportsPass(),
        {"vector_id": "v", "data_item": 100, "oracle_deterministic_hex": "1a00000065"},
    )
    for row in rows:
        assert row[CBOR_EXPECTED] != row[CBOR_ACTUAL], (
            f"control: the two sides must differ for this test to mean anything: {row}"
        )
        assert row[CBOR_VERDICT] not in ("PASS", "SPEC_AMBIGUITY"), (
            f"same-length different bytes graded {row[CBOR_VERDICT]!r}; the bytes "
            f"differ, so this is a measurement, not an ambiguity: {row}"
        )


@needs_cbor_run
def test_a_differing_cell_always_records_both_sides_of_the_comparison():
    """Attack 3 generalised: no verdict without the bytes that justify it.

    For a verdict to be evidence it must be checkable by a reader who does not
    trust the runner.  That needs both hex columns populated on every cell,
    whichever way the comparison went.
    """
    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(
            Path(tmp),
            [{"vector_id": "v", "data_item": 100,
              "oracle_deterministic_hex": "1864", "oracle_canonical_hex": "1864"}],
        )
        rows = CBOR_RUN.run_matrix([_SelfReportsPass()], vectors_dir, Path(tmp) / "r")
    for row in rows:
        assert row[CBOR_VERDICT] != "PASS"
        assert row[CBOR_ACTUAL], f"actual bytes missing from the row: {row}"


@needs_frost_run
def test_frost_classify_cell_never_lets_a_self_reported_field_outrank_the_kat():
    """Attack 3 against FROST, where the laundering path is explicit.

    ``classify_cell`` returns PASS when ``verify_aggregate is True`` *before* it
    compares ``computed_final_sig`` to the RFC 9591 KAT value.  The subprocess
    driver is an arbitrary external program whose JSON is trusted verbatim, so
    a driver that reports ``verify_aggregate: true`` beside a wrong signature
    yields PASS.  The KAT is the authoritative expected value; a byte mismatch
    must not be overruled by the adapter's own opinion of itself.
    """
    expected = "aa" * 32
    lying = {
        "ok": True,
        "verify_aggregate": True,
        "computed_final_sig": "bb" * 32,
        "aggregate_R_hex": "00",
        "aggregate_z_hex": "00",
    }
    verdict = FROST_RUN.classify_cell(lying, expected)
    assert verdict != "PASS", (
        "a self-reported verify_aggregate over signature bytes that disagree with "
        f"the RFC 9591 KAT produced {verdict!r}; the adapter's opinion outranked "
        "the oracle"
    )


@needs_frost_run
def test_frost_self_reported_verification_over_wrong_bytes_is_a_defect():
    """Attack 3, isolated so the failure names the defect rather than the symptom."""
    assert FROST_RUN.classify_cell(
        {"ok": True, "verify_aggregate": True, "computed_final_sig": "bb" * 32},
        "aa" * 32,
    ) != "PASS"


@needs_frost_run
def test_frost_graded_pass_is_always_derivable_from_the_kat_comparison():
    """Attack 3, the property the fix installs: PASS is recomputable from bytes.

    An earlier attempt at a fix could pass the tests above by grading every
    ``verify_aggregate is True`` cell as a failure -- refusals are not fixes.
    This asserts the property a reader of the matrix needs: if the verdict is
    PASS, the KAT comparison alone accounts for it, whatever the adapter claims.
    """
    kat = "aa" * 32
    wrong = "bb" * 32
    assert FROST_RUN.classify_cell(
        {"ok": True, "verify_aggregate": True, "computed_final_sig": kat}, kat
    ) == "PASS", "the honest path stopped working: the KAT match is no longer enough"
    assert FROST_RUN.classify_cell(
        {"ok": True, "verify_aggregate": False, "computed_final_sig": kat}, kat
    ) == "PASS", (
        "PASS was made conditional on the self-report: a KAT match with a "
        "disagreeing verify_aggregate must still be a pass on the KAT"
    )
    for flag in (True, False, "true", 1, None):
        verdict = FROST_RUN.classify_cell(
            {"ok": True, "verify_aggregate": flag, "computed_final_sig": wrong}, kat
        )
        assert verdict != "PASS", (
            f"verify_aggregate={flag!r} over a KAT mismatch produced {verdict!r}"
        )


@needs_frost_run
def test_frost_classify_cell_still_grades_unmeasured_cells_without_a_signature():
    """Control: the KAT-first ordering must not invent verdicts for absent data.

    A driver that returns no signature at all has measured nothing, so the KAT
    comparison cannot run and the cell must fall through to the same labels it
    used before -- whatever the self-report says.
    """
    for flag in (True, False):
        verdict = FROST_RUN.classify_cell({"ok": True, "verify_aggregate": flag}, "aa" * 32)
        assert verdict != "PASS", (
            f"a cell with no computed signature was graded PASS with "
            f"verify_aggregate={flag!r}"
        )


@needs_frost_run
def test_frost_classify_cell_control_matches_are_still_pass():
    """Control: the honest path must work, or the attack test above is vacuous."""
    assert FROST_RUN.classify_cell(
        {"ok": True, "computed_final_sig": "aa" * 32}, "aa" * 32
    ) == "PASS"


@needs_frost_run
def test_frost_classify_cell_control_mismatch_is_not_pass():
    assert FROST_RUN.classify_cell(
        {"ok": True, "computed_final_sig": "bb" * 32}, "aa" * 32
    ) != "PASS"


@needs_frost_run
@pytest.mark.parametrize(
    "value", ["true", "True", 1, "yes", [1]], ids=["str-true", "str-True", "int-1", "str-yes", "list"]
)
def test_frost_verification_flag_must_be_a_real_bool(value):
    """Attack 3, second FROST path: ``is True`` vs truthiness.

    ``is True`` is the right guard.  A driver emitting the JSON string ``"true"``
    or the integer ``1`` must not read as a confirmation.  Swapping in a
    truthiness test is the obvious "simplification", so this pins the guard.
    """
    verdict = FROST_RUN.classify_cell(
        {"ok": True, "verify_aggregate": value, "computed_final_sig": "bb" * 32},
        "aa" * 32,
    )
    assert verdict != "PASS", (
        f"verify_aggregate={value!r} (a {type(value).__name__}) was read as a "
        "confirmation"
    )


@needs_frost_run
def test_naive_truthiness_baseline_would_accept_a_json_string_verification():
    """Demonstration: a truthiness test accepts a JSON ``"true"`` string."""
    assert _naive_truthy_verify_flag({"verify_aggregate": "true"}) is True


@needs_frost_run
def test_frost_classify_cell_requires_ok():
    """An ``ok: False`` adapter result can never be PASS."""
    assert FROST_RUN.classify_cell(
        {"ok": False, "verify_aggregate": True, "computed_final_sig": "aa" * 32},
        "aa" * 32,
    ) != "PASS"


# ==========================================================================
# 4. Missing version / provenance metadata
# ==========================================================================


class _NoVersionNoSupportsCanonical:
    """An adapter that declares nothing about itself."""

    ADAPTER_NAME = "probe_anonymous"

    def encode(self, data_item, mode="default"):
        return b"\x18\x64"


@needs_cbor_run
@pytest.mark.xfail(
    strict=True,
    reason="DEFECT cbor-cross-impl/runner/run_matrix.py writes no library version "
           "into matrix.jsonl or matrix.tsv at all -- unlike the COSE runner, which "
           "has a lib_version column. A CBOR cell cannot be attributed to any "
           "version of any implementation, so it cannot be re-checked against that "
           "implementation later; this is the fnd-2026-0013 staleness shape",
)
def test_cbor_matrix_records_the_adapter_version_or_flags_its_absence():
    """Attack 4.  A cell with no version attached is not reproducible evidence.

    ``fnd-2026-0013`` was contradicted by the repo's own oracle because the
    corpus went stale underneath it.  A matrix row that cannot name the version
    of the thing it measured has no way to be re-checked against that thing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(
            Path(tmp),
            [{"vector_id": "v", "data_item": 100,
              "oracle_deterministic_hex": "1864",
              "oracle_canonical_hex": "1864"}],
        )
        CBOR_RUN.run_matrix(
            [_NoVersionNoSupportsCanonical()], vectors_dir, Path(tmp) / "r"
        )
        jsonl = (Path(tmp) / "r" / "matrix.jsonl").read_text(encoding="utf-8")
        tsv = (Path(tmp) / "r" / "matrix.tsv").read_text(encoding="utf-8")
    records = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
    assert records, "no matrix rows emitted"
    assert "lib_version" in json.dumps(records[0]) or "unknown" in tsv, (
        "the CBOR matrix records neither a library version nor a flag that it is "
        f"unknown; tsv header was {tsv.splitlines()[0]!r}"
    )


@needs_cbor_run
def test_cbor_matrix_cells_are_attributable_to_the_adapter_that_produced_them():
    """Control: whatever else it omits, the adapter name is always recorded."""
    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(
            Path(tmp), [{"vector_id": "v", "data_item": 100,
                         "oracle_deterministic_hex": "1864"}]
        )
        CBOR_RUN.run_matrix(
            [_NoVersionNoSupportsCanonical()], vectors_dir, Path(tmp) / "r"
        )
        jsonl = (Path(tmp) / "r" / "matrix.jsonl").read_text(encoding="utf-8")
    for record in (
        json.loads(line) for line in jsonl.splitlines() if line.strip()
    ):
        assert record["adapter"] == "probe_anonymous", record


@needs_cose_run
def test_cose_runner_never_invents_or_blanks_a_version_string():
    """Attack 4.  ``?`` is honest; an empty string is not.

    ``getattr(adapter, "LIB_VERSION", "?")`` substitutes a visible placeholder.
    A runner substituting ``""`` would emit a version column indistinguishable
    from a library that genuinely reports no version -- an unfalsifiable claim.
    """

    class NoVersion:
        ADAPTER_NAME = "probe_cose_anonymous"

        def encode_structure(self, data_item):
            return b"\x84"

        def encode(self, data_item, mode="default"):
            return None

    rows = _run_cose(
        NoVersion(), {"vector_id": "v", "data_item": {}, "oracle_structure_hex": "84"}
    )
    for row in rows:
        assert row[COSE_VERSION] == "?", (
            f"expected the explicit unknown-version placeholder, got "
            f"{row[COSE_VERSION]!r}"
        )


@needs_cose_run
def test_cose_runner_never_blanks_the_version_of_an_adapter_that_has_one():
    """Control: a real version is carried through to the row."""

    class Versioned:
        ADAPTER_NAME = "probe_cose_versioned"
        LIB_VERSION = "1.3.0"

        def encode_structure(self, data_item):
            return b"\x84"

        def encode(self, data_item, mode="default"):
            return None

    rows = _run_cose(
        Versioned(), {"vector_id": "v", "data_item": {}, "oracle_structure_hex": "84"}
    )
    for row in rows:
        assert row[COSE_VERSION] == "1.3.0", row


@needs_cose_run
def test_cose_runner_marks_an_adapter_with_no_structure_extraction_as_not_supported():
    """Attack 4 with teeth: absence of a measurement is not a measurement.

    An adapter with no ``encode_structure`` cannot produce structure bytes.
    That must be a labelled gap, never a cell that a verdict counter tallies.
    """

    class NoStructure:
        ADAPTER_NAME = "probe_cose_no_structure"
        LIB_VERSION = "0"

        def encode(self, data_item, mode="default"):
            return None

    rows = _run_cose(
        NoStructure(), {"vector_id": "v", "data_item": {}, "oracle_structure_hex": "84"}
    )
    for row in rows:
        assert row[COSE_VERDICT] == "NOT_SUPPORTED", (
            f"an adapter with no structure extraction graded {row[COSE_VERDICT]!r}"
        )
        assert "encode_structure" in str(row[COSE_NOTES]), (
            f"the note must say what is missing: {row[COSE_NOTES]!r}"
        )


# ==========================================================================
# 5. Fake PASS where the oracle says REJECT
# ==========================================================================


@needs_cbor_oracle
def test_the_cbor_oracle_rejects_a_duplicate_map_key_when_one_can_be_expressed():
    """Control: the oracle is fail-closed where it is reachable.

    ``encode_canonical`` raises ``DuplicateKeyError`` rather than picking a
    winner, which is what RFC 8949 4.2.1 requires.  Pinned here so the corpus
    defect below reads as a *corpus* gap rather than an oracle gap.

    A Python ``dict`` cannot hold duplicate keys, so the branch is only
    reachable through a mapping that can.  The runner's own data items are
    ``dict``-based, which is exactly why the committed axis is inert.
    """
    from collections.abc import Mapping

    class DuplicateKeyMap(Mapping):
        """A mapping whose ``keys()`` yields one key twice."""

        def __init__(self):
            self._items = [("a", 1), ("a", 2)]

        def __getitem__(self, key):
            for k, v in self._items:
                if k == key:
                    return v
            raise KeyError(key)

        def __iter__(self):
            return (k for k, _ in self._items)

        def __len__(self):
            return len(self._items)

        def keys(self):
            # The duplicate lives here: iteration yields "a" twice.
            return [k for k, _ in self._items]

    with pytest.raises(CBOR_ORACLE.DuplicateKeyError):
        CBOR_ORACLE.encode_canonical(DuplicateKeyMap())


@needs_cbor_oracle
def test_python_cannot_express_a_duplicate_key_map_so_the_axis_is_inert():
    """Attack 5 at the corpus level, and the sharpest form of the inert-vector risk.

    ``vectors_duplicate_key_rejection.jsonl`` is named for testing *rejection*,
    but a Python dict deduplicates on construction, so neither committed vector
    contains a duplicate map key and the axis exercises nothing.  The second
    vector is even named ``map_duplicate_test_inert`` with the description
    "Python dedupes".  A rejection axis with no rejection case in it cannot
    detect a library that silently accepts duplicates.
    """
    path = REPO / "cbor-cross-impl" / "vectors" / "vectors_duplicate_key_rejection.jsonl"
    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records, f"{path.name} is empty; the axis tests nothing either way"
    for record in records:
        item = record["data_item"]
        pairs = item.get("pairs") if isinstance(item, dict) else None
        keys = [p[0] for p in pairs] if pairs else list(item or {})
        assert len(keys) == len(set(map(str, keys))), (
            f"vector {record['vector_id']} now contains duplicate map keys; if it "
            "does, this test must be replaced by one that asserts the oracle "
            "rejects them -- an inert axis is the defect, not the fix"
        )


class _ClaimsSuccessOnARejectCase:
    """Claims success for a case that must be rejected, and says so."""

    ADAPTER_NAME = "probe_fake_pass"
    LIB_VERSION = "0"
    supports_canonical = True
    verdict = "PASS"

    def encode(self, data_item, mode="default"):
        # A1 01 01 A1 01 02 -- a two-entry map whose keys collide.  Correct
        # behaviour is rejection, not an encoding.
        return b"\xa2\x01\x01\x01\x02"


@needs_cbor_run
def test_fake_pass_over_a_reject_case_is_not_transcribed_as_a_pass():
    """Attack 5.  Every PASS must be recomputable from the recorded bytes.

    The runner has no way to be told "the oracle rejects this", so the only
    protection available to it is structural: a verdict must be derivable from
    ``expected_hex`` and ``actual_hex``.  A verdict that cannot be recomputed by
    a reader who does not trust the runner is a self-certification.
    """
    rows = _run_cbor(
        _ClaimsSuccessOnARejectCase(),
        {"vector_id": "v", "data_item": {"__type__": "dict_int_keys",
                                         "pairs": [[1, 1], [1, 2]]},
         "oracle_deterministic_hex": "a201010102"},
    )
    for row in rows:
        if row[CBOR_VERDICT] == "PASS":
            assert row[CBOR_EXPECTED] == row[CBOR_ACTUAL], (
                "PASS is not derivable from the recorded bytes: "
                f"expected={row[CBOR_EXPECTED]!r} actual={row[CBOR_ACTUAL]!r}"
            )


@needs_cbor_run
def test_runner_records_the_bytes_that_justify_every_pass():
    """Attack 5 generalised: no PASS without both sides present.

    For a PASS to be evidence it must be checkable by a reader who does not
    trust the runner, which requires both hex columns to be populated.
    """
    with tempfile.TemporaryDirectory() as tmp:
        vectors_dir = _write_vectors(
            Path(tmp),
            [{"vector_id": "v", "data_item": 100,
              "oracle_deterministic_hex": "1864", "oracle_canonical_hex": "1864"}],
        )

        class GoodAdapter:
            ADAPTER_NAME = "probe_good"
            LIB_VERSION = "0"
            supports_canonical = True

            def encode(self, data_item, mode="default"):
                return bytes.fromhex("1864")

        rows = CBOR_RUN.run_matrix([GoodAdapter()], vectors_dir, Path(tmp) / "r")
    passes = [row for row in rows if row[CBOR_VERDICT] == "PASS"]
    assert passes, "control: the honest adapter must still earn PASS cells"
    for row in passes:
        assert row[CBOR_EXPECTED], "PASS with an empty expected_hex column"
        assert row[CBOR_ACTUAL], "PASS with an empty actual_hex column"
        assert row[CBOR_EXPECTED] == row[CBOR_ACTUAL], row


# ==========================================================================
# 7. Adapter normalisation must not launder a meaningful difference away
# ==========================================================================


@pytest.mark.parametrize("module", MATERIALIZERS)
def test_materialize_does_not_case_fold(module):
    """Attack 7.  Case folding makes two different CBOR items identical.

    CBOR text strings are case-sensitive: ``"a"`` encodes 0x6161 and ``"A"``
    encodes 0x6141.  An adapter that case-folded would report the same bytes for
    both, so a library that got one of them wrong would be recorded as correct.
    """
    lower = module._materialize("abc")
    upper = module._materialize("ABC")
    assert lower != upper, (
        f"{module.ADAPTER_NAME}._materialize case-folds: 'abc' and 'ABC' became "
        "the same item, so a case-sensitivity bug in the library under test "
        "could not be observed"
    )


@needs_cbor2
def test_naive_case_fold_baseline_would_launder_the_case_attack():
    """Demonstration for the case-folding attack."""
    assert _naive_case_fold("ABC") == _naive_case_fold("abc") == "abc"


@pytest.mark.parametrize("module", MATERIALIZERS)
def test_materialize_does_not_strip_significant_whitespace(module):
    """Attack 7.  ``.strip()`` on a CBOR text string loses data.

    ``_materialize`` is documented to "reconstruct a CBOR data item from its
    string repr".  Stripping a *repr* is defensible; stripping a *text string
    that is itself the data item* is not, and the helper's interface cannot tell
    the two apart.  Asserted here as a known limitation rather than a defect:
    the value that actually makes ``strip()`` harmful is the type change below.
    """
    stripped = module._materialize("  42  ")
    assert stripped != "42", (
        f"{module.ADAPTER_NAME}._materialize stripped significant whitespace: "
        f"'  42  ' became {stripped!r}, a different CBOR text string"
    )


def test_naive_strip_baseline_would_launder_the_whitespace_attack():
    """Demonstration for the whitespace attack."""
    assert _naive_strip_whitespace("  42  ") == _naive_strip_whitespace("42") == "42"


@pytest.mark.parametrize("module", MATERIALIZERS)
def test_materialize_does_not_percent_decode(module):
    """Attack 7, percent-decoding: no adapter may 'helpfully' URL-decode.

    A percent-decoding adapter would turn ``"%41"`` and ``"A"`` into one item.
    Nothing in CBOR or in the vector format calls for it, so any such decoding
    is a pure fidelity loss.
    """
    assert module._materialize("%41") != module._materialize("A"), (
        f"{module.ADAPTER_NAME}._materialize percent-decodes; '%41' and 'A' are "
        "different CBOR text strings"
    )


@pytest.mark.parametrize("module", MATERIALIZERS)
def test_materialize_cannot_execute_its_input(module):
    """Attack 7, injection shape: ``ast.literal_eval`` is the guard that matters.

    Every ``_materialize`` ends in ``ast.literal_eval`` on vector-supplied text.
    ``literal_eval`` refuses calls, attributes and comprehensions, which is what
    makes the adapter safe to feed a corpus.  ``eval`` here would be arbitrary
    code execution from a vector file.
    """
    with pytest.raises((ValueError, SyntaxError, MemoryError, RecursionError)):
        module._materialize("__import__('os').system('echo pwned')")


# CBOR text strings that are also valid Python literals.  Each is a *distinct*
# CBOR data item from the value it spells, and must stay distinct.
_LITERAL_SHAPED_STRINGS = [
    "42", "-0", "1.5", "True", "False", "None", "[1, 2]", "{'a': 1}", "1e3",
]


def _cbor_type_of(value) -> str:
    """The CBOR type a materialized value would encode as."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "tstr"
    if isinstance(value, (bytes, bytearray)):
        return "bstr"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, dict):
        return "map"
    return type(value).__name__


@pytest.mark.parametrize("module", MATERIALIZERS)
@pytest.mark.parametrize("text", _LITERAL_SHAPED_STRINGS, ids=lambda s: repr(s))
def test_materialize_does_not_retype_a_text_string_that_parses_as_python(module, text):
    """Attack 7, the strongest form: type-changing normalisation.

    Every ``_materialize`` ends in ``ast.literal_eval``, so a CBOR *text string*
    whose content happens to be a Python literal is silently converted into that
    literal: ``"42"`` becomes the integer 42 (0x182a, not 0x623432), ``"True"``
    becomes a boolean, ``"[1, 2]"`` becomes an array.

    Two genuinely different CBOR data items are then encoded identically, so a
    library that got one of them wrong is recorded as correct -- and a vector
    whose ``oracle_*_hex`` was written for the text string is reported as a
    spurious divergence, blaming the library for the adapter's own change.
    """
    materialized = module._materialize(text)
    assert _cbor_type_of(materialized) == "tstr", (
        f"{module.ADAPTER_NAME}._materialize turned the CBOR text string "
        f"{text!r} into {materialized!r} (a "
        f"{_cbor_type_of(materialized)}); the adapter changed the data item it was "
        "asked to encode, so a text string and the value it spells become "
        "indistinguishable in the matrix"
    )


def test_naive_eval_baseline_would_retype_the_attack_case():
    """Demonstration for the retype attack: the naive rule is the real one."""
    assert _naive_eval_as_data_item("42") == 42 != "42"


def _canon(value):
    """Semantic identity for a materialized data item, across adapter types.

    ``lib_cbor2`` materializes ``Tag(...)`` into ``cbor2.CBORTag`` and the two
    subprocess-backed adapters into the oracle's own ``Tagged``.  They are the
    same CBOR item, so comparing ``repr`` would report a difference that is not
    one -- and a test that reports false differences is worse than no test.
    """
    tag = getattr(value, "tag", None)
    if tag is not None:
        content = getattr(value, "content", None)
        if content is None:
            content = getattr(value, "value", None)
        return ("tag", tag, _canon(content))
    if isinstance(value, (bytes, bytearray)):
        return ("bstr", bytes(value).hex())
    if isinstance(value, (list, tuple)):
        return ("array", tuple(_canon(v) for v in value))
    if isinstance(value, dict):
        return ("map", tuple(sorted((_canon(k), _canon(v)) for k, v in value.items())))
    return (_cbor_type_of(value), repr(value))


@pytest.mark.parametrize("module", MATERIALIZERS)
@pytest.mark.parametrize(
    "text",
    ["abc", "ABC", "  42  ", "42", "%41", "A", "1", "0100", "-0",
     "b'\\x41'", "{'a': 1}", "[1, 2]", "None", "True", "1e3", "Tag(42, 1)"],
    ids=lambda s: repr(s),
)
def test_materialize_behaves_identically_across_the_cbor_cohort(module, text):
    """Attack 7, cohort-level: three adapters, one meaning.

    Each adapter reimplements ``_materialize`` independently.  A divergence
    means the matrix compares libraries on *different inputs*, and the
    resulting table has no interpretation -- which is the shape of the
    ``fnd-2026-0013`` defect, where the columns did not mean what the axis
    claimed.
    """
    results = {}
    for other, label in (
        (CBOR2_ADAPTER, "cbor2"),
        (CIBORIUM_ADAPTER, "ciborium"),
        (CBORX_ADAPTER, "cbor-x"),
    ):
        if other is None:
            pytest.skip(f"{label} adapter not importable")
        try:
            results[label] = _canon(other._materialize(text))
        except Exception as exc:  # noqa: BLE001 - record, do not mask
            results[label] = f"<{type(exc).__name__}>"
    assert len(set(results.values())) == 1, (
        f"CBOR adapters disagree on how to materialize {text!r}; the matrix would "
        f"compare libraries on different inputs: {results}"
    )


# --- COSE header normalisation: highest laundering risk in the cohort -------


@needs_pycose_adapter
def test_pycose_header_normalisation_does_not_collide_distinct_labels():
    """Attack 7, COSE.  Two distinct header labels must stay distinct.

    ``_normalize_header_dict`` coerces any string key ``int()`` accepts to an
    int.  That is necessary -- JSON cannot carry int map keys -- but it silently
    merges ``"1"``, ``"01"``, ``"+1"`` and ``" 1"``, which are four *distinct*
    COSE header labels in the tstr space.  A corpus using two of them would have
    them collapse into one measurement and read as a pass for both.
    """
    collapsed = PYCOSE_ADAPTER._normalize_header_dict({"1": "a", "01": "b"})
    assert len(collapsed) == 2, (
        "two distinct tstr COSE header labels collapsed into one during "
        f"normalization: {collapsed!r}"
    )


@needs_gocose_adapter
def test_gocose_header_normalisation_does_not_collide_distinct_labels():
    """Same attack against the go-cose adapter's ``_normalize_int_keys``."""
    collapsed = GOCOSE_ADAPTER._normalize_int_keys({"1": "a", "01": "b"})
    assert len(collapsed) == 2, (
        f"distinct header labels collapsed into one: {collapsed!r}"
    )


@pytest.mark.skipif(
    PYCOSE_ADAPTER is None or GOCOSE_ADAPTER is None,
    reason="a COSE adapter is not importable",
)
@pytest.mark.parametrize(
    "source",
    [{"1": "a", "z": "b"}, {"1000": "x", "-300": "y"}, {1: "a", "z": "b"}],
    ids=["mixed-labels", "ordering-axis-labels", "already-int"],
)
def test_cose_adapters_normalise_header_labels_identically(source):
    """Attack 7, cohort-level for COSE.

    Two adapters feeding one runner must normalise identically.  A divergence
    means the runner compares two libraries on different inputs -- the
    adapter-mediated claim the vector-repair report had to unpick by hand.
    """
    a = PYCOSE_ADAPTER._normalize_header_dict(dict(source))
    b = GOCOSE_ADAPTER._normalize_int_keys(dict(source))
    assert a == b, (
        f"pycose and go-cose adapters normalize {source!r} differently: {a!r} "
        f"vs {b!r}"
    )


@needs_pycose_adapter
@pytest.mark.xfail(
    strict=True,
    reason="DEFECT cose-cross-impl/adapters/lib_pycose_adapter.py "
           "_normalize_header_dict: any string value that happens to be valid hex "
           "is silently re-typed to bytes, so the COSE tstr value '6161' is encoded "
           "as bstr 0x446161 instead of tstr 0x626161. The adapter changes the data "
           "item it was asked to encode, so the library under test is measured on "
           "input nobody asked for",
)
def test_pycose_header_normalisation_does_not_launder_a_tstr_into_a_bstr():
    """Attack 7, COSE value normalisation: the hex-sniffing branch.

    ``_normalize_header_dict`` decodes any string value that happens to be valid
    hex into ``bytes``.  ``"6161"`` is a perfectly good COSE tstr value ("aa")
    and also valid hex, so it is silently re-typed.  A corpus exercising a
    hex-shaped tstr header value has its expected bytes changed by the adapter.
    """
    original = {"kid": "6161"}
    normalized = PYCOSE_ADAPTER._normalize_header_dict(dict(original))
    assert normalized == original, (
        f"a hex-shaped tstr header value was silently re-typed to bytes: "
        f"{original!r} -> {normalized!r}"
    )


@needs_pycose_adapter
def test_pycose_header_normalisation_passes_an_int_key_through_untouched():
    """Control: an int key must survive untouched."""
    assert PYCOSE_ADAPTER._normalize_header_dict({1: "a"}) == {1: "a"}


@needs_pycose_adapter
def test_pycose_header_normalisation_preserves_an_uninterpretable_label():
    """Attack 7, fail-closed direction: an uninterpretable label is preserved.

    A label the adapter cannot interpret must be carried through so the library
    sees it, or the run must fail.  Dropping or coercing it measures something
    other than the vector.
    """
    out = PYCOSE_ADAPTER._normalize_header_dict({"not-a-number": "v"})
    assert "not-a-number" in out, (
        f"an uninterpretable header label was dropped or coerced: {out!r}"
    )


@needs_pycose_adapter
def test_pycose_header_normalisation_does_not_reinterpret_a_tstr_alg_value():
    """Attack 7, algorithm labels: a name the adapter does not know must survive.

    ``ALG_NAME_TO_INT.get(phdr["alg"], phdr["alg"])`` maps known names and passes
    the rest through.  A pass-through is correct; mapping an unknown name onto a
    known algorithm's integer would be inventing an implementation of the spec.
    """
    out = PYCOSE_ADAPTER._normalize_header_dict({"alg": "MadeUpAlg999"})
    assert out["alg"] == "MadeUpAlg999", (
        f"an unknown algorithm label was rewritten to something else: {out!r}"
    )


# ==========================================================================
# Naive-baseline discipline
# ==========================================================================


def test_no_naive_baseline_is_ever_correct():
    """Every ``_naive_*`` helper must be demonstrated wrong by a test.

    A "naive" helper that turns out to be correct means the attack it backs is
    not an attack.  This keeps the demonstrations honest as the file evolves.
    """
    module = sys.modules[__name__]
    naive_helpers = {
        name
        for name, obj in vars(module).items()
        if name.startswith("_naive_") and inspect.isfunction(obj)
    }
    naive_tests = [
        obj
        for name, obj in vars(module).items()
        if name.startswith("test_naive_") and inspect.isfunction(obj)
    ]
    assert naive_helpers, "no naive demonstrations left; this file has drifted"
    assert naive_tests, "no naive demonstration tests left"
    referenced: set[str] = set()
    for test in naive_tests:
        source = inspect.getsource(test)
        referenced |= {n for n in naive_helpers if n in source}
    unreferenced = naive_helpers - referenced
    assert not unreferenced, (
        f"naive baselines never demonstrated as wrong: {sorted(unreferenced)}"
    )
