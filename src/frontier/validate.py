"""Structural validation of the Frontier evidence graph.

Research state is machine-checked: required fields, ID/type agreement, status
vocabularies, promotion evidence rules, cross-reference resolution, duplicate
detection, and mission-directory/status consistency. ``validate_repo`` must
pass on a clean checkout; CI fails on any structural error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from frontier.ids import ArtifactId, IdError

EPISTEMIC_STATUSES = frozenset(
    {
        "idea",
        "assumption",
        "hypothesis",
        "observation",
        "interpretation",
        "verified_conclusion",
    }
)

ENVELOPE_FIELDS = (
    "id",
    "type",
    "status",
    "created_at",
    "updated_at",
    "summary",
    "epistemic_status",
    "provenance",
    "links",
)

DOMAINS = frozenset({"cryptography", "compilers", "formal", "interop"})

MISSION_TERMINAL = frozenset(
    {
        "verified",
        "disproved",
        "inconclusive-after-budget",
        "superseded",
        "abandoned-with-reason",
    }
)

BUDGET_FIELDS = (
    "max_attempts",
    "max_independent_reviews",
    "max_compute_runs",
    "diminishing_returns_window",
    "max_auto_descendants",
)

COMPUTE_CLASSES = frozenset({"lightweight", "medium", "heavy"})

EVIDENCE_LINKS = ("experiments", "observations", "reproducers", "reviews", "verifications")

VERIFICATION_METHODS = frozenset(
    {
        "executable",
        "formal-verifier",
        "differential",
        "deterministic-script",
        "reproduction",
    }
)

DISCLOSURE_VALUES = frozenset({"public", "embargoed", "escalate/security-sensitive"})

# Mission status -> allowed queue directories.
MISSION_DIRS = {
    "pending": {"pending"},
    "active": {"active"},
    "blocked-by-missing-evidence": {"active", "completed"},
}
_TERMINAL_MISSION_DIRS = {"completed", "archive", "embargoed"}

# Artifact type -> knowledge subdirectory names.
TYPE_DIRS = {
    "target": {"targets"},
    "specification": {"specifications"},
    "implementation": {"implementations"},
    "hypothesis": {"hypotheses"},
    "experiment": {"experiments"},
    "observation": {"observations"},
    "reproducer": {"reproducers"},
    "review": {"reviews"},
    "verification": {"verifications"},
    "finding": {"findings"},
    "conjecture": {"conjectures"},
    "proof": {"proofs"},
    "report": {"reports"},
}

_MISSION_QUEUE = ("pending", "active", "completed", "archive", "embargoed")
_INDEX_SKIP_DIRS = {"indices", "notes"}


@dataclass
class RepoValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _validate_mission(doc: dict, did: str) -> list[str]:
    errors: list[str] = []
    if doc.get("domain") not in DOMAINS:
        errors.append(f"{did}: unknown domain {doc.get('domain')!r}")
    budget = doc.get("budget")
    if not isinstance(budget, dict):
        errors.append(f"{did}: mission requires a budget object")
    else:
        for name in BUDGET_FIELDS:
            value = budget.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append(f"{did}: budget.{name} must be a non-negative integer")
    for list_field in ("acceptance_criteria", "stopping_conditions"):
        value = doc.get(list_field)
        if not isinstance(value, list) or not value:
            errors.append(f"{did}: mission requires non-empty {list_field}")
    compute = doc.get("compute")
    if not isinstance(compute, dict) or compute.get("expected_class") not in COMPUTE_CLASSES:
        errors.append(
            f"{did}: compute.expected_class must be one of {sorted(COMPUTE_CLASSES)}"
        )
    status = doc.get("status")
    if status in MISSION_TERMINAL and not doc.get("terminal_reason"):
        errors.append(
            f"{did}: terminal mission status {status!r} requires a terminal_reason"
        )
    return errors


def _validate_finding(doc: dict, did: str) -> list[str]:
    errors: list[str] = []
    links = doc.get("links") or {}
    if doc.get("status") == "verified":
        missing = [key for key in EVIDENCE_LINKS if not links.get(key)]
        if missing:
            errors.append(
                f"{did}: verified finding requires the full evidence chain "
                f"(missing links: {', '.join(missing)}); verification cannot be "
                "claimed without experiment, observation, reproducer, independent "
                "review, and deterministic verification"
            )
    disclosure = doc.get("disclosure")
    if disclosure is not None and disclosure not in DISCLOSURE_VALUES:
        errors.append(f"{did}: invalid disclosure {disclosure!r}")
    return errors


def _validate_verification(doc: dict, did: str) -> list[str]:
    method = doc.get("method")
    if method is not None and method not in VERIFICATION_METHODS:
        return [
            f"{did}: verification method {method!r} is not deterministic; "
            "agent-assertion can never serve as verification method"
        ]
    return []


def validate_document(doc: object) -> list[str]:
    """Validate a single artifact document. Empty list means valid."""
    if not isinstance(doc, dict):
        return ["document is not a mapping"]
    errors: list[str] = []
    did = doc.get("id")
    dtype = doc.get("type")
    label = str(did) if did else "<no-id>"

    for name in ENVELOPE_FIELDS:
        if name not in doc or doc[name] is None or doc[name] == "":
            errors.append(f"{label}: missing required envelope field {name!r}")

    if isinstance(did, str) and isinstance(dtype, str):
        try:
            aid = ArtifactId.parse(did)
            if not aid.matches_type(dtype):
                errors.append(
                    f"{did}: id prefix does not match declared type {dtype!r}"
                )
        except IdError as exc:
            errors.append(f"{label}: bad id ({exc})")

    epistemic = doc.get("epistemic_status")
    if epistemic is not None and epistemic not in EPISTEMIC_STATUSES:
        errors.append(f"{label}: invalid epistemic_status {epistemic!r}")

    provenance = doc.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        errors.append(f"{label}: provenance must be a mapping")
    links = doc.get("links")
    if links is not None and not isinstance(links, dict):
        errors.append(f"{label}: links must be a mapping")

    if dtype == "mission":
        errors.extend(_validate_mission(doc, label))
    elif dtype == "finding":
        errors.extend(_validate_finding(doc, label))
    elif dtype == "verification":
        errors.extend(_validate_verification(doc, label))
    return errors


def _iter_yaml_docs(root: Path):
    """Yield ``(relative_path, doc_or_error_dict)`` for repo YAML objects."""
    folders = [root / "missions" / name for name in _MISSION_QUEUE]
    knowledge_root = root / "knowledge"
    if knowledge_root.is_dir():
        folders.extend(
            child for child in sorted(knowledge_root.iterdir()) if child.is_dir()
        )
    for folder in folders:
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*.yaml")):
            rel = path.relative_to(root)
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception as exc:  # report malformed YAML, don't crash
                yield rel, {"__error__": str(exc)}
                continue
            if isinstance(doc, dict):
                yield rel, doc


def validate_repo(root: Path) -> RepoValidationResult:
    """Validate the whole repository research state."""
    root = Path(root)
    errors: list[str] = []
    warnings: list[str] = []

    entries = list(_iter_yaml_docs(root))
    docs: list[tuple[Path, dict]] = []
    seen_ids: dict[str, str] = {}
    defined_ids: set[str] = set()

    for rel, doc in entries:
        if "__error__" in doc:
            errors.append(f"{rel}: unparseable YAML: {doc['__error__']}")
            continue
        docs.append((rel, doc))
        did = doc.get("id")
        if isinstance(did, str) and did:
            if did in seen_ids:
                errors.append(
                    f"duplicate id {did} at {rel} (first seen at {seen_ids[did]})"
                )
            else:
                seen_ids[did] = str(rel)
            defined_ids.add(did)

    for rel, doc in docs:
        label = str(doc.get("id")) if doc.get("id") else str(rel)
        for message in validate_document(doc):
            errors.append(f"{rel}: {message}")
        _check_location(rel, doc, label, errors)
        _check_references(rel, doc, label, defined_ids, errors)

    return RepoValidationResult(ok=not errors, errors=errors, warnings=warnings)


def _parts_after_root(rel: Path) -> tuple[str, ...]:
    return rel.parts


def _check_location(rel: Path, doc: dict, label: str, errors: list[str]) -> None:
    parts = _parts_after_root(rel)
    if len(parts) < 3:
        return
    dtype = doc.get("type")
    if dtype == "mission":
        current_dir = parts[1]
        status = doc.get("status")
        allowed = MISSION_DIRS.get(status, _TERMINAL_MISSION_DIRS)
        if current_dir not in allowed or parts[0] != "missions":
            errors.append(
                f"{label}: mission with status {status!r} stored at {rel} - "
                f"directory location must match status (allowed: missions/"
                f"{'|missions/'.join(sorted(allowed))})"
            )
        return
    expected_dirs = TYPE_DIRS.get(dtype)
    if not expected_dirs:
        return
    if parts[0] == "knowledge":
        subdir = parts[1]
        if subdir not in expected_dirs:
            errors.append(f"{label}: {dtype} stored under knowledge/{subdir}/")


def _check_references(
    rel: Path,
    doc: dict,
    label: str,
    defined_ids: set[str],
    errors: list[str],
) -> None:
    refs: list[str] = []
    for key in ("candidate_targets", "dependencies"):
        values = doc.get(key) or []
        refs.extend(v for v in values if isinstance(v, str))
    links = doc.get("links") or {}
    if isinstance(links, dict):
        for values in links.values():
            if isinstance(values, list):
                refs.extend(v for v in values if isinstance(v, str))
    artifacts = doc.get("artifacts") or []
    if isinstance(artifacts, list):
        refs.extend(v for v in artifacts if isinstance(v, str))
    for ref in refs:
        if ref not in defined_ids:
            errors.append(
                f"{label}: dangling reference to missing artifact {ref}"
            )
