"""Human-facing status reporting.

Assembles the status report directly from the filesystem evidence graph so the
maintainer never needs to read agent transcripts.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_MISSION_STATES = (
    ("pending", "pending_missions"),
    ("active", "active_missions"),
    ("completed", "completed_missions"),
    ("archive", "completed_missions"),
    ("embargoed", "blocked_missions"),
)

_NEGATIVE_HYPOTHESIS_STATUSES = frozenset(
    {"rejected", "disproved", "inconclusive", "superseded", "archived"}
)


def _load_yaml_docs(folder: Path) -> list[dict]:
    docs: list[dict] = []
    if not folder.is_dir():
        return docs
    for path in sorted(folder.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(doc, dict):
            docs.append(doc)
    return docs


def _brief(doc: dict) -> dict:
    return {
        "id": doc.get("id"),
        "title": doc.get("title") or doc.get("summary"),
        "domain": doc.get("domain"),
        "status": doc.get("status"),
    }


def _front_matter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    # Prompt files may hold raw markdown-with-front-matter or the same content
    # YAML-serialized as a string; normalize before splitting on '---'.
    if not text.lstrip().startswith("---"):
        try:
            loaded = yaml.safe_load(text)
        except Exception:
            return {}
        if isinstance(loaded, str):
            text = loaded
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                meta = yaml.safe_load(parts[1])
            except Exception:
                return {}
            if isinstance(meta, dict):
                return meta
    return {}


def collect_status(repo_root: Path) -> dict:
    """Build the full status report from repository state."""
    root = Path(repo_root)
    report: dict[str, list | str] = {
        "active_missions": [],
        "pending_missions": [],
        "completed_missions": [],
        "blocked_missions": [],
        "verified_findings": [],
        "preserved_negative_results": [],
        "external_research_awaiting": [],
        "recommended_next": [],
    }

    for state_dir, key in _MISSION_STATES:
        for doc in _load_yaml_docs(root / "missions" / state_dir):
            entry = _brief(doc)
            if doc.get("status") == "blocked-by-missing-evidence":
                report["blocked_missions"].append(entry)
            else:
                report[key].append(entry)

    for doc in _load_yaml_docs(root / "knowledge" / "findings"):
        if doc.get("status") == "verified":
            report["verified_findings"].append(
                {
                    "id": doc.get("id"),
                    "summary": doc.get("summary"),
                    "classification": doc.get("classification"),
                }
            )

    for doc in _load_yaml_docs(root / "knowledge" / "hypotheses"):
        if doc.get("status") in _NEGATIVE_HYPOTHESIS_STATUSES:
            report["preserved_negative_results"].append(
                {"id": doc.get("id"), "summary": doc.get("summary")}
            )

    prompts_dir = root / "ai-io" / "prompts"
    if prompts_dir.is_dir():
        for path in sorted(prompts_dir.glob("aio-*.md")):
            meta = _front_matter(path)
            if meta.get("status") == "awaiting-output":
                report["external_research_awaiting"].append(
                    {"id": meta.get("id"), "angle": meta.get("angle")}
                )

    report["markdown"] = _render_markdown(report)
    return report


def _render_markdown(report: dict) -> str:
    lines = ["Frontier status", "===============", ""]
    lines.append(f"Active missions: {len(report['active_missions'])}")
    for mission in report["active_missions"]:
        domain = mission.get("domain") or "-"
        lines.append(f"  - {mission['id']} [{domain}]: {mission['title']}")
    lines.append("")
    lines.append(f"Pending missions: {len(report['pending_missions'])}")
    for mission in report["pending_missions"]:
        domain = mission.get("domain") or "-"
        lines.append(f"  - {mission['id']} [{domain}]: {mission['title']}")
    lines.append("")
    lines.append(f"Verified findings: {len(report['verified_findings'])}")
    for finding in report["verified_findings"]:
        lines.append(
            f"  - {finding['id']} ({finding.get('classification')}): "
            f"{finding.get('summary')}"
        )
    lines.append("")
    lines.append(
        f"Preserved negative results: {len(report['preserved_negative_results'])}"
    )
    for hyp in report["preserved_negative_results"]:
        lines.append(f"  - {hyp['id']}: {hyp['summary']}")
    lines.append("")
    lines.append(f"Blocked work: {len(report['blocked_missions'])}")
    lines.append(
        f"External research awaiting input: {len(report['external_research_awaiting'])}"
    )
    for prompt in report["external_research_awaiting"]:
        lines.append(f"  - {prompt['id']} ({prompt.get('angle')})")
    lines.append("")
    return "\n".join(lines)
