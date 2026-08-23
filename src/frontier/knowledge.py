"""Obsidian-compatible note rendering for human-readable knowledge.

The machine layer stays authoritative; these notes explain meaningful findings
in human terms with wikilinks back into the evidence graph.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def render_finding_note(finding: dict) -> str:
    """Render a finding as an Obsidian note with front matter and wikilinks."""
    front = {
        "id": finding.get("id"),
        "type": finding.get("type", "finding"),
        "status": finding.get("status"),
        "epistemic_status": finding.get("epistemic_status"),
        "classification": finding.get("classification"),
        "disclosure": finding.get("disclosure"),
    }
    lines = [
        "---",
        yaml.safe_dump(front, sort_keys=False).rstrip("\n"),
        "---",
        "",
        f"# {finding.get('id')}",
        "",
        str(finding.get("statement", "")).strip(),
        "",
    ]
    flat_refs: list[str] = []
    links = finding.get("links") or {}
    if isinstance(links, dict):
        for values in links.values():
            if isinstance(values, list):
                flat_refs.extend(v for v in values if isinstance(v, str))
    if flat_refs:
        lines.append("## Links")
        lines.append("")
        lines.extend(f"- [[{ref}]]" for ref in flat_refs)
        lines.append("")
    return "\n".join(lines)


def write_note(repo_root: Path, object_id: str, content: str) -> Path:
    """Write a note into ``knowledge/notes`` and return its path."""
    notes_dir = Path(repo_root) / "knowledge" / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    path = notes_dir / f"{object_id}.md"
    path.write_text(content, encoding="utf-8")
    return path
