"""Obsidian-compatible notes generated from machine artifacts."""

from pathlib import Path

from tests.conftest import envelope


def test_finding_note_contains_wikilinks_and_epistemic_status():
    from frontier.knowledge import render_finding_note

    finding = envelope(
        "fnd-2026-0001",
        "finding",
        "verified",
        epistemic_status="verified_conclusion",
        classification="implementation-defined",
        statement="The implementation documents Encaps-time checks as optional.",
        disclosure="public",
        links={
            "mission": ["msn-2026-0001"],
            "specifications": ["spc-2026-0001"],
            "experiments": ["exp-2026-0001"],
        },
    )
    note = render_finding_note(finding)
    assert "[[fnd-2026-0001]]" in note or "fnd-2026-0001" in note
    assert "[[msn-2026-0001]]" in note
    assert "verified_conclusion" in note
    assert "implementation-defined" in note
    assert "---" in note  # YAML frontmatter


def test_write_note_updates_knowledge_notes(repo_root: Path):
    from frontier.knowledge import write_note

    path = write_note(repo_root, "fnd-2026-0001", "# Finding\n\nHello [[msn-2026-0001]].\n")
    assert path == repo_root / "knowledge/notes/fnd-2026-0001.md"
    assert path.read_text(encoding="utf-8").startswith("# Finding")
