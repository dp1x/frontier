"""Structural validation skips non-artifact directories."""

from frontier.validate import validate_repo


def test_validator_ignores_indices_and_notes(tmp_path):
    root = tmp_path
    (root / "knowledge" / "targets").mkdir(parents=True)
    (root / "knowledge" / "indices").mkdir(parents=True)
    (root / "missions" / "completed").mkdir(parents=True)
    (root / "knowledge" / "targets" / "tgt-2026-0001.yaml").write_text(
        "id: tgt-2026-0001\ntype: target\nstatus: active\n"
        "created_at: \"2026-01-01T00:00:00Z\"\nupdated_at: \"2026-01-01T00:00:00Z\"\n"
        "summary: s\nepistemic_status: hypothesis\nprovenance:\n"
        "  created_by:\n    kind: human\n  sources: []\nlinks: {}\n",
        encoding="utf-8",
    )
    (root / "knowledge" / "indices" / "by-type.yaml").write_text(
        "target: [tgt-2026-0001]\n", encoding="utf-8"
    )
    result = validate_repo(root)
    assert result.ok, result.errors
