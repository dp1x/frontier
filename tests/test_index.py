"""Filesystem graph indexing."""

from pathlib import Path

from tests.conftest import envelope, write_yaml


def test_index_rebuilds_by_type_and_status(repo_root: Path):
    from frontier.index import rebuild_index

    write_yaml(
        repo_root / "knowledge/hypotheses/hyp-2026-0001.yaml",
        envelope("hyp-2026-0001", "hypothesis", "rejected", statement="Nope."),
    )
    index = rebuild_index(repo_root)
    by_type = (repo_root / "knowledge/indices/by-type.yaml").read_text(encoding="utf-8")
    by_status = (repo_root / "knowledge/indices/by-status.yaml").read_text(encoding="utf-8")
    assert "hyp-2026-0001" in by_type
    assert "rejected" in by_status
    assert index["counts"]["hypothesis"] == 1
