"""Index-drift enforcement: ``knowledge/indices/*`` is derived, not authoritative.

An index file is never validated as an artifact (it carries no envelope and no
allocated ID), but it must not contradict the artifacts it summarises. These
tests pin that second, separate obligation.
"""

from pathlib import Path

from tests.conftest import envelope, write_yaml


def _two_artifacts(root: Path) -> None:
    write_yaml(
        root / "knowledge/targets/tgt-2026-0001.yaml",
        envelope("tgt-2026-0001", "target", "active"),
    )
    write_yaml(
        root / "knowledge/hypotheses/hyp-2026-0001.yaml",
        envelope("hyp-2026-0001", "hypothesis", "rejected"),
    )


def _write_index(root: Path, by_status=None, by_type=None) -> None:
    index_dir = root / "knowledge" / "indices"
    index_dir.mkdir(parents=True, exist_ok=True)
    if by_status is not None:
        write_yaml(index_dir / "by-status.yaml", by_status)
    if by_type is not None:
        write_yaml(index_dir / "by-type.yaml", by_type)


def test_freshly_rebuilt_index_validates(repo_root: Path):
    """The real regeneration path leaves a repo that validates."""
    from frontier.index import rebuild_index
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    rebuild_index(repo_root)
    result = validate_repo(repo_root)
    assert result.ok, result.errors


def test_stale_status_in_index_fails_validation(repo_root: Path):
    """An index asserting a superseded status is a structural error."""
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    _write_index(
        repo_root,
        by_status={"verified_conclusion": ["hyp-2026-0001"], "active": ["tgt-2026-0001"]},
        by_type={"target": ["tgt-2026-0001"], "hypothesis": ["hyp-2026-0001"]},
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any(
        "hyp-2026-0001 is indexed under status 'verified_conclusion'"
        " but its artifact says 'rejected'" in e
        for e in result.errors
    ), result.errors


def test_artifact_missing_from_index_fails_validation(repo_root: Path):
    """Index drift in the other direction is caught too."""
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    _write_index(
        repo_root,
        by_status={"active": ["tgt-2026-0001"]},
        by_type={"target": ["tgt-2026-0001"]},
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("hyp-2026-0001" in e and "absent from the index" in e for e in result.errors), (
        result.errors
    )


def test_index_entry_without_artifact_fails_validation(repo_root: Path):
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    _write_index(
        repo_root,
        by_status={"active": ["tgt-2026-0001", "tgt-2026-0009"]},
        by_type={"target": ["tgt-2026-0001"]},
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any(
        "tgt-2026-0009 is indexed under status 'active' but no such artifact exists" in e
        for e in result.errors
    ), result.errors


def test_wrong_type_in_index_fails_validation(repo_root: Path):
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    _write_index(
        repo_root,
        by_status={"active": ["tgt-2026-0001"], "rejected": ["hyp-2026-0001"]},
        by_type={"finding": ["hyp-2026-0001"]},
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any(
        "hyp-2026-0001 is indexed under type 'finding' but its artifact says 'hypothesis'"
        in e
        for e in result.errors
    ), result.errors


def test_repo_without_indices_still_validates(repo_root: Path):
    """Index consistency is only enforced where an index file exists."""
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    result = validate_repo(repo_root)
    assert result.ok, result.errors


def test_index_file_is_never_treated_as_an_artifact(repo_root: Path):
    """Reconciliation with the skip-indices rule: no envelope is demanded.

    ``tests/test_validate_skip_indices.py`` pins that index files are not
    evidence artifacts. This pins that the new consistency check does not
    reintroduce envelope validation for them: a bare ``{status: [ids]}`` file
    with no id/type/created_at must not produce "missing required envelope
    field" errors.
    """
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    (repo_root / "knowledge/indices").mkdir(parents=True, exist_ok=True)
    (repo_root / "knowledge/indices/by-status.yaml").write_text(
        "active:\n- tgt-2026-0001\nrejected:\n- hyp-2026-0001\n", encoding="utf-8"
    )
    (repo_root / "knowledge/indices/by-type.yaml").write_text(
        "target:\n- tgt-2026-0001\nhypothesis:\n- hyp-2026-0001\n", encoding="utf-8"
    )
    result = validate_repo(repo_root)
    assert result.ok, result.errors
    assert not any("envelope" in e for e in result.errors)


def test_unparseable_index_file_fails_validation(repo_root: Path):
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    (repo_root / "knowledge/indices").mkdir(parents=True, exist_ok=True)
    (repo_root / "knowledge/indices/by-status.yaml").write_text(
        "active:\n  - tgt-2026-0001\n :\n\tbad\n", encoding="utf-8"
    )
    result = validate_repo(repo_root)
    assert not result.ok
    assert any("unparseable index file" in e for e in result.errors), result.errors
def test_nested_index_directory_is_refused(repo_root: Path):
    """A derived view has exactly one location; a nested copy is a defect.

    Regression: a mis-pathed rebuild wrote
    knowledge/indices/knowledge/indices/{by-status,by-type}.yaml as two tracked
    4-byte "{}" stubs. Files under knowledge/indices are not validated as
    artifacts, so nothing noticed. This asserts the validator now refuses the
    shape regardless of the stubs' contents.
    """
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    _write_index(
        repo_root,
        by_status={"active": ["tgt-2026-0001"], "rejected": ["hyp-2026-0001"]},
        by_type={"target": ["tgt-2026-0001"], "hypothesis": ["hyp-2026-0001"]},
    )
    nested = repo_root / "knowledge/indices/knowledge/indices"
    nested.mkdir(parents=True)
    (nested / "by-status.yaml").write_text("{}\n", encoding="utf-8")
    (nested / "by-type.yaml").write_text("{}\n", encoding="utf-8")

    result = validate_repo(repo_root)
    assert not result.ok
    assert any("nested index directory" in e for e in result.errors), result.errors


def test_clean_index_tree_has_no_nested_copy(repo_root: Path):
    """The control: a legitimate single-level index tree still validates."""
    from frontier.validate import validate_repo

    _two_artifacts(repo_root)
    _write_index(
        repo_root,
        by_status={"active": ["tgt-2026-0001"], "rejected": ["hyp-2026-0001"]},
        by_type={"target": ["tgt-2026-0001"], "hypothesis": ["hyp-2026-0001"]},
    )
    result = validate_repo(repo_root)
    assert result.ok, result.errors
    assert not any("nested index directory" in e for e in result.errors)
