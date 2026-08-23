"""Scratch workspace selection, capacity, and cleanup."""

from pathlib import Path

from frontier.scratch import (
    ScratchError,
    clean_workspace,
    default_scratch_root,
    ensure_capacity,
    init_workspace,
    inspect_scratch,
)


def test_env_var_overrides_default(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FRONTIER_SCRATCH", str(tmp_path / "custom"))
    monkeypatch.delenv("FRONTIER_FORCE_RAMDISK", raising=False)
    root = default_scratch_root()
    assert root == tmp_path / "custom"


def test_init_workspace_is_mission_scoped(tmp_path: Path):
    ws = init_workspace(tmp_path, "msn-2026-0001")
    assert ws.exists()
    assert ws.name == "msn-2026-0001"
    assert ws.parent == tmp_path


def test_clean_workspace_removes_contents(tmp_path: Path):
    ws = init_workspace(tmp_path, "msn-2026-0001")
    (ws / "blob.bin").write_bytes(b"x" * 100)
    clean_workspace(ws)
    assert not ws.exists()


def test_ensure_capacity_raises_when_short(tmp_path: Path, monkeypatch):
    def fake_usage(_path):
        class Usage:
            free = 10

        return Usage()

    monkeypatch.setattr("frontier.scratch.shutil.disk_usage", fake_usage)
    try:
        ensure_capacity(tmp_path, needed_bytes=1000)
        raised = False
    except ScratchError:
        raised = True
    assert raised


def test_inspect_reports_free_bytes(tmp_path: Path):
    info = inspect_scratch(tmp_path)
    assert info["path"] == str(tmp_path.resolve())
    assert info["free_bytes"] > 0
    assert "exists" in info
