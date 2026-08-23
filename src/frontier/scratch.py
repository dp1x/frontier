"""Disposable scratch workspace management.

Scratch is ephemeral by design: clones, builds, corpora, and large logs live
here and die here. Preference order: ``$FRONTIER_SCRATCH``, then the RAM disk
(``R:``) unless disabled with ``FRONTIER_FORCE_RAMDISK=0``, then a local
``.scratch/`` directory. Nothing in scratch is assumed to survive a reboot.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

_RAMDISK_CANDIDATES = ("R:\\",)


class ScratchError(RuntimeError):
    """Raised when scratch resources are insufficient for a request."""


def _repo_root() -> Path:
    # src/frontier/scratch.py -> repo root is three levels up.
    return Path(__file__).resolve().parents[2]


def default_scratch_root() -> Path:
    """Select the scratch root according to policy."""
    env = os.environ.get("FRONTIER_SCRATCH")
    if env:
        return Path(env)
    if os.environ.get("FRONTIER_FORCE_RAMDISK") != "0":
        for candidate in _RAMDISK_CANDIDATES:
            if Path(candidate).exists():
                return Path(candidate) / "frontier-scratch"
    return _repo_root() / ".scratch"


def init_workspace(base_root: Path, mission_id: str) -> Path:
    """Create (or reuse) a mission-scoped scratch workspace."""
    workspace = Path(base_root) / mission_id
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def clean_workspace(workspace: Path) -> None:
    """Remove a scratch workspace and all of its contents."""
    shutil.rmtree(workspace, ignore_errors=True)


def ensure_capacity(path: Path, needed_bytes: int) -> None:
    """Raise :class:`ScratchError` when ``path`` lacks ``needed_bytes``."""
    free = shutil.disk_usage(path).free
    if free < needed_bytes:
        raise ScratchError(
            f"insufficient scratch capacity at {path}: "
            f"{free} bytes free, {needed_bytes} bytes required"
        )


def inspect_scratch(path: Path) -> dict:
    """Report basic facts about a scratch location."""
    target = Path(path)
    return {
        "path": str(target.resolve()),
        "free_bytes": shutil.disk_usage(target).free,
        "exists": target.exists(),
    }
