"""Filesystem graph indexing.

Rebuilds ``knowledge/indices/by-type.yaml`` and ``by-status.yaml`` from all
tracked YAML objects so agents can cheaply discover prior art before starting
new work.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml

_SKIP_DIR_NAMES = {"indices", "notes"}
_MISSION_QUEUES = ("pending", "active", "completed", "archive")


def iter_docs(repo_root: Path):
    """Yield every well-formed artifact document in the repo."""
    root = Path(repo_root)
    folders = [root / "missions" / name for name in _MISSION_QUEUES]
    knowledge_root = root / "knowledge"
    if knowledge_root.is_dir():
        folders.extend(
            child for child in sorted(knowledge_root.iterdir()) if child.is_dir()
        )
    seen_paths: set[str] = set()
    for folder in folders:
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*.yaml")):
            key = str(path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(doc, dict) and doc.get("id") and doc.get("type"):
                yield doc


def rebuild_index(repo_root: Path) -> dict:
    """Rebuild index files and return a summary with per-type counts."""
    root = Path(repo_root)
    by_type: dict[str, list[str]] = {}
    by_status: dict[str, list[str]] = {}
    counts: Counter[str] = Counter()

    for doc in iter_docs(root):
        dtype = doc["type"]
        did = doc["id"]
        by_type.setdefault(dtype, []).append(did)
        by_status.setdefault(str(doc["status"]), []).append(did)
        counts[dtype] += 1

    index_dir = root / "knowledge" / "indices"
    index_dir.mkdir(parents=True, exist_ok=True)
    (index_dir / "by-type.yaml").write_text(
        yaml.safe_dump(by_type, sort_keys=False), encoding="utf-8"
    )
    (index_dir / "by-status.yaml").write_text(
        yaml.safe_dump(by_status, sort_keys=False), encoding="utf-8"
    )
    return {"counts": dict(counts)}
