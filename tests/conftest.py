"""Shared fixtures for Frontier tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


def iso(ts: str = "2026-08-23T12:00:00Z") -> str:
    return ts


def provenance(**kwargs) -> dict:
    base = {
        "created_by": {
            "kind": "deterministic-tool",
            "role": "test",
            "model": None,
            "tool": "pytest",
        },
        "sources": [],
        "parent": None,
        "generation": 0,
    }
    base.update(kwargs)
    return base


def envelope(object_id: str, object_type: str, status: str, **extra) -> dict:
    doc = {
        "id": object_id,
        "type": object_type,
        "status": status,
        "created_at": iso(),
        "updated_at": iso(),
        "summary": extra.pop("summary", f"{object_type} {object_id}"),
        "epistemic_status": extra.pop("epistemic_status", "hypothesis"),
        "provenance": extra.pop("provenance", provenance()),
        "links": extra.pop("links", {}),
    }
    doc.update(extra)
    return doc


def write_yaml(path: Path, doc: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    """A filesystem-backed mini Frontier repo."""
    for rel in (
        "missions/pending",
        "missions/active",
        "missions/completed",
        "missions/archive",
        "missions/embargoed",
        "knowledge/targets",
        "knowledge/specifications",
        "knowledge/implementations",
        "knowledge/hypotheses",
        "knowledge/experiments",
        "knowledge/observations",
        "knowledge/reproducers",
        "knowledge/reviews",
        "knowledge/verifications",
        "knowledge/findings",
        "knowledge/findings/embargoed",
        "knowledge/conjectures",
        "knowledge/proofs",
        "knowledge/reports",
        "knowledge/process-findings",
        "knowledge/notes",
        "knowledge/indices",
        "ai-io/prompts",
        "ai-io/outputs",
        "localdocs/schemas",
    ):
        (tmp_path / rel).mkdir(parents=True, exist_ok=True)
    return tmp_path
