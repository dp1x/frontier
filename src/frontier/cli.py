"""Command-line interface for Frontier machinery."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

from frontier.ids import next_id
from frontier.status import collect_status
from frontier.validate import validate_repo

_SCAN_SKIP_PARTS = {".git", ".venv", ".scratch", "__pycache__"}


def _existing_ids(root: Path) -> list[str]:
    ids: list[str] = []
    for path in sorted(root.rglob("*.yaml")):
        if any(part in _SCAN_SKIP_PARTS for part in path.parts):
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(doc, dict) and isinstance(doc.get("id"), str):
            ids.append(doc["id"])
    return ids


def _cmd_validate(root: Path) -> int:
    result = validate_repo(root)
    for warning in result.warnings:
        print(f"warning: {warning}")
    if result.ok:
        print(f"ok: research state structurally consistent ({root})")
        return 0
    for error in result.errors:
        print(f"error: {error}", file=sys.stderr)
    print(f"failed: {len(result.errors)} structural error(s)", file=sys.stderr)
    return 1


def _cmd_next_id(root: Path, artifact_type: str, year: int | None) -> int:
    if year is None:
        year = datetime.now(UTC).year
    aid = next_id(_existing_ids(root), artifact_type, year=year)
    print(str(aid))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="frontier",
        description="Frontier deterministic research machinery",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--repo",
        default=".",
        help="repository root (default: current directory)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", parents=[common], help="human-facing status report")
    subparsers.add_parser(
        "validate", parents=[common], help="validate the repository research state"
    )
    next_parser = subparsers.add_parser(
        "next-id", parents=[common], help="allocate the next artifact id"
    )
    next_parser.add_argument("--type", required=True, dest="artifact_type")
    next_parser.add_argument("--year", type=int, default=None)

    args = parser.parse_args(argv)
    root = Path(args.repo).resolve()

    if args.command == "status":
        print(collect_status(root)["markdown"])
        return 0
    if args.command == "validate":
        return _cmd_validate(root)
    if args.command == "next-id":
        return _cmd_next_id(root, args.artifact_type, args.year)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
