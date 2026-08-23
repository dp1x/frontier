"""Stable artifact identifiers for Frontier research objects.

Every durable object carries an ID of the form ``<prefix>-<year>-<seq4>``
(e.g. ``msn-2026-0001``). Sequences are per prefix per year and are allocated
from repository state, never hand-picked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PREFIXES: dict[str, str] = {
    "target": "tgt",
    "specification": "spc",
    "implementation": "imp",
    "hypothesis": "hyp",
    "experiment": "exp",
    "observation": "obs",
    "reproducer": "rpr",
    "review": "rev",
    "verification": "vrf",
    "finding": "fnd",
    "conjecture": "cnj",
    "proof": "prf",
    "mission": "msn",
    "report": "rpt",
}

_PREFIX_TO_TYPE = {prefix: artifact_type for artifact_type, prefix in PREFIXES.items()}
_ID_RE = re.compile(r"^([a-z]{3})-(\d{4})-(\d{4})$")


class IdError(ValueError):
    """Raised for malformed or unknown artifact identifiers."""


def _resolve_prefix(name: str) -> str:
    """Accept either an artifact type or a raw prefix."""
    if name in _PREFIX_TO_TYPE:
        return name
    return prefix_for_type(name)


def prefix_for_type(artifact_type: str) -> str:
    try:
        return PREFIXES[artifact_type]
    except KeyError:
        raise IdError(f"unknown artifact type: {artifact_type!r}") from None


def type_for_prefix(prefix: str) -> str:
    try:
        return _PREFIX_TO_TYPE[prefix]
    except KeyError:
        raise IdError(f"unknown id prefix: {prefix!r}") from None


@dataclass(frozen=True)
class ArtifactId:
    prefix: str
    year: int
    seq: int

    @classmethod
    def parse(cls, raw: str) -> ArtifactId:
        match = _ID_RE.match(raw)
        if match is None:
            raise IdError(f"malformed artifact id: {raw!r}")
        prefix, year, seq = match.groups()
        if prefix not in _PREFIX_TO_TYPE:
            raise IdError(f"unknown id prefix: {prefix!r}")
        return cls(prefix=prefix, year=int(year), seq=int(seq))

    def __str__(self) -> str:
        return f"{self.prefix}-{self.year}-{self.seq:04d}"

    def matches_type(self, artifact_type: str) -> bool:
        try:
            return self.prefix == prefix_for_type(artifact_type)
        except IdError:
            return False


def next_id(existing: list[str], artifact_type: str, *, year: int) -> ArtifactId:
    """Allocate the next sequence number for ``artifact_type`` in ``year``.

    ``artifact_type`` may be given as the semantic type (``"hypothesis"``)
    or directly as the ID prefix (``"hyp"``).
    """
    prefix = _resolve_prefix(artifact_type)
    max_seq = 0
    for raw in existing:
        aid = ArtifactId.parse(raw)
        if aid.prefix == prefix and aid.year == year:
            max_seq = max(max_seq, aid.seq)
    return ArtifactId(prefix=prefix, year=year, seq=max_seq + 1)
