"""Artifact ID allocation and parsing."""

import pytest

from frontier.ids import (
    PREFIXES,
    ArtifactId,
    IdError,
    next_id,
    prefix_for_type,
    type_for_prefix,
)


def test_parse_round_trip():
    aid = ArtifactId.parse("msn-2026-0001")
    assert aid.prefix == "msn"
    assert aid.year == 2026
    assert aid.seq == 1
    assert str(aid) == "msn-2026-0001"


def test_parse_rejects_unknown_prefix():
    with pytest.raises(IdError):
        ArtifactId.parse("foo-2026-0001")


def test_parse_rejects_malformed():
    with pytest.raises(IdError):
        ArtifactId.parse("msn-26-1")
    with pytest.raises(IdError):
        ArtifactId.parse("msn-2026-1")
    with pytest.raises(IdError):
        ArtifactId.parse("MSN-2026-0001")


def test_next_id_starts_at_one_when_empty():
    aid = next_id([], "hyp", year=2026)
    assert str(aid) == "hyp-2026-0001"


def test_next_id_increments_per_prefix_and_year():
    existing = ["hyp-2026-0001", "hyp-2026-0003", "msn-2026-0009", "hyp-2025-0040"]
    aid = next_id(existing, "hyp", year=2026)
    assert str(aid) == "hyp-2026-0004"


def test_prefix_type_tables_are_inverses():
    for artifact_type, prefix in PREFIXES.items():
        assert prefix_for_type(artifact_type) == prefix
        assert type_for_prefix(prefix) == artifact_type


def test_id_type_must_match_declared_type():
    aid = ArtifactId.parse("fnd-2026-0012")
    assert aid.matches_type("finding")
    assert not aid.matches_type("mission")
