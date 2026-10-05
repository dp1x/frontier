"""Regression tests for the PNG unknown-critical-chunk corpus.

These assertions are written by the ORCHESTRATOR, independently of the corpus
generator, and deliberately re-derive the structural facts from the raw bytes
using stdlib primitives only. They do not trust the generator's recorded
metadata: every CRC is recomputed, every length is re-walked, and the decisive
pair's difference is localised by byte offset.

Why this file exists at all
---------------------------
The corpus under test was built to answer one question, and the previous
framing of that question was VACUOUS because its vectors could be rejected for
the wrong reason (a bad CRC) before criticality was ever evaluated. A corpus
is only as good as its ability to distinguish "rejected because the chunk is
critical" from "rejected because something else is wrong". These tests pin the
properties that make it discriminating, so a later edit that breaks them fails
here rather than producing a confident wrong matrix.

What is asserted
----------------
  1. Framing is exact: chunk lengths consume the stream with no trailing bytes.
  2. Every CRC is recomputed and matches, EXCEPT the probe chunk of the two
     designated bad-CRC negative controls.
  3. The decisive pair differs ONLY in the probe chunk's type byte (by exactly
     bit 5, value 32) and that chunk's CRC. Nothing else moves.
  4. IHDR is the first chunk and IEND the last (PNG 11.2.1 / structural).
  5. The probe chunk's third type-letter is uppercase in every vector except
     the one that deliberately sets the reserved bit -- a lowercase third letter
     sets the reserved bit and makes the datastream non-conforming for a reason
     unrelated to criticality, which would confound the whole experiment.
  6. The corpus contains a valid, CRC-correct control that MUST be accepted.
     Without it the harness cannot produce an ACCEPT and nothing else it says
     is interpretable.
"""

from __future__ import annotations

import json
import struct
import sys
import zlib
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1] / "crypto" / "png-critical-chunk"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# Only the PROBE chunk is corrupted in these vectors; the base PNG's own
# IHDR/IDAT/IEND chunks must still verify. The expectation is therefore
# per-chunk, not per-file.
BAD_CRC_VECTORS = {"negc-anc-badcrc", "negc-cri-badcrc"}


def _load_vectors() -> list[dict]:
    lines = (HERE / "vectors.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _parse_chunks(blob: bytes) -> list[dict]:
    """Re-walk the chunk stream from raw bytes. Raises on any framing defect."""
    assert blob[:8] == PNG_SIGNATURE, "PNG signature mismatch"
    off = 8
    chunks: list[dict] = []
    while off < len(blob):
        if off + 8 > len(blob):
            raise AssertionError(f"truncated chunk header at offset {off}")
        (length,) = struct.unpack(">I", blob[off : off + 4])
        ctype = blob[off + 4 : off + 8]
        data = blob[off + 8 : off + 8 + length]
        crc_field = blob[off + 8 + length : off + 12 + length]
        if len(data) != length:
            raise AssertionError(f"chunk data overruns file at offset {off}")
        if len(crc_field) != 4:
            raise AssertionError(f"chunk CRC overruns file at offset {off}")
        stored = int.from_bytes(crc_field, "big")
        # PNG's CRC covers the type and data fields, NOT the length.
        calc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        chunks.append(
            {
                "offset": off,
                "type": ctype.decode("latin-1"),
                "type_bytes": ctype,
                "length": length,
                "crc_ok": calc == stored,
            }
        )
        off += 12 + length
    if off != len(blob):
        raise AssertionError(f"trailing bytes: stream ended at {off}, file is {len(blob)} bytes")
    return chunks


@pytest.fixture(scope="module")
def vectors():
    return _load_vectors()


def _blob(name: str) -> bytes:
    return (HERE / "vectors" / f"{name}.png").read_bytes()


def test_corpus_is_present_and_nonempty(vectors):
    assert vectors, "vectors.jsonl is empty"
    for v in vectors:
        path = HERE / "vectors" / f"{v['name']}.png"
        assert path.is_file(), f"missing emitted PNG for vector {v['name']}"


def test_every_vector_has_exact_structural_framing(vectors):
    for v in vectors:
        blob = _blob(v["name"])
        assert len(blob) == v["bytes_len"], (
            f"{v['name']}: on-disk length {len(blob)} != recorded {v['bytes_len']}"
        )
        _parse_chunks(blob)  # raises on framing defects


def test_ihdr_is_first_and_iend_is_last(vectors):
    """PNG 11.2.1: IHDR shall be the first chunk in the datastream."""
    for v in vectors:
        chunks = _parse_chunks(_blob(v["name"]))
        assert chunks[0]["type"] == "IHDR", (
            f"{v['name']}: first chunk is {chunks[0]['type']}, expected IHDR"
        )
        assert chunks[-1]["type"] == "IEND", (
            f"{v['name']}: last chunk is {chunks[-1]['type']}, expected IEND"
        )


def test_crcs_are_valid_except_the_designated_negative_controls(vectors):
    """THE CONFOUND CONTROL.

    Every non-control vector must have a correct CRC on every chunk, so that a
    rejection can only be attributable to the chunk's criticality. A decoder
    that rejects the unknown-critical vector because of a CRC error has proved
    nothing about criticality.
    """
    for v in vectors:
        probe_type = (v.get("probe_chunk") or {}).get("type")
        for c in _parse_chunks(_blob(v["name"])):
            is_probe = c["type"] == probe_type
            expect_valid = not (is_probe and v["name"] in BAD_CRC_VECTORS)
            assert c["crc_ok"] == expect_valid, (
                f"{v['name']}/{c['type']}: crc_ok={c['crc_ok']}, expected {expect_valid}"
            )


def test_the_negative_controls_really_have_a_bad_crc(vectors):
    """The negative control must actually be negative, or it proves nothing."""
    by_name = {v["name"]: v for v in vectors}
    for name in BAD_CRC_VECTORS:
        assert name in by_name, f"negative control {name} is not in the corpus"
        probe_type = (by_name[name].get("probe_chunk") or {}).get("type")
        probe_chunks = [c for c in _parse_chunks(_blob(name)) if c["type"] == probe_type]
        assert probe_chunks, f"{name}: probe chunk {probe_type!r} not found"
        assert not any(c["crc_ok"] for c in probe_chunks), (
            f"{name}: expected the probe chunk's CRC to be INVALID"
        )


def test_the_decisive_pair_differs_only_in_the_criticality_bit():
    """The property the entire experiment rests on.

    The two files must be byte-identical except for one bit of one chunk type
    byte and that chunk's CRC. If anything else differs -- a length, another
    chunk, the placement -- the pair no longer isolates criticality and any
    verdict drawn from it is unattributable.
    """
    anc = _blob("pair-primary-anc")
    cri = _blob("pair-primary-cri")
    assert len(anc) == len(cri), (
        f"decisive pair differs in length: {len(anc)} vs {len(cri)}"
    )
    diffs = [i for i in range(len(anc)) if anc[i] != cri[i]]
    # 1 type byte + 4 CRC bytes.
    assert len(diffs) == 5, (
        f"decisive pair differs at {len(diffs)} offsets {diffs}; expected exactly 5 "
        "(one type byte plus its 4-byte CRC)"
    )

    a_chunks, c_chunks = _parse_chunks(anc), _parse_chunks(cri)
    assert len(a_chunks) == len(c_chunks), "decisive pair has different chunk counts"

    differing_types = [
        (a, c)
        for a, c in zip(a_chunks, c_chunks, strict=True)
        if a["type_bytes"] != c["type_bytes"]
    ]
    assert len(differing_types) == 1, (
        f"expected exactly one chunk type to differ, got {len(differing_types)}"
    )
    a_type, c_type = differing_types[0]
    xor = a_type["type_bytes"][0] ^ c_type["type_bytes"][0]
    assert xor == 0x20, (
        f"first type byte XOR is 0x{xor:02x}; PNG property bits are bit 5 (value 32), "
        "not the high-order bit"
    )
    # The chunk lengths must match, so the pair differs only in criticality.
    assert a_type["length"] == c_type["length"], (
        "probe chunk lengths differ; the pair does not isolate criticality"
    )
    # The rest of each type must be identical.
    assert a_type["type_bytes"][1:] == c_type["type_bytes"][1:], (
        "probe chunk type bytes differ beyond the first byte"
    )


def test_probe_reserved_bit_is_clear_except_where_deliberate(vectors):
    """PNG Table 6: a set reserved bit makes the datastream non-conforming.

    A lowercase third type-letter sets the reserved bit, which would make the
    file non-conforming for a reason unrelated to criticality -- exactly the
    confound this corpus exists to exclude.
    """
    for v in vectors:
        probe = v.get("probe_chunk")
        if not probe or not probe.get("type"):
            continue
        third = probe["type"][2]
        if v["name"] == "negc-anc-reserved-bit":
            assert third.islower(), (
                "negc-anc-reserved-bit must deliberately set the reserved bit, "
                f"but its third letter {third!r} is uppercase"
            )
        else:
            assert not third.islower(), (
                f"{v['name']}: probe third letter {third!r} is lowercase, which sets "
                "the reserved bit and confounds the criticality test"
            )


def test_a_control_vector_must_be_accepted_by_the_oracle():
    """The harness must be able to produce an ACCEPT.

    Without this the whole matrix is vacuous: a harness that rejects
    everything would 'pass' every critical-chunk cell while measuring nothing.
    """
    vectors = _load_vectors()
    controls = [v for v in vectors if v.get("group") == "positive_control"]
    assert controls, "no positive controls in the corpus"
    accepting = [v for v in controls if v["expected_reason"] == "ACCEPTED"]
    assert accepting, (
        "no positive control is expected to ACCEPT; the harness cannot demonstrate "
        "a successful decode, so no rejection result would be interpretable"
    )
    # The minimal control must be ACCEPTED, per the specification.
    minimal = [v for v in vectors if v["name"] == "ctl-00-minimal"]
    assert minimal and minimal[0]["expected_reason"] == "ACCEPTED", (
        "ctl-00-minimal (a conforming PNG with no unknown chunk) must be ACCEPTED"
    )


def test_oracle_distinguishes_crc_failure_from_unknown_critical_chunk(vectors):
    """The oracle must not collapse every rejection into one reason class.

    This is the failure mode that made the earlier framing vacuous: a harness
    that reports 'rejected' without saying WHY cannot distinguish a correct
    critical-chunk rejection from a CRC error or a malformed structure.
    """
    by_name = {v["name"]: v for v in vectors}
    for name in BAD_CRC_VECTORS:
        assert by_name[name]["expected_reason"] != "UNKNOWN_CRITICAL_CHUNK", (
            f"{name} has a deliberately invalid CRC; its expected reason must be a "
            "CRC class, not the phenomenon under study"
        )
    # And the decisive pair must be separated by the oracle.
    assert by_name["pair-primary-anc"]["expected_reason"] == "ACCEPTED"
    assert by_name["pair-primary-cri"]["expected_reason"] != "ACCEPTED", (
        "the unknown-CRITICAL vector must not be expected to accept"
    )


def test_every_unknown_probe_chunk_type_is_genuinely_unknown_to_the_spec():
    """Probe types on the unknown-chunk cells must not collide with real types.

    A 'critical' chunk the decoder actually knows is not an unknown critical
    chunk, and the cell would measure ordinary decoding. The known-chunk
    CONTROLS (ctl-01 gAMA, ctl-02 tEXt, ctl-03 PLTE) deliberately use real
    types -- that is what makes them controls -- so they are excluded by group,
    not by name.
    """
    known = {
        "IHDR", "PLTE", "IDAT", "IEND", "gAMA", "tEXt", "pHYs", "tIME", "sRGB",
        "bKGD", "cHRM", "iCCP", "sBIT", "sPLT", "tRNS", "hIST", "eXIf",
    }
    checked = 0
    for v in _load_vectors():
        probe = v.get("probe_chunk")
        if not probe or not probe.get("type"):
            continue
        if v.get("group") == "positive_control":
            # Deliberately a KNOWN chunk; assert that it really is one.
            assert probe["type"] in known, (
                f"{v['name']} is a positive control and must use a real chunk type, "
                f"but uses {probe['type']!r}"
            )
            continue
        ptype = probe["type"]
        assert ptype not in known, (
            f"{v['name']}: probe type {ptype!r} is a real PNG chunk type; the cell "
            "would measure ordinary decoding, not the unknown-chunk rule"
        )
        checked += 1
    assert checked >= 3, (
        f"only {checked} unknown-chunk vectors were checked; the corpus should carry "
        "the decisive pair plus its placement and negative-control variants"
    )