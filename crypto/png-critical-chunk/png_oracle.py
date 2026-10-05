"""Cleanroom STRUCTURAL oracle for PNG datastreams.

Scope (deliberately minimal): this oracle does NOT decode pixels. It does not
inflate IDAT, does not unfilter scanlines, and does not reconstruct a reference
image. It answers one structural question per datastream:

    given the datastream framing, what does the PNG specification require a
    decoder to do, and WHY?

Every verdict carries an explicit reason drawn from a closed set, so that
"rejected because the chunk was critical" is never conflated with "rejected
because the CRC was wrong" or "rejected because the framing was broken".

Provenance
----------
Normative source: PNG Specification (Third Edition), W3C Recommendation
24 June 2025, https://www.w3.org/TR/2025/REC-png-3-20250624/
A byte-exact local copy used to derive every rule below is pinned at
spec/png-3.txt (extracted from the HTML of that URL).

Sections cited in RULE_SOURCES were read from that copy. Nothing here is
derived from, or reconciled against, any PNG decoder implementation.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Rules derived from the specification, each with its section anchor.
# ---------------------------------------------------------------------------

RULE_SOURCES = {
    "signature": "5.2 PNG signature",
    "chunk_layout": "5.3 Chunk layout (Table 5: chunk fields)",
    "legal_type_bytes": "5.3 Chunk layout, Chunk Type field",
    "property_bits": "5.4 Chunk naming conventions; Table 6 Semantics of property bits",
    "criticality": "5.4 Chunk naming conventions; Table 6, 'Ancillary bit: first byte'",
    "private_bit": "Table 6, 'Private bit: second byte'",
    "reserved_bit": "Table 6, 'Reserved bit: third byte'",
    "safe_to_copy": "Table 6, 'Safe-to-copy bit: fourth byte'",
    "unknown_ancillary": "Table 6 ancillary-bit description (ancillary=1: 'can safely ignore')",
    "unknown_critical": "Table 6 ancillary-bit description (ancillary=0: 'shall indicate ... cannot safely interpret')",
    "decoder_conformance": "15.3.3 Conformance of PNG decoders, items 3, 6 and 7",
    "critical_first": "11.2 Critical chunks, Introduction; 11.2.1 IHDR",
    "ihdr": "11.2.1 IHDR Image header",
    "crc": "5.5 CRC algorithm",
}

PNG_SIGNATURE = bytes((0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))

#: Value of the "ancillary bit" (spec Table 6) => chunk is ANCILLARY.
#:
#: The spec calls bit 5 (value 32) of each type byte the property bit that
#: carries critical/ancillary status. 0 => critical, 1 => ancillary.
ANCILLARY_BIT_MASK = 0x20

#: Legal chunk-type bytes: hexadecimal 41-5A and 61-7A (spec 5.3, Chunk Type).
LEGAL_TYPE_BYTE_RANGES = ((0x41, 0x5A), (0x61, 0x7A))

#: Chunk types this specification defines (spec 4.8.2 + section 11).
#: Enumerated from the spec text itself: every entry below is either a type
#: whose four-byte type field is printed in section 11, or is named in the
#: 4.8.2 chunk-type lists. Used to decide whether a type is "known".
KNOWN_CRITICAL = frozenset({b"IHDR", b"PLTE", b"IDAT", b"IEND"})
KNOWN_ANCILLARY = frozenset({
    b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"cICP", b"mDCV",
    b"iTXt", b"tEXt", b"zTXt", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"eXIf",
    b"tIME", b"acTL", b"fcTL", b"fdAT", b"cLLI",
})
KNOWN_CHUNK_TYPES = KNOWN_CRITICAL | KNOWN_ANCILLARY

MAX_CHUNK_LENGTH = 2 ** 31 - 1


# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------

ACCEPTED = "ACCEPTED"
UNKNOWN_CRITICAL_CHUNK = "UNKNOWN_CRITICAL_CHUNK"
CRC_MISMATCH = "CRC_MISMATCH"
MALFORMED_STRUCTURE = "MALFORMED_STRUCTURE"

#: Reasons that constitute evidence about the critical/ancillary rule.
#: A CRC_MISMATCH or MALFORMED_STRUCTURE verdict is a CONFOUND and must never
#: be cited as evidence about criticality.
EVIDENCEFUL_REASONS = frozenset({ACCEPTED, UNKNOWN_CRITICAL_CHUNK})
CONFOUND_REASONS = frozenset({CRC_MISMATCH, MALFORMED_STRUCTURE})


# ---------------------------------------------------------------------------
# CRC-32 per spec 5.5
# ---------------------------------------------------------------------------

def png_crc32(type_bytes: bytes, data: bytes) -> int:
    """CRC over the chunk type field followed by the chunk data field.

    Spec 5.3: "A four-byte CRC calculated on the preceding bytes in the chunk,
    including the chunk type field and chunk data fields, but not including the
    length field." Spec 5.5: initialized to all 1s, processed LSB-first, final
    value inverted, stored MSB first. That is exactly zlib.crc32, which is the
    standard CRC-32 with init 0xFFFFFFFF and final XOR 0xFFFFFFFF.
    """
    return zlib.crc32(type_bytes + data) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Chunk-type property decoding (spec 5.4 / Table 6)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TypeProperties:
    raw: bytes
    text: str
    hex: str
    ancillary_bit: int
    is_ancillary: bool
    is_critical: bool
    private_bit: int
    is_private: bool
    reserved_bit: int
    reserved_ok: bool
    safe_to_copy_bit: int
    safe_to_copy: bool
    all_bytes_legal: bool
    known_to_spec: bool

    def describe(self) -> str:
        return (
            "%s (%s) ancillary_bit=%d -> %s; private_bit=%d; reserved_bit=%d "
            "(%s); safe_to_copy=%d; legal_letters=%s; known_to_spec=%s"
            % (
                self.text, self.hex, self.ancillary_bit,
                "ANCILLARY" if self.is_ancillary else "CRITICAL",
                self.private_bit, self.reserved_bit,
                "OK" if self.reserved_ok else "RESERVED_BIT_SET",
                self.safe_to_copy_bit, self.all_bytes_legal, self.known_to_spec,
            )
        )


def _is_legal_type_byte(b: int) -> bool:
    return any(lo <= b <= hi for lo, hi in LEGAL_TYPE_BYTE_RANGES)


def decode_type_properties(type_bytes: bytes) -> TypeProperties:
    """Decode the four property bits described in spec 5.4 / Table 6.

    Each of the four type bytes carries one property bit at bit 5 (value 32):
      byte 0 -> ancillary bit   (0 = critical, 1 = ancillary)
      byte 1 -> private bit     (0 = public,   1 = private)
      byte 2 -> reserved bit    (0 in this version of PNG)
      byte 3 -> safe-to-copy bit(0 = unsafe,   1 = safe to copy)

    Note the letters shown in text form are a convenience only; the spec says
    chunk types are fixed binary values, and each byte is confined to 0x41-0x5A
    and 0x61-0x7A, so bit 7 is always 0 and bit 5 is the property bit.
    """
    if len(type_bytes) != 4:
        raise ValueError("chunk type must be exactly 4 bytes")
    a0, a1, a2, a3 = type_bytes
    ancillary_bit = (a0 & ANCILLARY_BIT_MASK) >> 5
    private_bit = (a1 & ANCILLARY_BIT_MASK) >> 5
    reserved_bit = (a2 & ANCILLARY_BIT_MASK) >> 5
    safe_bit = (a3 & ANCILLARY_BIT_MASK) >> 5
    legal = all(_is_legal_type_byte(b) for b in type_bytes)
    return TypeProperties(
        raw=type_bytes,
        text=''.join(chr(b) for b in type_bytes),
        hex=' '.join('%02X' % b for b in type_bytes),
        ancillary_bit=ancillary_bit,
        is_ancillary=(ancillary_bit == 1),
        is_critical=(ancillary_bit == 0),
        private_bit=private_bit,
        is_private=(private_bit == 1),
        reserved_bit=reserved_bit,
        reserved_ok=(reserved_bit == 0),
        safe_to_copy_bit=safe_bit,
        safe_to_copy=(safe_bit == 1),
        all_bytes_legal=legal,
        known_to_spec=(type_bytes in KNOWN_CHUNK_TYPES),
    )


# ---------------------------------------------------------------------------
# Structural parse result
# ---------------------------------------------------------------------------

@dataclass
class ChunkRecord:
    index: int
    offset: int          # byte offset of the length field in the datastream
    length: int          # declared length of the data field
    type_bytes: bytes
    data: bytes
    crc_stored: int
    crc_computed: int
    props: TypeProperties

    @property
    def end_offset(self) -> int:
        return self.offset + 12 + self.length

    @property
    def crc_ok(self) -> bool:
        return self.crc_stored == self.crc_computed

    @property
    def crc_hex(self) -> str:
        return '%08X' % self.crc_stored

    @property
    def total_bytes(self) -> int:
        return 12 + self.length


@dataclass
class OracleVerdict:
    reason: str
    detail: str
    chunks: List[ChunkRecord] = field(default_factory=list)
    structural_errors: List[str] = field(default_factory=list)
    spec_basis: List[str] = field(default_factory=list)

    @property
    def is_confound(self) -> bool:
        return self.reason in CONFOUND_REASONS

    @property
    def is_evidenceful(self) -> bool:
        return self.reason in EVIDENCEFUL_REASONS


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------

def analyse(data: bytes) -> OracleVerdict:
    """Structurally classify a PNG datastream. Never decodes image data."""
    chunks: List[ChunkRecord] = []
    errors: List[str] = []

    # -- (a) signature -------------------------------------------------------
    if len(data) < len(PNG_SIGNATURE) or data[:8] != PNG_SIGNATURE:
        return OracleVerdict(
            reason=MALFORMED_STRUCTURE,
            detail="PNG signature mismatch (expected 89 50 4E 47 0D 0A 1A 0A)",
            chunks=chunks,
            structural_errors=['BAD_SIGNATURE'],
            spec_basis=[RULE_SOURCES['signature']],
        )

    # -- (b) chunk framing ---------------------------------------------------
    off = 8
    n = len(data)
    while off < n:
        if n - off < 8:
            errors.append(
                'TRUNCATED_CHUNK_HEADER at offset %d (%d trailing byte(s))'
                % (off, n - off))
            break
        length = struct.unpack('>I', data[off:off + 4])[0]
        type_bytes = data[off + 4:off + 8]
        if length > MAX_CHUNK_LENGTH:
            errors.append(
                'CHUNK_LENGTH_OUT_OF_RANGE at offset %d (length=%d > 2^31-1)'
                % (off, length))
            break
        end = off + 12 + length
        if end > n:
            errors.append(
                'CHUNK_OVERRUN at offset %d: declared length %d needs %d bytes, '
                'only %d available' % (off, length, 12 + length, n - off))
            break
        cdata = data[off + 8:off + 8 + length]
        crc_stored = struct.unpack('>I', data[off + 8 + length:end])[0]
        props = decode_type_properties(type_bytes)
        chunks.append(ChunkRecord(
            index=len(chunks),
            offset=off,
            length=length,
            type_bytes=type_bytes,
            data=cdata,
            crc_stored=crc_stored,
            crc_computed=png_crc32(type_bytes, cdata),
            props=props,
        ))
        off = end

    # -- (c) structural well-formedness ------------------------------------
    if errors:
        return OracleVerdict(
            reason=MALFORMED_STRUCTURE,
            detail='; '.join(errors),
            chunks=chunks,
            structural_errors=errors,
            spec_basis=[RULE_SOURCES['chunk_layout']],
        )

    types = [c.type_bytes for c in chunks]

    # Structural rules from spec 11.2 Introduction / 11.2.1:
    if not types:
        errors.append('NO_CHUNKS after signature')
    else:
        if types[0] != b'IHDR':
            errors.append(
                'IHDR_NOT_FIRST (first chunk is %s); spec 11.2.1: "The IHDR '
                'chunk shall be the first chunk in the PNG datastream."'
                % chunks[0].props.text)
        if types.count(b'IHDR') != 1:
            errors.append('IHDR_COUNT=%d (spec allows exactly one)'
                          % types.count(b'IHDR'))
        if types.count(b'IEND') != 1:
            errors.append('IEND_COUNT=%d (spec allows exactly one)'
                          % types.count(b'IEND'))
        elif types[-1] != b'IEND':
            errors.append('IEND_NOT_LAST (last chunk is %s)'
                          % chunks[-1].props.text)
        if types.count(b'IDAT') < 1:
            errors.append('NO_IDAT (spec 11.2: one or more IDAT chunks required)')

    # Chunk-type legality (spec 5.3, Chunk Type field).
    for c in chunks:
        if not c.props.all_bytes_legal:
            errors.append(
                'ILLEGAL_TYPE_BYTE in chunk %d type %s; spec 5.3 restricts each '
                'type byte to 41-5A and 61-7A' % (c.index, c.props.hex))

    # Ordering of the critical chunks (spec 5.6, Table 7).
    crit_order = [t for t in types if t in (b'IHDR', b'IDAT', b'IEND', b'PLTE')]
    if crit_order not in ([b'IHDR', b'IDAT', b'IEND'],
                          [b'IHDR', b'PLTE', b'IDAT', b'IEND'],
                          [b'IHDR', b'IDAT', b'IEND', b'PLTE']):
        errors.append(
            'CRITICAL_CHUNK_ORDER=%s (spec 5.6 Table 7: IHDR, PLTE?, IDAT, IEND)'
            % ' '.join(t.decode('ascii') for t in crit_order))

    if errors:
        return OracleVerdict(
            reason=MALFORMED_STRUCTURE,
            detail='; '.join(errors),
            chunks=chunks,
            structural_errors=errors,
            spec_basis=[RULE_SOURCES['chunk_layout'],
                        RULE_SOURCES['critical_first']],
        )

    # -- (d) CRC verification (spec 5.3 CRC field / 5.5 CRC algorithm) -------
    for c in chunks:
        if not c.crc_ok:
            return OracleVerdict(
                reason=CRC_MISMATCH,
                detail=(
                    'chunk %d (%s) at offset %d: stored CRC %s, computed %s. '
                    'CONFOUND: a decoder will reject here during CRC '
                    'verification, before ever consulting the chunk type.'
                    % (c.index, c.props.text, c.offset, c.crc_hex,
                       '%08X' % c.crc_computed)),
                chunks=chunks,
                spec_basis=[RULE_SOURCES['crc']],
            )

    # -- (e) the phenomenon under study ------------------------------------
    # Spec 15.3.3 item 3: "An unknown chunk type is not treated as an error
    # unless it is a critical chunk." Item 6: "Encountering an unknown chunk in
    # which the ancillary bit is 0 generates an error if the decoder is
    # attempting to extract the image."
    #
    # Reported in stream order so the FIRST offending chunk is named.
    for c in chunks:
        if c.props.known_to_spec:
            continue
        if c.props.reserved_bit == 1:
            # Spec 15.3.3 item 7: a chunk type with the reserved bit set is
            # treated as an unknown chunk type. Classification below still
            # applies, but the type is non-conforming by construction.
            pass
        if c.props.is_critical:
            return OracleVerdict(
                reason=UNKNOWN_CRITICAL_CHUNK,
                detail=(
                    'chunk %d at offset %d has unknown type %s (%s); ancillary '
                    'bit = 0 => CRITICAL. Spec 5.4/Table 6 requires a decoder to '
                    'indicate the datastream contains information it cannot '
                    'safely interpret; 15.3.3(6) makes this an error.'
                    % (c.index, c.offset, c.props.text, c.props.hex)),
                chunks=chunks,
                spec_basis=[RULE_SOURCES['unknown_critical'],
                            RULE_SOURCES['decoder_conformance']],
            )

    return OracleVerdict(
        reason=ACCEPTED,
        detail=(
            'all %d chunks are structurally well framed, all CRCs verify, and '
            'no unknown chunk with ancillary bit = 0 is present'
            % len(chunks)),
        chunks=chunks,
        spec_basis=[RULE_SOURCES['unknown_ancillary'],
                    RULE_SOURCES['decoder_conformance']],
    )


def expected_decision(verdict: OracleVerdict) -> str:
    """Map an oracle verdict to the decision a conforming decoder must make."""
    return 'REJECT' if verdict.reason != ACCEPTED else 'ACCEPT'


def explain(verdict: OracleVerdict) -> str:
    lines = ['reason   : %s' % verdict.reason,
             'decision : %s' % expected_decision(verdict),
             'detail   : %s' % verdict.detail,
             'spec     : %s' % '; '.join(verdict.spec_basis)]
    for c in verdict.chunks:
        lines.append(
            '  [%d] off=%-4d len=%-4d type=%-6s %-11s crc=%s/%s %s %s'
            % (c.index, c.offset, c.length, c.props.text, c.props.hex,
               c.crc_hex, '%08X' % c.crc_computed,
               'CRC_OK' if c.crc_ok else 'CRC_BAD',
               'known' if c.props.known_to_spec else 'UNKNOWN'))
    return '\n'.join(lines)