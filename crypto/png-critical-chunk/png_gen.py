"""Deterministic raw-byte PNG vector generator for the unknown-critical-chunk
harness.

Design constraints honoured here:
  * No PNG library is used to BUILD anything. Pillow / imageio / pypng are not
    imported. Every byte is assembled by hand from the specification.
  * zlib is used ONLY for (i) CRC-32 over type+data (spec 5.5) and (ii) the
    deflate/zlib stream that the spec REQUIRES inside IDAT (spec 10.1).
    Neither use can rewrite, reorder or repair a chunk.
  * Output is deterministic: no timestamps, no randomness, fixed zlib level.

Normative source: PNG Specification (Third Edition), W3C Recommendation
24 June 2025, https://www.w3.org/TR/2025/REC-png-3-20250624/
Sections used: 5.2 signature, 5.3 chunk layout, 5.4/Table 6 chunk naming,
5.5 CRC, 5.6/Table 7 ordering, 10.1 compression method 0, 11.2.1 IHDR,
11.2.3 IDAT, 11.2.4 IEND, 11.3.3.2 tEXt, 11.3.2.2 gAMA.
"""

from __future__ import annotations

import struct
import zlib

from png_oracle import PNG_SIGNATURE, decode_type_properties, png_crc32

# ---------------------------------------------------------------------------
# IHDR field constants for the minimal image (spec 11.2.1)
# ---------------------------------------------------------------------------
WIDTH = 1
HEIGHT = 1
BIT_DEPTH = 8
COLOR_TYPE = 0        # 0 = greyscale (spec Table 9); smallest legal image
COMPRESSION_METHOD = 0
FILTER_METHOD = 0
INTERLACE_METHOD = 0

#: gAMA image gamma value, encoded per spec 11.3.2.2 as gamma*100000.
GAMA_45455 = 45455


def ihdr_data() -> bytes:
    """IHDR chunk data, built field-by-field per spec 11.2.1."""
    return (
        struct.pack('>I', WIDTH)
        + struct.pack('>I', HEIGHT)
        + struct.pack('>B', BIT_DEPTH)
        + struct.pack('>B', COLOR_TYPE)
        + struct.pack('>B', COMPRESSION_METHOD)
        + struct.pack('>B', FILTER_METHOD)
        + struct.pack('>B', INTERLACE_METHOD)
    )


def idat_data() -> bytes:
    """IDAT chunk data for a 1x1 greyscale image.

    Image data = filter type byte + one scanline, for filter method 0
    (spec 9.2: filter type 0 = None, so the scanline is unaltered) and
    interlace method 0 (spec 8.1). For a 1x1 greyscale, 8-bit image the single
    scanline is one byte, preceded by one filter-type byte: 2 bytes total.
    The image data is then compressed per spec 10.1 with zlib method 8.
    """
    raw = bytes((0x00, 0x00))            # filter type 0 (None), sample value 0
    return zlib.compress(raw, 9)         # deterministic, no timestamp


def make_chunk(type_bytes: bytes, data: bytes,
               corrupt_crc: bool = False) -> bytes:
    """Assemble one chunk: length | type | data | CRC.

    CRC covers type + data and NOT the length field (spec 5.3). Stored MSB
    first. When corrupt_crc is set the transmitted CRC is flipped so the
    harness's CRC check must fire; this is used ONLY for the negative control.
    """
    crc = png_crc32(type_bytes, data)
    if corrupt_crc:
        crc ^= 0xFFFFFFFF
    return (
        struct.pack('>I', len(data))
        + type_bytes
        + data
        + struct.pack('>I', crc)
    )


def minimal_png(extra_before_ihdr: bytes = b'',
                extra_after_ihdr: bytes = b'',
                extra_after_idat: bytes = b'') -> bytes:
    """Build the smallest conforming PNG, with optional injected chunks.

    Placement (spec 5.6 / Table 7 and 11.2.1):
      extra_before_ihdr -> between signature and IHDR. NOT conforming: IHDR
        shall be the first chunk. Callers must not use this for a vector whose
        expected verdict is ACCEPT.
      extra_after_ihdr -> between IHDR and IDAT. Valid position for ancillary
        chunks; spec 15.3.3(12) says no assumptions are made about ancillary
        chunk positioning.
      extra_after_idat -> between IDAT and IEND. Also a valid position for
        ancillary chunks.
    """
    return (
        PNG_SIGNATURE
        + extra_before_ihdr
        + make_chunk(b'IHDR', ihdr_data())
        + extra_after_ihdr
        + make_chunk(b'IDAT', idat_data())
        + extra_after_idat
        + make_chunk(b'IEND', b'')
    )


def minimal_png_color(extra_before_ihdr: bytes = b'',
                      extra_after_ihdr: bytes = b'',
                      extra_after_idat: bytes = b'',
                      color_type: int = 2,
                      width: int = 1,
                      height: int = 1) -> bytes:
    """Smallest PNG of an arbitrary colour type, with optional injected chunks.

    Needed for the PLTE positive control: spec 11.2.2 says PLTE is required for
    colour type 3, optional for colour types 2 and 6, and "shall not appear for
    color types 0 and 4". Colour type 2 (truecolor, 8-bit) is used so PLTE is
    legal there.
    """
    bits = {0: 8, 2: 8, 3: 8, 4: 8, 6: 8}[color_type]
    samples = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    hdr = (struct.pack('>I', width) + struct.pack('>I', height)
           + struct.pack('>B', bits) + struct.pack('>B', color_type)
           + struct.pack('>B', 0) + struct.pack('>B', 0) + struct.pack('>B', 0))
    raw = bytes((0x00,)) + bytes(width * samples)     # filter 0 + one scanline
    idat = zlib.compress(raw, 9)
    return (
        PNG_SIGNATURE
        + extra_before_ihdr
        + make_chunk(b'IHDR', hdr)
        + extra_after_ihdr
        + make_chunk(b'IDAT', idat)
        + extra_after_idat
        + make_chunk(b'IEND', b'')
    )


# ---------------------------------------------------------------------------
# Chunk payloads used by the corpus
# ---------------------------------------------------------------------------

UNKNOWN_CHUNK_DATA = b'frontier-criticality-probe'


def unknown_ancillary_type() -> bytes:
    """Unknown ANCILLARY chunk type, spec-conforming naming.

    'vQAx': byte0 'v' lowercase => ancillary bit 1; byte1 'Q' uppercase =>
    public; byte2 'A' UPPERCASE => reserved bit 0 (required by spec 5.4 /
    Table 6: "In this International Standard, all chunk names shall have
    uppercase third letters"); byte3 'x' lowercase => safe to copy. No chunk
    in the specification's registered set begins 'vQA'.
    """
    return b'vQAx'


def unknown_critical_type() -> bytes:
    """The paired CRITICAL type: identical except the ancillary bit.

    'VQAx' differs from 'vQAx' in exactly one bit: bit 5 (value 32) of byte 0.
    """
    return b'VQAx'


def gamа_data() -> bytes:
    return struct.pack('>I', GAMA_45455)


def text_data(keyword: bytes = b'Comment', text: bytes = b'frontier') -> bytes:
    """tEXt data: keyword | null separator | text (spec 11.3.3.2)."""
    assert 1 <= len(keyword) <= 79
    assert b'\x00' not in keyword and b'\x00' not in text
    return keyword + b'\x00' + text