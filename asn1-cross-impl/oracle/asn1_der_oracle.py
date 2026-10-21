"""Clean-room DER canonical encoder/decoder for a bounded ASN.1 subset.

Types supported:
  BOOLEAN, INTEGER, BIT STRING, OCTET STRING, OBJECT IDENTIFIER,
  SEQUENCE (Seq1), SET (Set1), SET OF INTEGER, UTCTime, GeneralizedTime,
  OCTET STRING length boundaries.

No tested implementation is used as an oracle.
"""
from __future__ import annotations

import struct


def _len_enc(n: int) -> bytes:
    if n < 0:
        raise ValueError("negative length")
    if n < 0x80:
        return bytes([n])
    # minimal long form
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(b) > 4:
        raise ValueError("length too large")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, content: bytes, constructed: bool = False) -> bytes:
    t = tag | (0x20 if constructed else 0x00)
    return bytes([t]) + _len_enc(len(content)) + content


def encode_integer(v: int) -> bytes:
    if v == 0:
        content = b"\x00"
    else:
        # minimal two's complement
        nbytes = (v.bit_length() + 8) // 8 if v >= 0 else ((-v).bit_length() + 8) // 8
        # ensure sign bit
        while True:
            content = v.to_bytes(nbytes, "big", signed=True)
            # check minimality
            if len(content) > 1:
                if content[0] == 0x00 and (content[1] & 0x80) == 0:
                    nbytes -= 1
                    continue
                if content[0] == 0xFF and (content[1] & 0x80) != 0:
                    nbytes -= 1
                    continue
            break
    return _tlv(0x02, content)


def encode_boolean(v: bool) -> bytes:
    return _tlv(0x01, bytes([0xFF if v else 0x00]))


def encode_octet_string(data: bytes) -> bytes:
    return _tlv(0x04, data)


def encode_bit_string(data: bytes, unused: int) -> bytes:
    if unused < 0 or unused > 7:
        raise ValueError("unused bits out of range")
    # zero unused bits in last byte
    if data:
        last = data[-1] & (0xFF << unused) if unused else data[-1]
        data = data[:-1] + bytes([last]) if data else data
    content = bytes([unused]) + data
    return _tlv(0x03, content)


def _oid_subid_encode(x: int) -> bytes:
    if x < 0:
        raise ValueError("negative oid component")
    # minimal base-128
    out = bytearray()
    out.append(x & 0x7F)
    x >>= 7
    while x:
        out.insert(0, (x & 0x7F) | 0x80)
        x >>= 7
    return bytes(out)


def encode_oid(arcs: list[int]) -> bytes:
    if len(arcs) < 2:
        raise ValueError("oid needs at least two arcs")
    if arcs[0] < 0 or arcs[0] > 2:
        raise ValueError("first arc out of range")
    if arcs[0] in (0, 1) and arcs[1] < 0 or (arcs[0] in (0, 1) and arcs[1] > 39):
        raise ValueError("second arc out of range")
    first = arcs[0] * 40 + arcs[1]
    content = _oid_subid_encode(first)
    for a in arcs[2:]:
        content += _oid_subid_encode(a)
    return _tlv(0x06, content)


def encode_seq1(name: str, ok: bool) -> bytes:
    content = _tlv(0x16, name.encode("ascii")) + encode_boolean(ok)
    return _tlv(0x30, content, constructed=True)


def encode_set1(n: int, f: bool) -> bytes:
    # components sorted by tag: BOOLEAN (01) before INTEGER (02)
    comps = [encode_boolean(f), encode_integer(n)]
    # ensure tag order
    comps_sorted = sorted(comps, key=lambda b: b[0])
    content = b"".join(comps_sorted)
    return _tlv(0x31, content, constructed=True)


def encode_setof_ints(values: list[int]) -> bytes:
    comps = [encode_integer(v) for v in values]
    # sort by full encoding as octet string
    comps_sorted = sorted(comps)
    content = b"".join(comps_sorted)
    return _tlv(0x31, content, constructed=True)


def encode_utc_time(s: str) -> bytes:
    return _tlv(0x17, s.encode("ascii"))


def encode_gen_time(s: str) -> bytes:
    return _tlv(0x18, s.encode("ascii"))


def encode_octet_string_n(n: int) -> bytes:
    return encode_octet_string(bytes(n))


TYPE_ENCODERS = {
    "BOOLEAN": lambda v: encode_boolean(bool(v)),
    "INTEGER": lambda v: encode_integer(int(v)),
    "OCTET_STRING": lambda v: encode_octet_string(bytes.fromhex(v) if isinstance(v, str) else bytes(v)),
    "BIT_STRING": lambda v: encode_bit_string(bytes.fromhex(v["hex"]), int(v["unused"])),
    "OID": lambda v: encode_oid(list(v)),
    "SEQ1": lambda v: encode_seq1(str(v["name"]), bool(v["ok"])),
    "SET1": lambda v: encode_set1(int(v["n"]), bool(v["f"])),
    "SETOF_INT": lambda v: encode_setof_ints([int(x) for x in v]),
    "UTCTime": lambda v: encode_utc_time(str(v)),
    "GeneralizedTime": lambda v: encode_gen_time(str(v)),
}


def canonical_bytes(type_name: str, value) -> bytes:
    if type_name not in TYPE_ENCODERS:
        raise ValueError(f"unsupported type {type_name}")
    return TYPE_ENCODERS[type_name](value)


# ---------- BER/DER classification helpers ----------

def _parse_tlv(data, i=0, allow_indefinite=False):
    if i >= len(data):
        raise ValueError("truncated")
    tag = data[i]
    i += 1
    if i >= len(data):
        raise ValueError("truncated length")
    first = data[i]
    i += 1
    if first < 0x80:
        length = first
        indefinite = False
    elif first == 0x80:
        indefinite = True
        length = None
    else:
        n = first & 0x7F
        if n == 0 or i + n > len(data):
            raise ValueError("bad length")
        length = int.from_bytes(data[i:i+n], "big")
        i += n
        indefinite = False
    if indefinite:
        # find EOC 00 00 at top level (only constructed)
        # search
        start = i
        depth = 0
        j = i
        # simple: find 00 00
        while j < len(data) - 1:
            if data[j] == 0 and data[j+1] == 0:
                break
            j += 1
        if j > len(data) - 2:
            raise ValueError("no eoc")
        content = data[i:j]
        i = j + 2
        return tag, content, i, True
    if i + length > len(data):
        raise ValueError("length exceeds data")
    content = data[i:i+length]
    i += length
    return tag, content, i, False


def _is_constructed(tag):
    return bool(tag & 0x20)


def ber_parse_ok(type_name: str, raw: bytes) -> bool:
    """Lenient BER parse (enforces BER minimality for integer/oid)."""
    try:
        if type_name == "BOOLEAN":
            tag, content, i, ind = _parse_tlv(raw)
            if tag != 0x01 or ind or len(content) != 1:
                return False
            return i == len(raw)
        if type_name == "INTEGER":
            tag, content, i, ind = _parse_tlv(raw)
            if tag != 0x02 or ind or not content:
                return False
            # minimality
            if len(content) > 1:
                if content[0] == 0x00 and (content[1] & 0x80) == 0:
                    return False
                if content[0] == 0xFF and (content[1] & 0x80) != 0:
                    return False
            return i == len(raw)
        if type_name == "BIT_STRING":
            tag, content, i, ind = _parse_tlv(raw)
            # primitive 03 or constructed 23
            if tag not in (0x03, 0x23) or ind and tag == 0x03:
                # indefinite only constructed
                pass
            if tag == 0x03:
                if not content:
                    return False
                unused = content[0]
                if unused > 7 or (len(content) == 1 and unused != 0):
                    return False
                return i == len(raw)
            if tag == 0x23:
                return i == len(raw)
            return False
        if type_name == "OCTET_STRING":
            tag, content, i, ind = _parse_tlv(raw)
            if tag in (0x04, 0x24):
                return i == len(raw)
            return False
        if type_name == "OID":
            tag, content, i, ind = _parse_tlv(raw)
            if tag != 0x06 or ind or not content:
                return False
            vals = []
            cur = 0
            for b in content:
                cur = (cur << 7) | (b & 0x7F)
                if not (b & 0x80):
                    vals.append(cur)
                    cur = 0
            if cur != 0 or not vals:
                return False
            first_val = vals[0]
            if first_val < 40:
                a0, a1 = 0, first_val
            elif first_val < 80:
                a0, a1 = 1, first_val - 40
            else:
                a0, a1 = 2, first_val - 80
            arcs = [a0, a1] + vals[1:]
            try:
                if encode_oid(arcs) != raw:
                    return False
            except Exception:
                return False
            return i == len(raw)
        if type_name in ("SEQ1",):
            tag, content, i, ind = _parse_tlv(raw)
            if tag != 0x30 or not _is_constructed(tag):
                return False
            # parse two fields
            try:
                t1, c1, i1, ind1 = _parse_tlv(content, 0)
                t2, c2, i2, ind2 = _parse_tlv(content, i1)
            except Exception:
                return False
            if not (i1 + (i2 - i1) == len(content) and i2 == len(content)):
                # allow extra? no
                pass
            if i2 != len(content):
                return False
            if t1 != 0x16 or t2 != 0x01:
                return False
            return i == len(raw)
        if type_name in ("SET1",):
            tag, content, i, ind = _parse_tlv(raw)
            if tag != 0x31 or not _is_constructed(tag):
                return False
            # parse two components (any order)
            try:
                t1, c1, i1, ind1 = _parse_tlv(content, 0)
                t2, c2, i2, ind2 = _parse_tlv(content, i1)
            except Exception:
                return False
            if i2 != len(content):
                return False
            tags = sorted([t1, t2])
            if tags != [0x01, 0x02]:
                return False
            return i == len(raw)
        if type_name in ("SETOF_INT",):
            tag, content, i, ind = _parse_tlv(raw)
            if tag != 0x31 or not _is_constructed(tag):
                return False
            # parse all ints
            pos = 0
            while pos < len(content):
                t, c, npos, ind = _parse_tlv(content, pos)
                if t != 0x02:
                    return False
                pos = npos
            return pos == len(content) and i == len(raw)
        if type_name in ("UTCTime", "GeneralizedTime"):
            tag = 0x17 if type_name == "UTCTime" else 0x18
            t, content, i, ind = _parse_tlv(raw)
            if t != tag or ind:
                return False
            try:
                content.decode("ascii")
            except Exception:
                return False
            return i == len(raw)
        if type_name == "OCTET_STRING":
            return True  # handled above
    except Exception:
        return False
    return False


def is_canonical_der(type_name: str, raw: bytes) -> bool:
    """Strict: BER-valid, fully consumed, and raw == canonical re-encoding."""
    if not ber_parse_ok(type_name, raw):
        return False
    # decode value from raw
    try:
        val = decode_value(type_name, raw)
    except Exception:
        return False
    try:
        return canonical_bytes(type_name, val) == raw
    except Exception:
        return False


def decode_value(type_name: str, raw: bytes):
    if type_name == "BOOLEAN":
        tag, content, i, ind = _parse_tlv(raw)
        return content[0] != 0
    if type_name == "INTEGER":
        tag, content, i, ind = _parse_tlv(raw)
        return int.from_bytes(content, "big", signed=True)
    if type_name == "OCTET_STRING":
        tag, content, i, ind = _parse_tlv(raw)
        return content.hex()
    if type_name == "BIT_STRING":
        tag, content, i, ind = _parse_tlv(raw)
        if tag == 0x23:
            raise ValueError("constructed not decodable to simple")
        unused = content[0]
        return {"hex": content[1:].hex(), "unused": unused}
    if type_name == "OID":
        tag, content, i, ind = _parse_tlv(raw)
        # parse subids
        vals = []
        cur = 0
        for b in content:
            cur = (cur << 7) | (b & 0x7F)
            if not (b & 0x80):
                vals.append(cur)
                cur = 0
        first = vals[0]
        a0 = 2 if first >= 80 else (1 if first >= 40 else 0)
        # Actually derive first arc properly:
        if first < 40:
            a0, a1 = 0, first
        elif first < 80:
            a0, a1 = 1, first - 40
        else:
            a0, a1 = 2, first - 80
        return [a0, a1] + vals[1:]
    if type_name == "SEQ1":
        tag, content, i, ind = _parse_tlv(raw)
        t1, c1, i1, _ = _parse_tlv(content, 0)
        t2, c2, i2, _ = _parse_tlv(content, i1)
        name = c1.decode("ascii")
        ok = (c2 == b"\xff") if c2 else False
        if t2 == 0x01:
            ok = c2[0] != 0
        return {"name": name, "ok": ok}
    if type_name == "SET1":
        tag, content, i, ind = _parse_tlv(raw)
        # find bool and int by tag
        pos = 0
        n = None
        f = None
        while pos < len(content):
            t, c, npos, _ = _parse_tlv(content, pos)
            if t == 0x01:
                f = c[0] != 0
            elif t == 0x02:
                n = int.from_bytes(c, "big", signed=True)
            pos = npos
        return {"n": n, "f": f}
    if type_name == "SETOF_INT":
        tag, content, i, ind = _parse_tlv(raw)
        out = []
        pos = 0
        while pos < len(content):
            t, c, npos, _ = _parse_tlv(content, pos)
            out.append(int.from_bytes(c, "big", signed=True))
            pos = npos
        return out
    if type_name == "UTCTime":
        tag, content, i, ind = _parse_tlv(raw)
        return content.decode("ascii")
    if type_name == "GeneralizedTime":
        tag, content, i, ind = _parse_tlv(raw)
        return content.decode("ascii")
    raise ValueError(f"decode not supported for {type_name}")


def classify(type_name: str, raw: bytes) -> str:
    """Return one of: canonical-der, ber-valid-non-der, invalid-ber, trailing-data, unknown."""
    # trailing data check: try parse one value; if leftover -> trailing-data (but still maybe canonical of first?)
    # We'll detect trailing bytes at top level.
    # detect trailing: parse one top-level TLV
    try:
        tag, content, i, ind = _parse_tlv(raw)
        trailing = i != len(raw)
        prefix_ok = True
    except Exception:
        trailing = False
        prefix_ok = False
    # BER validity of the first value (without trailing)
    try:
        ber_ok = ber_parse_ok(type_name, raw[:i]) if trailing else ber_parse_ok(type_name, raw)
    except Exception:
        ber_ok = False
    if trailing and ber_ok:
        # prefix valid but extra bytes -> trailing-data
        return "trailing-data"
    if not ber_ok:
        return "invalid-ber"
    if trailing:
        return "trailing-data"
    # canonical check
    try:
        if is_canonical_der(type_name, raw):
            return "canonical-der"
    except Exception:
        pass
    return "ber-valid-non-der"
