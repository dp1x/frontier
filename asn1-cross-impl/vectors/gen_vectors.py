import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "oracle"))
from asn1_der_oracle import canonical_bytes, classify

OUT = os.path.join(os.path.dirname(__file__), "vectors.jsonl")
rows = []
counter = [0]


def vid():
    counter[0] += 1
    return f"asn1-vec-{counter[0]:04d}"


# ---- Encoder vectors ----
enc_cases = [
    ("BOOLEAN", False),
    ("BOOLEAN", True),
    ("INTEGER", 0),
    ("INTEGER", 1),
    ("INTEGER", 127),
    ("INTEGER", 128),
    ("INTEGER", -1),
    ("INTEGER", -128),
    ("INTEGER", -129),
    ("BIT_STRING", {"hex": "", "unused": 0}),
    ("BIT_STRING", {"hex": "a0", "unused": 5}),
    ("BIT_STRING", {"hex": "0a3b5f291cd0", "unused": 4}),  # '0A3B5F291CD'H => last byte D0, unused 4? Actually standard example unused 4
    ("OCTET_STRING", ""),
    ("OCTET_STRING", "010203"),
    ("OID", [2, 999, 3]),
    ("OID", [1, 2, 840, 113549, 1, 1, 1]),
    ("SEQ1", {"name": "Smith", "ok": True}),
    ("SET1", {"n": 5, "f": True}),
    ("SETOF_INT", [-1, 0, 1]),
    ("SETOF_INT", [5, 5, 1]),
    ("UTCTime", "920622123421Z"),
    ("GeneralizedTime", "19920622123421Z"),
    ("OCTET_STRING", "00" * 127),
    ("OCTET_STRING", "00" * 128),
    ("OCTET_STRING", "00" * 256),
    ("DefSeq_empty", None),
]
# DefSeq special: encode as empty SEQUENCE
for t, v in enc_cases:
    if t == "DefSeq_empty":
        b = bytes.fromhex("3000")
        rows.append({"id": vid(), "track": "encoder", "type": "SEQUENCE", "value": {"defseq": "empty"},
                     "expected_canonical_hex": b.hex(), "x690_clause": "8.9.3, 11.5",
                     "reason": "DEFAULT-valued components omitted"})
        continue
    b = canonical_bytes(t, v)
    rows.append({"id": vid(), "track": "encoder", "type": t, "value": v,
                 "expected_canonical_hex": b.hex(), "x690_clause": "see oracle",
                 "reason": "canonical DER"})

# BIT_STRING standard example correction: use known expected
# Replace the bit string entry? Keep as is; oracle handles.

# ---- Decoder vectors ----
def dec_row(type_name, raw_hex, reason, clause):
    raw = bytes.fromhex(raw_hex.replace(" ", ""))
    cls = classify(type_name, raw)
    rows.append({"id": vid(), "track": "decoder", "type": type_name, "input_hex": raw.hex(),
                 "expected_class": cls, "x690_clause": clause, "reason": reason})

# Canonical controls
dec_row("BOOLEAN", "01 01 00", "canonical FALSE", "8.2.2, 11.1")
dec_row("BOOLEAN", "01 01 FF", "canonical TRUE", "8.2.2, 11.1")
dec_row("INTEGER", "02 01 00", "zero", "8.3.1-8.3.3")
dec_row("INTEGER", "02 01 7F", "127", "8.3.2")
dec_row("INTEGER", "02 02 00 80", "128", "8.3.2")
dec_row("INTEGER", "02 01 FF", "-1", "8.3.1-8.3.3")
dec_row("INTEGER", "02 01 80", "-128", "8.3.1-8.3.3")
dec_row("INTEGER", "02 02 FF 7F", "-129", "8.3.2")
dec_row("BIT_STRING", "03 01 00", "empty", "8.6.2.3")
dec_row("BIT_STRING", "03 02 05 A0", "5 unused bits", "8.6.2.1-8.6.2.2")
dec_row("OCTET_STRING", "04 00", "empty", "8.7.2")
dec_row("OCTET_STRING", "04 03 01 02 03", "three bytes", "8.7.2")
dec_row("OID", "06 03 88 37 03", "{2 999 3}", "8.19.4")
dec_row("OID", "06 09 2A 86 48 86 F7 0D 01 01 01", "rsaEncryption", "8.19.2-8.19.5")
dec_row("SEQ1", "30 0A 16 05 53 6D 69 74 68 01 01 FF", "Smith/TRUE", "8.9.1-8.9.3")
dec_row("SET1", "31 06 01 01 FF 02 01 05", "tag order", "8.11.1-8.11.3,10.3")
dec_row("SETOF_INT", "31 09 02 01 00 02 01 01 02 01 FF", "sorted", "8.12.1-8.12.3,11.6")
dec_row("UTCTime", "17 0D 39 32 30 36 32 32 31 32 33 34 32 31 5A", "920622123421Z", "8.25,8.26,11.8")
dec_row("GeneralizedTime", "18 0F 31 39 39 32 30 36 32 32 31 32 33 34 32 31 5A", "19920622123421Z", "8.25,8.26,11.7")

# BER-valid non-DER
dec_row("BOOLEAN", "01 01 01", "non-canonical TRUE (BER-valid, not DER)", "8.2.2, 11.1")
dec_row("BIT_STRING", "03 02 04 0A", "nonzero unused bits (BER-valid, not DER)", "8.6.2.2, 11.2.1")
dec_row("OCTET_STRING", "24 07 04 03 01 02 03 04 00", "constructed octet string (BER-valid, not DER)", "8.7.1, 10.2")
dec_row("BIT_STRING", "23 03 03 01 00", "constructed bit string (BER-valid, not DER)", "8.6.1, 10.2")
dec_row("SET1", "31 06 02 01 05 01 01 FF", "wrong component order (BER-valid, not DER)", "8.11.2, 10.3")
dec_row("SETOF_INT", "31 09 02 01 FF 02 01 00 02 01 01", "unsorted (BER-valid, not DER)", "8.12.3, 11.6")
dec_row("SEQ1", "30 0D 16 05 53 6D 69 74 68 01 01 FF 02 01 00", "default included (BER-valid, not DER)", "8.9.3, 11.5")
# long-form length
dec_row("OCTET_STRING", "04 81 01 41", "long-form length for 1 (BER-valid, not DER)", "8.1.3.5, 10.1")
# indefinite length
dec_row("SEQ1", "30 80 16 05 53 6D 69 74 68 01 01 FF 00 00", "indefinite length (BER-valid, not DER)", "8.1.3.6, 9.1/10.1")

# Invalid BER
dec_row("INTEGER", "02 02 00 7F", "redundant leading zero (invalid BER)", "8.3.2")
dec_row("INTEGER", "02 02 FF 80", "redundant leading FF (invalid BER)", "8.3.2")
dec_row("OID", "06 02 80 03", "non-minimal subidentifier (invalid BER)", "8.19.2")
dec_row("SEQ1", "30 08 01 01 FF 16 05 53 6D", "swapped components (invalid BER)", "8.9.2")
dec_row("BIT_STRING", "03 02 08 00", "unused bits = 8 (invalid BER)", "8.6.2.1")
dec_row("OCTET_STRING", "04 80", "indefinite length on primitive (invalid BER)", "8.1.3.2")

# Trailing data
dec_row("INTEGER", "02 01 05 00", "trailing byte after valid integer", "API contract")

# Length boundaries canonical
dec_row("OCTET_STRING", "04 7F " + "00 " * 127, "127 zero octets", "8.1.3")
dec_row("OCTET_STRING", "04 81 80 " + "00 " * 128, "128 zero octets (long form)", "8.1.3.5, 10.1")

with open(OUT, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")

print(f"wrote {len(rows)} vectors")
