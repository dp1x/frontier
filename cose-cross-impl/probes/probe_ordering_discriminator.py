"""Supplementary probe: does the fnd-2026-0014 evidence DISCRIMINATE
RFC 8949 section 4.2.1 (bytewise lex) from section 4.2.3 (length-first)?

If a maintainer answered "we would sort length-first, and your vectors agree
with us", the current evidence could not refute it. This tests that directly,
using the discriminating map Qwen identified: {24: b'x', -1: b'y'}.

Also records the cbor2 canonical=True semantics question, which Qwen Turn 3
left UNRESOLVED and which determines whether 'add canonical=True' is even a
valid fix.

Read-only. Prints JSON.
"""

import json
import sys
from pathlib import Path

REPO = Path(r"C:\Users\Dhane\frontier")
sys.path.insert(0, str(REPO / "cbor-cross-impl" / "oracle"))
sys.path.insert(0, str(REPO / "cose-cross-impl" / "adapters"))

import cbor2
from cbor_oracle import encode_canonical, encode_deterministic
from pycose.messages import Sign1Message

R = {"discriminators": [], "cbor2_semantics": {}, "pycose_on_discriminator": {}}

# -------------------------------------------------------------------
# 1. Which of the already-cited vectors actually discriminate?
# -------------------------------------------------------------------
CITED = {
    "int-only {4:b'y',3:50}": {4: b"y", 3: 50},
    "tstr-only {a,aa,b,ab,z}": {"a": 1, "aa": 2, "b": 3, "ab": 4, "z": 5},
    "mixed {2,mmm,4,qqq}": {2: ["zzz"], "mmm": 7, 4: b"kid-bytes", "qqq": True},
}
for name, m in CITED.items():
    c421 = encode_canonical(m).hex()
    c423 = encode_deterministic(m).hex()
    R["discriminators"].append(
        {
            "map": name,
            "section_4_2_1": c421,
            "section_4_2_3": c423,
            "discriminates": c421 != c423,
            "note": (
                "Does NOT discriminate: a maintainer sorting length-first would "
                "produce the same bytes, so these vectors cannot refute that "
                "defence."
                if c421 == c423
                else "Discriminates."
            ),
        }
    )

# -------------------------------------------------------------------
# 2. A map that DOES discriminate, and what pycose does with it
# -------------------------------------------------------------------
DISC = {24: b"x", -1: b"y"}
d421 = encode_canonical(DISC).hex()
d423 = encode_deterministic(DISC).hex()
ins = cbor2.dumps(DISC).hex()
R["discriminator_map"] = {
    "map": '{24: b"x", -1: b"y"}',
    "section_4_2_1_bytewise_lex": d421,
    "section_4_2_3_length_first": d423,
    "insertion_order_cbor2_default": ins,
    "discriminates": d421 != d423,
    "caveat": (
        "cbor2's own insertion-order default coincides with 4.2.1 here, so "
        "insertion-order output alone cannot prove absence of a sort on this "
        "map. The decisive evidence is that reversing insertion order changes "
        "the emitted bytes."
    ),
}


def _try(label_map):
    """Construct Sign1Message and read the protected bucket back."""
    try:
        m = Sign1Message(phdr=dict(label_map), uhdr={}, payload=b"p")
        sig = m._create_sig_structure()
        prot = cbor2.loads(sig)[1]
        return prot.hex(), list(cbor2.loads(prot).keys()), None
    except Exception as exc:
        return None, None, f"{type(exc).__name__}: {exc}"


# Label 24 is 'PARTIAL_IV' in pycose, whose value_parser rejects a bytes value.
# Record that rejection explicitly, then use a negative unregistered label.
_px, _pk, _perr = _try(DISC)
R["pycose_discriminator_label_24_rejected"] = {
    "map": '{24: b"x", -1: b"y"}',
    "error": _perr,
    "cause": (
        "label 24 is registered as PARTIAL_IV in pycose, whose value_parser "
        "requires an int; b'x' is rejected. This is pycose label validation, "
        "not the CBOR encoder."
    ),
}

# Unregistered negative labels avoid value_parser entirely. Need two labels
# whose ENCODED LENGTHS differ, otherwise 4.2.1 and 4.2.3 agree and the map
# cannot discriminate. pycose registers -1..-3 and -20..-26 as COSE_KEY
# headers (value_parser = CoseKey.from_dict, which rejects bytes), so pick
# labels outside that set: -4 (encodes 0x23, 1 byte) and -100 (0x1863, 2 bytes).
DISC_NEG = {-4: b"x", -100: b"y"}
n421 = encode_canonical(DISC_NEG).hex()
n423 = encode_deterministic(DISC_NEG).hex()
nx, nk, nerr = _try(DISC_NEG)
R["pycose_on_discriminator"] = {
    "map": "{-4: b'x', -100: b'y'}",
    "why_these_labels": (
        "Both labels are unregistered in pycose (which registers -1..-3 and "
        "-20..-26 as COSE_KEY headers with a value_parser that rejects bytes), "
        "and their encoded lengths differ (0x23 = 1 byte, 0x1863 = 2 bytes) so "
        "4.2.1 and 4.2.3 order them oppositely."
    ),
    "accepted_labels": nerr is None,
    "error": nerr,
    "section_4_2_1": n421,
    "section_4_2_3": n423,
    "insertion_order": cbor2.dumps(DISC_NEG).hex(),
    "discriminates": n421 != n423,
    "protected_hex": nx,
    "decoded_key_order": nk,
    "equals_4_2_1": nx == n421,
    "equals_4_2_3": nx == n423,
    "equals_insertion": nx == cbor2.dumps(DISC_NEG).hex(),
}
try:
    msg2 = Sign1Message(phdr={-100: b"y", -4: b"x"}, uhdr={}, payload=b"p")
    prot2 = cbor2.loads(msg2._create_sig_structure())[1]
    R["pycose_on_discriminator"]["reversed_protected_hex"] = prot2.hex()
    R["pycose_on_discriminator"]["reversed_differs"] = prot2.hex() != nx
    R["pycose_on_discriminator"]["reversed_equals_4_2_1"] = prot2.hex() == n421
    R["pycose_on_discriminator"]["reversed_equals_4_2_3"] = prot2.hex() == n423
except Exception as exc:
    R["pycose_on_discriminator"]["reversed_error"] = f"{type(exc).__name__}: {exc}"

# -------------------------------------------------------------------
# 2b. THE DECISIVE VECTOR: a map where 4.2.1 and 4.2.3 disagree, using
#     one int label and one tstr label. int 1000 encodes as 0x1903e8
#     (3 bytes); tstr 'z' encodes as 0x617a (2 bytes). So:
#       4.2.1 bytewise lex  : 0x19 < 0x61  -> int 1000 first
#       4.2.3 length-first  : 2 bytes < 3  -> 'z' first
#     Both labels are legal COSE labels; neither int 1000 nor 'z' triggers a
#     pycose value_parser.
# -------------------------------------------------------------------
DEC = {1000: b"x", "z": b"y"}
dec421 = encode_canonical(DEC).hex()
dec423 = encode_deterministic(DEC).hex()
dx, dk, derr = _try(DEC)
try:
    dmsg2 = Sign1Message(phdr={"z": b"y", 1000: b"x"}, uhdr={}, payload=b"p")
    drev = cbor2.loads(dmsg2._create_sig_structure())[1].hex()
except Exception as exc:
    drev = f"ERROR {type(exc).__name__}: {exc}"

R["decisive_discriminator"] = {
    "map": '{1000: b"x", "z": b"y"}',
    "why": (
        "int 1000 encodes as 0x1903e8 (3 bytes, leading byte 0x19); tstr 'z' "
        "encodes as 0x617a (2 bytes, leading byte 0x61). RFC 8949 4.2.1 orders "
        "by leading byte (int first); 4.2.3 orders by length ('z' first). The "
        "two rules disagree, so this vector distinguishes them."
    ),
    "section_4_2_1_bytewise_lex": dec421,
    "section_4_2_3_length_first": dec423,
    "discriminates": dec421 != dec423,
    "pycose_forward": dx,
    "pycose_forward_key_order": dk,
    "pycose_reversed": drev,
    "forward_equals_4_2_1": dx == dec421,
    "forward_equals_4_2_3": dx == dec423,
    "reversed_equals_4_2_1": drev == dec421,
    "reversed_equals_4_2_3": drev == dec423,
    "cbor2_canonical_true": cbor2.dumps(DEC, canonical=True).hex(),
    "cbor2_canonical_is_4_2_3": cbor2.dumps(DEC, canonical=True).hex() == dec423,
    "interpretation": (
        "If pycose sorted by either rule, BOTH insertion orders would emit the "
        "same bytes. They do not. Forward output coincides with 4.2.1 and "
        "reversed output coincides with 4.2.3 purely because the supplied "
        "insertion order changed. This is direct evidence that pycose applies "
        "NEITHER ordering rule: it emits insertion order."
    ),
    "refutes_length_first_defence": (
        "A maintainer replying 'we sort per 4.2.3 length-first' would be "
        "contradicted by the reversed case, which emits 4.2.3 order only "
        "because that was the supplied order, and emits different bytes when "
        "the order is reversed."
    ),
}

# -------------------------------------------------------------------
# 3. cbor2 canonical=True semantics (Qwen Turn 3: UNRESOLVED)
# -------------------------------------------------------------------
R["cbor2_semantics"] = {
    "question": "Does cbor2 6.1.4 canonical=True implement RFC 8949 4.2.1 or 4.2.3?",
    "map": '{24: b"x", -1: b"y"}',
    "cbor2_canonical_true": cbor2.dumps(DISC, canonical=True).hex(),
    "frontier_4_2_1": d421,
    "frontier_4_2_3": d423,
    "canonical_true_is_4_2_1": cbor2.dumps(DISC, canonical=True).hex() == d421,
    "canonical_true_is_4_2_3": cbor2.dumps(DISC, canonical=True).hex() == d423,
    "consequence": (
        "If canonical=True is length-first, then adding canonical=True to "
        "pycose's encoder would NOT satisfy RFC 9052 section 9, which selects "
        "4.2.1. The obvious one-line fix is wrong."
    ),
    "cbor2_version": getattr(cbor2, "__version__", "unknown"),
}

# Cross-check on the two key kinds that matter for COSE: tstr and int of
# differing encoded length.
for name, m in {
    "tstr len-vary {a,aa}": {"a": 1, "aa": 2},
    "int len-vary {24,-1}": DISC,
    "int len-vary {100,10}": {100: 1, 10: 2},
}.items():
    R.setdefault("cbor2_semantics_crosscheck", []).append(
        {
            "map": name,
            "cbor2_canonical": cbor2.dumps(m, canonical=True).hex(),
            "frontier_4_2_1": encode_canonical(m).hex(),
            "frontier_4_2_3": encode_deterministic(m).hex(),
            "cbor2_matches_4_2_1": cbor2.dumps(m, canonical=True).hex() == encode_canonical(m).hex(),
            "cbor2_matches_4_2_3": cbor2.dumps(m, canonical=True).hex() == encode_deterministic(m).hex(),
        }
    )

print(json.dumps(R, indent=2, default=str))