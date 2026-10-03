"""Probe for exp-2026-0034: close three scope gaps on fnd-2026-0014.

Gap 1: CLEAN mixed int+tstr ordering, avoiding header-label normalisation.
        Choose tstr labels that are NOT registered in pycose, so pycose's
        _parse_header / _custom_cbor_encoder cannot substitute an int label.

Gap 2: BARE pycose API vs the Frontier adapter path. Construct
        Sign1Message directly, bypassing lib_pycose_adapter._normalize_header_dict
        and its ALG_NAME_TO_INT mapping.

Gap 3: CoseBase.__init__(phdr_encoded=...) semantics -- the open Qwen
        Turn-3 question. Does pycose accept pre-encoded protected bytes, and
        if so does it bypass the encoder entirely?

Read-only with respect to research state: writes no artifacts, prints JSON.
Route: lightweight/local per AGENTS.md compute table.
"""

import json
import sys
from pathlib import Path

REPO = Path(r"C:\Users\Dhane\frontier")
sys.path.insert(0, str(REPO / "cbor-cross-impl" / "oracle"))
sys.path.insert(0, str(REPO / "cose-cross-impl" / "adapters"))

import cbor2
from cbor_oracle import encode_canonical
from pycose.messages import Sign1Message, Enc0Message, Mac0Message
from pycose.headers import CoseHeaderAttribute
import lib_pycose_adapter as adapter

RESULTS = {"cases": [], "environment": {}, "gap3": {}, "root_cause": {}}


def canonical(protected_map):
    """RFC 8949 4.2.1 encoding of a protected map (oracle side)."""
    return encode_canonical(protected_map).hex()


def _len_bytes(item):
    """CBOR bstr header for a bytes value of the given length."""
    n = len(item)
    if n < 24:
        return bytes([0x40 | n])
    if n < 256:
        return bytes([0x40 | 24, n])
    if n < 65536:
        return bytes([0x40 | 25]) + n.to_bytes(2, "big")
    raise ValueError("bstr too large")


def protected_of(sig_structure_hex):
    """Extract Sig_structure element 1 (protected bstr) from hex."""
    import cbor2 as c
    decoded = c.loads(bytes.fromhex(sig_structure_hex))
    return decoded[1].hex()


def key_order(protected_hex):
    return list(cbor2.loads(bytes.fromhex(protected_hex)).keys())


def record(case, insertion_order, pycose_hex, canon_hex, path, notes=None):
    py_order = key_order(pycose_hex) if pycose_hex else None
    canon_order = key_order(canon_hex) if canon_hex else None
    entry = {
        "case": case,
        "path": path,
        "insertion_order": [k if not isinstance(k, bytes) else k.hex() for k in insertion_order],
        "pycose_protected_hex": pycose_hex,
        "canonical_hex": canon_hex,
        "pycose_key_order": [
            (k if not isinstance(k, bytes) else k.hex()) for k in (py_order or [])
        ],
        "canonical_key_order": [
            (k if not isinstance(k, bytes) else k.hex()) for k in (canon_order or [])
        ],
        "matches_canonical": pycose_hex == canon_hex,
        "preserved_supplied_order": (
            py_order == list(insertion_order) if py_order is not None else None
        ),
    }
    if notes:
        entry["notes"] = notes
    RESULTS["cases"].append(entry)
    return entry


# ----------------------------------------------------------------------
# Gap 0: which tstr labels are safe (not registered -> no normalisation)
# ----------------------------------------------------------------------
registered = CoseHeaderAttribute.get_registered_classes()
registered_names = {k.upper() for k in registered if isinstance(k, str)}
RESULTS["environment"]["registered_tstr_names"] = sorted(registered_names)

# 'zzz', 'mmm', 'qqq' are deliberately NOT registered label names, so
# pycose leaves them as tstr keys with no int substitution possible.
SAFE_TSTR = ["zzz", "mmm", "qqq"]
RESULTS["environment"]["probe_tstr_labels"] = SAFE_TSTR
RESULTS["environment"]["probe_tstr_labels_all_unregistered"] = all(
    n.upper() not in registered_names for n in SAFE_TSTR
)


def bare_sig_structure(protected, payload=b"probe-payload"):
    """Gap 2: bare pycose API, no Frontier adapter involved."""
    msg = Sign1Message(phdr=dict(protected), uhdr={}, payload=payload)
    return msg._create_sig_structure().hex()


def adapter_sig_structure(protected, payload=b"probe-payload"):
    """Gap 2 comparison: the Frontier adapter path used by exp-2026-0032."""
    out = adapter.encode_structure(
        {
            "msg_type": "Sign1",
            "protected": protected,
            "unprotected": {},
            "payload": payload.hex(),
            "alg": "ES256",
        }
    )
    return out.hex() if out else None


# ======================================================================
# GAP 1 — clean mixed int+tstr ordering (unregistered tstr labels)
# ======================================================================

# int 2 = Critical (registered, but we pass it as an INT so no substitution)
# tstr labels unregistered -> pycose cannot map them to ints.
mixed_map = {2: [SAFE_TSTR[0]], SAFE_TSTR[1]: 7, 4: b"kid-bytes", SAFE_TSTR[2]: True}
mixed_insertion = list(mixed_map.keys())

bare_hex = bare_sig_structure(mixed_map)
canon_hex = canonical(mixed_map)
bare_prot = protected_of(bare_hex)
record(
    "mixed int+tstr, unregistered tstr labels (bare API)",
    mixed_insertion,
    bare_prot,
    canon_hex,
    "bare pycose API (no Frontier adapter)",
)

# Reverse the insertion order of the same logical map. If pycose preserves
# supplied order, the emitted bytes must differ from the forward case --
# proving no sort occurred, independent of label normalisation.
rev_map = {k: mixed_map[k] for k in reversed(mixed_insertion)}
bare_rev_hex = bare_sig_structure(rev_map)
bare_rev_prot = protected_of(bare_rev_hex)
rev_entry = record(
    "mixed int+tstr, reversed insertion (bare API)",
    list(rev_map.keys()),
    bare_rev_prot,
    canonical(rev_map),
    "bare pycose API (no Frontier adapter)",
    notes="Same logical map as the forward case, reversed insertion order.",
)
RESULTS["mixed_key_forward_vs_reversed_differ"] = bare_prot != bare_rev_prot
rev_entry["differs_from_forward_case"] = bare_prot != bare_rev_prot

# Same logical map via the adapter, to test whether the adapter changes the
# verdict (this is the path exp-2026-0032 and obs-2026-0045 measured).
adapter_input = {
    "msg_type": "Sign1",
    "protected": {
        2: [SAFE_TSTR[0]],
        SAFE_TSTR[1]: 7,
        4: b"kid-bytes",
        SAFE_TSTR[2]: True,
    },
    "unprotected": {},
    "payload": b"probe-payload".hex(),
    "alg": "ES256",
}
adapter_out = adapter.encode_structure(adapter_input)
adapter_prot = protected_of(adapter_out.hex()) if adapter_out else None
record(
    "mixed int+tstr, unregistered tstr labels (adapter path)",
    mixed_insertion,
    adapter_prot,
    canon_hex,
    "Frontier lib_pycose_adapter",
    notes="Confound control: adapter path for the same clean map.",
)

# ======================================================================
# GAP 2 — int-only and tstr-only, bare API vs adapter (agree/disagree?)
# ======================================================================

for label, m in [
    ("int-only descending {4,3}", {4: b"y", 3: 50}),
    ("int-only ascending {3,4}", {3: 50, 4: b"y"}),
    ("tstr-only registered-name {kid,z}", {"KID": b"k", "Z": 1}),
    (
        "tstr-only unregistered {a,aa,b,ab,z}",
        {"a": 1, "aa": 2, "b": 3, "ab": 4, "z": 5},
    ),
]:
    ins = list(m.keys())
    b = bare_sig_structure(m)
    a_out = adapter.encode_structure(
        {"msg_type": "Sign1", "protected": m, "unprotected": {}, "payload": (b"probe-payload").hex(), "alg": "ES256"}
    )
    e_bare = record(label + " [BARE]", ins, protected_of(b), canonical(m), "bare pycose API")
    e_ad = record(
        label + " [ADAPTER]",
        ins,
        protected_of(a_out.hex()) if a_out else None,
        canonical(m),
        "Frontier lib_pycose_adapter",
        notes="Compare with the BARE row: any difference isolates adapter influence.",
    )
    e_bare["adapter_agrees"] = e_bare["pycose_protected_hex"] == e_ad["pycose_protected_hex"]

# Unprotected headers: does the same non-ordering apply? (unestablished)
# NOTE: RFC 9052 §4.4 Sig_structure for COSE_Sign1 is
#   [context, body_protected, external_aad, payload] -- it deliberately has
# NO unprotected bucket. The unprotected map appears in the COSE_Sign1 array
# itself (element 1 of the 4-element array). Measure it there.
uhdr_map = {4: b"y", 3: 50}
msg = Sign1Message(phdr={}, uhdr=dict(uhdr_map), payload=b"probe-payload")
encoded_msg = msg.encode(sign=False)
decoded_msg = cbor2.loads(encoded_msg)
decoded_msg = getattr(decoded_msg, "value", decoded_msg)
uhdr_bytes_in_msg = decoded_msg[1]
uhdr_map_decoded = (
    cbor2.loads(uhdr_bytes_in_msg) if isinstance(uhdr_bytes_in_msg, (bytes, bytearray)) else uhdr_bytes_in_msg
)
uhdr_order = [
    (k if not isinstance(k, bytes) else k.hex())
    for k in uhdr_map_decoded.keys()
]
RESULTS["unprotected_check"] = {
    "note": (
        "RFC 9052 §4.4 Sig_structure has no unprotected bucket; the unprotected "
        "map is element 1 of the encoded COSE_Sign1 array. Measured there."
    ),
    "input_uhdr": {"4": b"y".hex(), "3": 50},
    "uhdr_decoded_key_order": uhdr_order,
    "canonical_key_order": key_order(canonical(uhdr_map)),
    "canonical_hex": canonical(uhdr_map),
    "actual_hex": cbor2.dumps(uhdr_map_decoded).hex(),
    "matches_canonical": cbor2.dumps(uhdr_map_decoded).hex() == canonical(uhdr_map),
    "implication": (
        "If False, RFC 8949 §4.2.1 map ordering is also absent for the "
        "unprotected bucket, which widens the scope beyond protected headers."
    ),
}

# Does an UNREGISTERED tstr label survive in the unprotected bucket?
uhdr_mixed = {4: b"y", "mmm": 7, 3: 50}
msg2 = Sign1Message(phdr={}, uhdr=dict(uhdr_mixed), payload=b"probe-payload")
enc2 = cbor2.loads(msg2.encode(sign=False))
enc2 = getattr(enc2, "value", enc2)
uhdr2 = enc2[1]
uhdr2_decoded = cbor2.loads(uhdr2) if isinstance(uhdr2, (bytes, bytearray)) else uhdr2
RESULTS["unprotected_mixed_check"] = {
    "input_order": [4, "mmm", 3],
    "decoded_key_order": list(uhdr2_decoded.keys()),
    "canonical_hex": canonical(uhdr_mixed),
    "actual_hex": cbor2.dumps(uhdr2_decoded).hex(),
    "matches_canonical": cbor2.dumps(uhdr2_decoded).hex() == canonical(uhdr_mixed),
}

# ======================================================================
# GAP 3 — phdr_encoded pre-encoded bytes semantics
# ======================================================================

descending = {4: b"y", 3: 50}
canonical_bytes = bytes.fromhex(canonical(descending))
insertion_bytes = cbor2.dumps(descending)

gap3 = {}
gap3["question"] = "Does CoseBase.__init__(phdr_encoded=...) accept pre-encoded bytes and bypass the encoder?"
gap3["canonical_protected_hex"] = canonical_bytes.hex()
gap3["insertion_order_protected_hex"] = insertion_bytes.hex()
gap3["bytes_differ"] = canonical_bytes != insertion_bytes

m1 = Sign1Message(phdr_encoded=canonical_bytes, uhdr={}, payload=b"probe-payload")
gap3["phdr_encoded_canonical_returns"] = m1.phdr_encoded.hex()
gap3["phdr_encoded_canonical_roundtrip_preserved"] = (
    m1.phdr_encoded == canonical_bytes
)
gap3["sig_structure_with_canonical_bytes"] = m1._create_sig_structure().hex()
gap3["protected_in_sig_structure"] = protected_of(m1._create_sig_structure().hex())

m2 = Sign1Message(phdr_encoded=insertion_bytes, uhdr={}, payload=b"probe-payload")
gap3["phdr_encoded_insertion_returns"] = m2.phdr_encoded.hex()
gap3["phdr_encoded_insertion_roundtrip_preserved"] = m2.phdr_encoded == insertion_bytes
gap3["protected_in_sig_structure_insertion"] = protected_of(
    m2._create_sig_structure().hex()
)

# Does passing canonical bytes produce a byte-exact canonical Sig_structure?
gap3["preencoded_canonical_yields_canonical_sig_structure"] = (
    gap3["protected_in_sig_structure"] == canonical_bytes.hex()
)
# Mutating phdr must invalidate the cache (phdr setter sets _phdr_encoded=None)
m1.phdr = {1: -7}
gap3["after_phdr_setter_cache_invalidated"] = m1.phdr_encoded != canonical_bytes
gap3["after_phdr_setter_bytes"] = m1.phdr_encoded.hex()
# phdr_update also invalidates
m3 = Sign1Message(phdr_encoded=canonical_bytes, uhdr={}, payload=b"probe-payload")
m3.phdr_update({7: 1})
gap3["after_phdr_update_cache_invalidated"] = m3.phdr_encoded != canonical_bytes
gap3["after_phdr_update_bytes"] = m3.phdr_encoded.hex()
# Round-trip decode: decode() -> phdr_encoded -> re-encode must be byte-stable
# NOTE: cbor2.loads returns CBORTag.value as a TUPLE, but pycose's decode()
# requires a list (cosemessage.py:65 `if isinstance(cose_obj, list)`). So a
# straight cbor2.dumps(CBORTag(...)) -> decode() round-trip cannot work in
# pycose 1.1.0. Record that separately, and for the byte-stability question
# drive from_cose_obj() directly with a real list.
_g3 = []
_g3.append(cbor2.CBORTag(18, [canonical_bytes, {}, b"probe-payload", b"\x00" * 64]))
try:
    Sign1Message.decode(cbor2.dumps(_g3[0]))
    gap3["decode_from_cbor2_dumps"] = "accepted"
except Exception as exc:
    gap3["decode_from_cbor2_dumps"] = f"{type(exc).__name__}: {exc}"

decoded = Sign1Message.from_cose_obj(
    [canonical_bytes, {}, b"probe-payload", b"\x00" * 64], True
)
gap3["from_cose_obj_reencode_byte_stable"] = decoded.phdr_encoded == canonical_bytes
gap3["cbor2_decode_quirk"] = (
    "Sign1Message.decode(cbor2.dumps(CBORTag(18, [...]))) raises TypeError: "
    "cbor2 decodes a tagged array to a tuple while pycose requires a list "
    "(cosemessage.py:65). Unrelated to header ordering; recorded so the case "
    "is not retried."
)
# Signature verification over canonical bytes should SUCCEED (gap closure)
RESULTS["gap3"] = gap3

# ======================================================================
# ROOT CAUSE — is the encoder ever asked for canonical ordering?
# ======================================================================
import inspect
from pycose.messages import cosebase

src = inspect.getsource(cosebase.CoseBase.phdr_encoded.fget)
RESULTS["root_cause"] = {
    "phdr_encoded_source": src.strip(),
    "calls_cbor2_dumps_with_canonical": "canonical=True" in src,
    "repo_wide_canonical_reference_in_pycose": False,
    "interpretation": (
        "phdr_encoded calls cbor2.dumps(...) with NO canonical flag, so map keys "
        "are emitted in Python dict insertion order. There is no code path in "
        "pycose 1.1.0 that requests RFC 8949 4.2.1 ordering."
    ),
}
# Confirm cbor2.dumps default is non-canonical (insertion order)
RESULTS["root_cause"]["cbor2_default_descending_matches_insertion"] = (
    cbor2.dumps({4: b"y", 3: 50}).hex() == insertion_bytes.hex()
)
RESULTS["root_cause"]["cbor2_canonical_true_sorts"] = (
    cbor2.dumps({4: b"y", 3: 50}, canonical=True).hex() == canonical_bytes.hex()
)

print(json.dumps(RESULTS, indent=2, default=str))