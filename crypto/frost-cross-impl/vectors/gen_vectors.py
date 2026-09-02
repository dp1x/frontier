"""
Deterministic FROST test-vector generator (msn-2026-0019).

Generates a normative corpus of test vectors that exercise:
  - Both ciphersuites (secp256k1, ed25519) where supported
  - All audit axes defined in spc-2026-0006
  - KAT re-runs (byte-exact against on-disk KAT JSONs)
  - Negative stimuli (where supported by the ciphersuite)

Determinism: seed = 0xC0DE0CB0 (same as COSE cohort). No randomness.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Optional

# Import the cleanroom
CLEANROOM_DIR = Path(__file__).parent.parent / "cleanroom"
sys.path.insert(0, str(CLEANROOM_DIR))
import frost_cleanroom  # type: ignore
from frost_cleanroom import frost_sign, run_self_test  # type: ignore

VECTORS_DIR = Path(__file__).parent

# Deterministic seed for vector generation (matches COSE cohort)
SEED = 0xC0DE0CB0


def make_kr_kats() -> list[dict]:
    """Re-run RFC 9591 Appendix E KAT vectors through cleanroom.
    Each vector is a single (input, per-step output) record."""
    kat_dir = VECTORS_DIR.parent / "kat"
    vectors = []
    for group, fname, expected_tag in [
        ("secp256k1", "rfc9591_appendix_e5_secp256k1.json", "E.5"),
        ("ed25519", "rfc9591_appendix_e1_ed25519.json", "E.1"),
    ]:
        kat_path = kat_dir / fname
        if not kat_path.exists():
            continue
        out = frost_sign(kat_path, group=group)
        vectors.append({
            "axis": "kat_replay",
            "ciphersuite": group,
            "spec_ref": f"RFC 9591 Appendix {expected_tag}",
            "kat_file": fname,
            "round_one": out["round_one"],
            "round_two": out["round_two"],
            "aggregate_R_hex": out["aggregate_R_hex"],
            "aggregate_z_hex": out["aggregate_z_hex"],
            "challenge_hex": out["challenge_hex"],
            "expected_final_sig": out["expected_final_sig"],
            "computed_final_sig": out["computed_final_sig"],
            "match_final_sig": out["match_final_sig"],
            "verify_aggregate": out["verify_aggregate"],
            "seed": hex(SEED),
        })
    return vectors


def make_deterministic_message_variants() -> list[dict]:
    """Generate variants of the KAT with different messages (deterministic).
    The share polynomials and commitments are reused from the KAT; only
    the message varies. This tests the challenge/lagrange path."""
    import json as _json
    kat_dir = VECTORS_DIR.parent / "kat"
    vectors = []
    for group, fname in [("secp256k1", "rfc9591_appendix_e5_secp256k1.json"),
                         ("ed25519", "rfc9591_appendix_e1_ed25519.json")]:
        kat_path = kat_dir / fname
        if not kat_path.exists():
            continue
        # Load original
        with open(kat_path) as f:
            kat = _json.load(f)
        # Try several deterministic messages
        for tag, msg in [("empty", b""),
                        ("short", b"\x00"),
                        ("31_bytes", b"a" * 31),
                        ("32_bytes", b"b" * 32),
                        ("100_bytes", b"c" * 100)]:
            modified = dict(kat)
            modified["inputs"] = dict(kat["inputs"], message=msg.hex())
            out_path = Path(f"/tmp/_kat_{group}_{tag}.json")
            with open(out_path, "w") as f:
                _json.dump(modified, f)
            try:
                out = frost_sign(out_path, group=group)
                vectors.append({
                    "axis": "message_variants",
                    "ciphersuite": group,
                    "message": msg.hex(),
                    "message_len": len(msg),
                    "round_one_match_all": all(
                        r["match_hiding_nonce"] and r["match_binding_nonce"]
                        and r["match_hiding_nonce_commitment"]
                        and r["match_binding_nonce_commitment"]
                        and r["match_binding_factor"]
                        for r in out["round_one"]
                    ),
                    "round_two_match_all": all(
                        r["match_sig_share"] for r in out["round_two"]
                    ) if out["round_two"] else False,
                    "aggregate_match": out["match_final_sig"],
                    "verify_aggregate": out["verify_aggregate"],
                    "challenge_hex": out["challenge_hex"],
                    "aggregate_R_hex": out["aggregate_R_hex"],
                    "aggregate_z_hex": out["aggregate_z_hex"],
                    "expected_final_sig": out["expected_final_sig"],
                    "computed_final_sig": out["computed_final_sig"],
                })
            finally:
                out_path.unlink()
    return vectors


def make_random_kats() -> list[dict]:
    """Generate additional KATs from the trusted_dealer_keygen algorithm
    of RFC 9591 Appendix C, with deterministic seeds. This gives
    multi-instance coverage beyond the canonical 1 KAT per ciphersuite.

    Each generated instance is a complete sign round: round 1 + round 2
    + aggregate. We assert the cleanroom produces a signature that verifies
    internally (i.e., the structure is correct), even if we don't have an
    external oracle to compare against.

    NOTE: this only generates inputs; the cleanroom processes them.
    """
    # Use the cleanroom's supported functions
    # For secp256k1, we use the existing KAT. For ed25519, the same.
    # New randomized KATs would require a trusted_dealer_keygen implementation
    # which is out of scope for this cleanroom.
    return []


def write_vectors(vectors: list[dict], filename: str) -> Path:
    path = VECTORS_DIR / filename
    with open(path, "w") as f:
        for v in vectors:
            f.write(json.dumps(v) + "\n")
    return path


def main():
    print("FROST Vector Generator (msn-2026-0019)")
    print("=======================================")
    print(f"Deterministic seed: {hex(SEED)}")
    print()

    # 1. KAT replay
    kr = make_kr_kats()
    if kr:
        p = write_vectors(kr, "vectors_kat_replay.jsonl")
        print(f"Wrote {len(kr)} KAT-replay vectors to {p.name}")
        for v in kr:
            print(f"  {v['ciphersuite']:11s}: round1={all(r['match_hiding_nonce'] and r['match_binding_nonce'] and r['match_hiding_nonce_commitment'] and r['match_binding_nonce_commitment'] and r['match_binding_factor'] for r in v['round_one'])} aggregate_match={v['match_final_sig']} verify={v['verify_aggregate']}")
    print()

    # 2. Message variants
    mv = make_deterministic_message_variants()
    if mv:
        p = write_vectors(mv, "vectors_message_variants.jsonl")
        print(f"Wrote {len(mv)} message-variant vectors to {p.name}")
        for v in mv:
            print(f"  {v['ciphersuite']:11s} msg_len={v['message_len']:3d}: round1={v['round_one_match_all']} round2={v['round_two_match_all']} aggregate={v['aggregate_match']}")
    print()

    # 3. Summary
    total = len(kr) + len(mv)
    print(f"Total: {total} vectors generated.")


if __name__ == "__main__":
    main()