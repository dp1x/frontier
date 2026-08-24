"""Deterministic ML-KEM encapsulation-key stimulus generator for msn-2026-0001.

Emits a JSON manifest of test vectors exercising FIPS 203 section 7.2:
valid controls, non-canonical segments (values >= q at several positions and
magnitudes), wrong-length keys, rho-tail mutations, cross-parameter-set
confusion keys, and C2SP Wycheproof ModulusOverflow passthrough vectors.

Deterministic: generated families use fixed seeds recorded in the manifest;
Wycheproof vectors carry their source tcId. Byte math follows FIPS 203
section 4.2.1 (little-endian 12-bit packing, decode reduces mod q = 3329).

Usage:
    python gen_vectors.py --wycheproof-dir <dir with mlkem_*_encaps_test.json>
                          --out stimuli.json [--valid-per-family 32]
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

Q = 3329
PARAMS = {"ML-KEM-512": 2, "ML-KEM-768": 3, "ML-KEM-1024": 4}


def bytes_to_bits(blob: bytes) -> list[int]:
    return [(byte >> i) & 1 for byte in blob for i in range(8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i : i + 8]):
            byte |= bit << j
        out.append(byte)
    return bytes(out)


def byte_decode_12(blob: bytes) -> list[int]:
    bits = bytes_to_bits(blob)
    return [
        sum(bit << j for j, bit in enumerate(bits[i : i + 12])) % Q
        for i in range(0, len(bits), 12)
    ]


def byte_encode_12(coeffs: list[int]) -> bytes:
    bits: list[int] = []
    for m in coeffs:
        bits.extend((m >> j) & 1 for j in range(12))
    return bits_to_bytes(bits)


def canonical_body(seed: int, k: int) -> bytes:
    rng = random.Random(seed)
    raw = bytes(rng.randrange(256) for _ in range(384 * k))
    return byte_encode_12(byte_decode_12(raw))


def corrupt_segment(body: bytes, coeff_index: int, value: int) -> bytes:
    coeffs = byte_decode_12(body)
    coeffs[coeff_index] = value % 4096
    return byte_encode_12(coeffs)


def ek_len(k: int) -> int:
    return 384 * k + 32


class Manifest:
    def __init__(self) -> None:
        self.vectors: list[dict] = []

    def add(self, family: str, params: str, ek: bytes, expect: str, source: str) -> None:
        self.vectors.append(
            {
                "family": family,
                "params": params,
                "ek_hex": ek.hex(),
                "expected_7_2": expect,  # pass | fail-modulus | fail-type
                "source": source,
            }
        )


def build_generated_families(man: Manifest, valid_per_family: int) -> None:
    for params, k in PARAMS.items():
        n_coeffs = 256 * k
        length = ek_len(k)
        # Valid controls: normalized body + random rho (rho unconstrained).
        for i in range(valid_per_family):
            seed = 20260824 + i + 1000 * k
            rng = random.Random(seed)
            ek = canonical_body(seed, k) + bytes(rng.randrange(256) for _ in range(32))
            assert len(ek) == length
            man.add("valid-control", params, ek, "pass", f"seed:{seed}")

        base_seed = 777000 + 1000 * k
        body = canonical_body(base_seed, k)
        positions = {
            "first": 0,
            "middle": n_coeffs // 2,
            "last": n_coeffs - 1,
        }
        # Non-canonical families: single planted segment >= q.
        for pos_name, idx in positions.items():
            for label, value in (("q3329", Q), ("v4000", 4000), ("max4095", 4095)):
                ek = corrupt_segment(body, idx, value) + b"\xAA" * 32
                man.add(
                    f"noncanon-{label}-{pos_name}",
                    params,
                    ek,
                    "fail-modulus",
                    f"seed:{base_seed}+coeff[{idx}]:={value}",
                )
        # Wrong-length families.
        man.add("len-minus-1", params, (body + b"\x01" * 32)[:-1], "fail-type", "derived:len-1")
        man.add("len-plus-1", params, body + b"\x01" * 33, "fail-type", "derived:len+1")
        # Rho-tail mutations on an accepted key (all must stay 'pass').
        full_valid = canonical_body(base_seed, k) + bytes(range(32))
        for tag, rho in (
            ("zero", b"\x00" * 32),
            ("ff", b"\xFF" * 32),
            ("prng-a", bytes(random.Random(42).randrange(256) for _ in range(32))),
            ("prng-b", bytes(random.Random(1337).randrange(256) for _ in range(32))),
        ):
            man.add(f"rho-{tag}", params, body + rho, "pass", "derived:rho-mutation")
        del full_valid
        # Cross-set confusion handled after all bodies exist.


def build_cross_set_confusion(man: Manifest) -> None:
    bodies = {k: canonical_body(555000 + 1000 * k, k) for k in PARAMS.values()}
    # A longer parameter-set key presented to a shorter context: type check must reject.
    man.add(
        "cross-set-1024-as-768",
        "ML-KEM-768",
        bodies[4] + b"\x07" * 32,
        "fail-type",
        "seed:555000+4000",
    )
    man.add(
        "cross-set-1024-as-512",
        "ML-KEM-512",
        bodies[4] + b"\x07" * 32,
        "fail-type",
        "seed:555000+4000",
    )
    man.add(
        "cross-set-768-as-512",
        "ML-KEM-512",
        bodies[3] + b"\x07" * 32,
        "fail-type",
        "seed:555000+3000",
    )


def build_congruent_plants(man: Manifest, valid_per_family: int) -> None:
    """Mission-novel family (hyp-2026-0007): plant c_i + q so the decoded
    coefficient is UNCHANGED - arithmetic behaves identically to the canonical
    key while raw bytes differ. Isolates shared-secret hash divergence from
    arithmetic divergence. Requires peer-side dk, so consumers must derive
    these from a real keypair; the manifest records the derivation recipe.
    """
    for params, k in PARAMS.items():
        n_coeffs = 256 * k
        for i in range(valid_per_family):
            seed = 909000 + 1000 * k + i
            body = canonical_body(seed, k)
            coeffs = byte_decode_12(body)
            # Plant at three spread positions where residue allows +q.
            planted_any = False
            for pos in (0, n_coeffs // 2, n_coeffs - 1):
                c = coeffs[pos]
                if c <= 4095 - Q:  # planted = c + q must stay < 4096
                    coeffs[pos] = c + Q
                    planted_any = True
            if not planted_any:
                continue
            ek = byte_encode_12(coeffs) + bytes(random.Random(seed).randrange(256) for _ in range(32))
            man.add(
                "congruent-plant",
                params,
                ek,
                "fail-modulus",
                f"seed:{seed}+plant(c+q)@0,mid,last",
            )


def load_wycheproof(man: Manifest, wy_dir: Path) -> int:
    count = 0
    for params, k in PARAMS.items():
        path = wy_dir / f"mlkem_{k*256}_encaps_test.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for group in data.get("testGroups", []):
            for case in group.get("tests", []):
                flags = case.get("flags", [])
                if "ModulusOverflow" not in flags:
                    continue
                ek = bytes.fromhex(case["ek"])
                expect = "pass" if case.get("result") == "valid" else "fail-modulus"
                man.add("wycheproof-modoverflow", params, ek, expect,
                        f"wycheproof:tcId{case['tcId']}")
                count += 1
    return count


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wycheproof-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--valid-per-family", type=int, default=32)
    args = ap.parse_args()

    man = Manifest()
    build_generated_families(man, args.valid_per_family)
    build_cross_set_confusion(man)
    build_congruent_plants(man, 8)
    wy_count = load_wycheproof(man, args.wycheproof_dir) if args.wycheproof_dir else 0

    doc = {
        "generator": "gen_vectors.py (msn-2026-0001)",
        "determinism": "fixed seeds inline per vector; no global RNG state",
        "q": Q,
        "counts": {},
        "vectors": man.vectors,
    }
    for v in man.vectors:
        key = (v["family"], v["params"])
        doc["counts"][f"{key[0]}|{key[1]}"] = doc["counts"].get(f"{key[0]}|{key[1]}", 0) + 1
    args.out.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"wrote {len(man.vectors)} vectors ({wy_count} wycheproof) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
