import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ORACLE_DIR = ROOT / "utf8-cross-impl" / "oracle"
VECTORS = ROOT / "utf8-cross-impl" / "vectors" / "vectors.jsonl"
ADAPTERS = ROOT / "utf8-cross-impl" / "adapters"
IMPLS = {
    "rust": ADAPTERS / "rust_utf8.exe",
    "go": ADAPTERS / "go_utf8.exe",
    "simdutf": ADAPTERS / "simdutf_utf8.exe",
}


@pytest.fixture(scope="module")
def oracle():
    sys.path.insert(0, str(ORACLE_DIR))
    import utf8_oracle
    return utf8_oracle


def test_oracle_known_cases(oracle):
    assert oracle.is_valid_utf8(b"") is True
    assert oracle.is_valid_utf8(b"\x41") is True
    assert oracle.is_valid_utf8(b"\xc0\x80") is False  # overlong
    assert oracle.is_valid_utf8(b"\xed\xa0\x80") is False  # surrogate
    assert oracle.is_valid_utf8(b"\xf4\x90\x80\x80") is False  # above max
    assert oracle.is_valid_utf8(b"\xef\xbf\xbd") is True  # U+FFFD


def test_corpus_exists_and_consistent(oracle):
    assert VECTORS.exists()
    rows = [json.loads(line) for line in VECTORS.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) >= 100
    for r in rows:
        b = bytes.fromhex(r["bytes_hex"])
        assert r["expected"] == bool(oracle.is_valid_utf8(b)), r["id"]


def test_ufffd_positive_control():
    rows = [json.loads(line) for line in VECTORS.read_text(encoding="utf-8").splitlines() if line.strip()]
    ufffd = [r for r in rows if r["bytes_hex"] == "efbfbd"]
    assert ufffd and ufffd[0]["expected"] is True


def test_adapters_exist():
    for name, exe in IMPLS.items():
        assert exe.exists(), f"missing adapter {name}: {exe}"


def _run(exe, data):
    p = subprocess.run([str(exe)], input=data, capture_output=True, timeout=30)
    out = p.stdout.decode("utf-8", errors="replace").strip()
    return out


def test_matrix_agreement(oracle):
    rows = [json.loads(line) for line in VECTORS.read_text(encoding="utf-8").splitlines() if line.strip()]
    for r in rows:
        data = bytes.fromhex(r["bytes_hex"])
        exp = "VALID" if r["expected"] else "INVALID"
        res = [_run(exe, data) for exe in IMPLS.values()]
        assert all(x == exp for x in res), (r["id"], r["bytes_hex"], exp, res)
        assert len(set(res)) == 1
