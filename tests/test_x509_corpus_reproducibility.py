"""Reproducibility of the X.509 pathLen corpus: what is true, and what is not.

``chainforge``'s docstring used to claim RFC 6979 deterministic nonces made the
corpus byte-reproducible.  They do not: ``builder.sign`` on an EC key draws a
fresh random ECDSA nonce, so two runs over the same seed differ in every
certificate.  Measured: 0 of 45 byte-identical.

What the experiments actually rely on is weaker and sufficient -- the chain
STRUCTURE is fixed by construction, so the verdicts do not move.  Both halves
are asserted here, because asserting only the stable half would leave the false
claim free to return, and asserting only the unstable half would suggest the
experiment is broken.  See ``knowledge/observations/obs-2026-0057.yaml``.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def _generate(repo: Path, out: Path) -> dict[str, str]:
    proc = subprocess.run(
        [sys.executable, str(repo / "crypto" / "x509-pathlen" / "gen_corpus.py"),
         "--out", str(out)],
        capture_output=True, text=True, cwd=repo,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    return {
        str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(out.rglob("*.der"))
    }


def _verdicts(repo: Path, out: Path) -> list[str]:
    proc = subprocess.run(
        [sys.executable,
         str(repo / "crypto" / "x509-pathlen" / "adapter_certvalidator.py"),
         str(out)],
        capture_output=True, text=True, cwd=repo,
    )
    # Guard against the vacuous comparison: two runs that BOTH failed are not
    # two runs that agreed. This exact mistake was made while building this test.
    assert proc.returncode == 0, (
        f"adapter failed; comparing two failures is not agreement: "
        f"{proc.stderr[-400:]}"
    )
    return proc.stdout.splitlines()


def test_der_is_not_byte_reproducible_but_verdicts_are():
    # The ``repo_root`` fixture is a synthetic mini-repo; this test needs the
    # real generator and adapter, so it resolves them from the test file.
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        first = _generate(repo, tmp / "a")
        second = _generate(repo, tmp / "b")

        assert first, "generator produced no certificates"
        assert first != second, (
            "the DER came out byte-identical across runs; the ECDSA nonce is "
            "supposed to be random. If signing has become deterministic, the "
            "nondeterminism_policy in exp-2026-0037 needs rewriting again."
        )

        verdicts_a = _verdicts(repo, tmp / "a")
        verdicts_b = _verdicts(repo, tmp / "b")

    assert verdicts_a == verdicts_b, (
        "verdicts moved between regenerations of the same seed, so the "
        "recorded matrix is a property of one byte generation rather than of "
        "the chain structure"
    )
    assert any("c17_anchor_constrained" in line for line in verdicts_a), (
        "the load-bearing cell is absent from the adapter output"
    )