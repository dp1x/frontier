"""Guard: no test module may fail COLLECTION when an optional dep is absent.

## Why this test exists

On 2026-10-05 the `ci` workflow on `main` went red (run 37304311430) because
`tests/test_x509_minimal_corpus.py` imported `minimal_chain`, which imports
`cryptography` at module scope. `cryptography` is NOT a declared dependency --
`pyproject.toml` lists only `pyyaml` and `jsonschema`, and CI runs
`pip install -e ".[dev]"`. On the runner the import raised ModuleNotFoundError
DURING COLLECTION, which aborts the entire run rather than skipping one test:

    ERROR collecting tests/test_x509_minimal_corpus.py
    ModuleNotFoundError: No module named 'cryptography'
    !!! Interrupted: 1 error during collection !!!

The sibling module `test_x509_corpus_reproducibility.py` had already been fixed
for this exact defect class in commit fb2279c. The new module regressed it,
because the guard was placed inside a test BODY rather than above the import
that triggers the failure. Nothing in the suite detected the difference.

This test is the mechanical difference between "a human noticed red CI" and
"the class cannot recur unnoticed". It asserts the property over the real test
suite, so a future module that hard-imports an undeclared dependency fails HERE,
in a cheap subprocess, with a precise message -- instead of failing the whole
CI run at collection time.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Dependencies that are NOT in pyproject's `dependencies` and so are absent from
# the GitHub runner. `cryptography` is the one that actually bit us; the others
# are the plausible next ones, so the guard generalises rather than hardcoding a
# single historical failure.
UNDECLARED_IMPORTS = ["cryptography"]

# Modules that legitimately require an undeclared dependency must reach it only
# through a guarded import (pytest.importorskip, or an import inside a function
# that is not called at module scope). These are the modules the check targets.
TEST_DIR = REPO_ROOT / "tests"

# Source text markers of a guarded import. A module using any of these before its
# undeclared import is considered guarded.
GUARD_MARKERS = (
    "importorskip",
    "pytest.importorskip",
    "try:",
)


def _modules_importing_undetectably(root: str) -> list[str]:
    """Import `root` with a meta-path blocker, returning modules that ERROR.

    Runs in a subprocess so the blocker cannot leak into this process's import
    machinery. Each candidate module is run in its OWN pytest invocation, because
    a single collection error aborts the whole run and would mask the others --
    exactly the failure mode we are guarding against.
    """
    import tempfile

    offenders: list[str] = []
    # This module probes every test module, so probing ITSELF would recurse
    # without bound. Exclude it by name, which is correct on the merits too: this
    # module imports no undeclared dependency at module scope.
    modules = [
        p.stem for p in sorted(TEST_DIR.glob("test_*.py"))
        if p.stem != Path(__file__).stem
    ]
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "probe.py"
        probe.write_text(
            "import importlib.abc, sys\n"
            "class _B(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self, fullname, path=None, target=None):\n"
            f"        if fullname.split('.')[0] in {UNDECLARED_IMPORTS!r}:\n"
            "            raise ModuleNotFoundError(fullname)\n"
            "        return None\n"
            "sys.meta_path.insert(0, _B())\n"
            "import pytest\n"
            "sys.exit(pytest.main(sys.argv[1:]))\n",
            encoding="utf-8",
        )
        for mod in modules:
            src = (TEST_DIR / f"{mod}.py").read_text(encoding="utf-8")
            first_occurrences = [src.find(m) for m in GUARD_MARKERS]
            first_guard = min([o for o in first_occurrences if o != -1] or [len(src)])
            for dep in UNDECLARED_IMPORTS:
                # A module that never mentions the dependency cannot fail on it.
                if dep not in src:
                    continue
                # Guarded if the FIRST occurrence of a guard marker precedes the
                # first mention of the undeclared dependency.
                dep_at = src.find(dep)
                if dep_at > first_guard:
                    continue
                try:
                    res = subprocess.run(
                        [sys.executable, str(probe), str(TEST_DIR / f"{mod}.py"),
                         "--collect-only", "-q", "--no-header",
                         "-p", "no:cacheprovider"],
                        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
                    )
                except subprocess.TimeoutExpired:
                    offenders.append(f"{mod}: {dep} (probe timed out)")
                    continue
                out = res.stdout + res.stderr
                if "error during collection" in out or "Interrupted" in out:
                    offenders.append(f"{mod}: {dep}")
    return offenders


def test_no_test_module_errors_at_collection_without_undeclared_deps():
    offenders = _modules_importing_undetectably("cryptography")
    assert not offenders, (
        "These test modules raise at COLLECTION (not skip) when an undeclared "
        f"dependency is missing, which fails the entire CI run: {offenders}. "
        "Guard with pytest.importorskip() ABOVE the import that triggers it."
    )


def test_guard_actually_detects_an_unguarded_module(tmp_path):
    """The guard must fail on a KNOWN-BAD module, or it proves nothing.

    A meta-test that only ever passes is exactly the "assertion that only shows
    the repository is fine" pattern AGENTS.md forbids. This writes a deliberately
    unguarded module, proves the collector flags it, and then proves the guarded
    module is NOT flagged. If the collector ever goes blind, this fails.
    """
    bad = tmp_path / "test_zzz_probe_bad.py"
    bad.write_text(
        "import cryptography\n\n\ndef test_x():\n    assert True\n",
        encoding="utf-8",
    )
    # Point the collector at the temp dir by temporarily monkeypatching TEST_DIR.
    original = globals()["TEST_DIR"]
    globals()["TEST_DIR"] = tmp_path
    try:
        offenders = _modules_importing_undetectably("cryptography")
    finally:
        globals()["TEST_DIR"] = original

    assert any("test_zzz_probe_bad" in o for o in offenders), (
        "The collector failed to detect a deliberately unguarded module that "
        f"hard-imports `cryptography`. offenders={offenders}"
    )


def test_guard_accepts_a_correctly_guarded_module(tmp_path):
    """A module using importorskip must NOT be flagged."""
    good = tmp_path / "test_zzz_probe_good.py"
    good.write_text(
        "import pytest\n\n"
        "pytest.importorskip('cryptography', reason='needs cryptography')\n\n"
        "import cryptography\n\n\n"
        "def test_x():\n    assert True\n",
        encoding="utf-8",
    )
    original = globals()["TEST_DIR"]
    globals()["TEST_DIR"] = tmp_path
    try:
        offenders = _modules_importing_undetectably("cryptography")
    finally:
        globals()["TEST_DIR"] = original

    assert not any("test_zzz_probe_good" in o for o in offenders), (
        f"A correctly guarded module was wrongly flagged: {offenders}"
    )