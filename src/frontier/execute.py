"""Execution of untrusted commands inside isolated scratch workspaces.

Generated code and cloned targets never see credentials: the child environment
is deny-list scrubbed before spawn (tokens, API keys, cloud/SSH/browser session
material). Commands must be passed as argument vectors — never shell strings.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

ISOLATION = "env-scrubbed-scratch"

_DENY_SUBSTRINGS = (
    "token",
    "secret",
    "password",
    "credential",
    "api_key",
    "apikey",
    "keytab",
    "passfile",
)
_DENY_PREFIXES = (
    "aws_",
    "azure_",
    "gcp_",
    "google_",
    "ssh_",
    "vault_",
    "pgpass",
)


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    isolation: str
    cwd: str


def scrub_env(env: dict[str, str]) -> dict[str, str]:
    """Return ``env`` minus credential-bearing variables."""
    clean: dict[str, str] = {}
    for name, value in env.items():
        lowered = name.lower()
        if lowered.startswith(_DENY_PREFIXES):
            continue
        if any(marker in lowered for marker in _DENY_SUBSTRINGS):
            continue
        clean[name] = value
    return clean


def run_command(argv: list[str], cwd: Path, timeout_s: int) -> RunResult:
    """Run ``argv`` in ``cwd`` with a scrubbed environment and timeout."""
    if isinstance(argv, str):
        raise TypeError("argv must be a sequence of arguments, never a shell string")
    arg_list = [str(arg) for arg in argv]
    workdir = Path(cwd)
    env = scrub_env(dict(os.environ))
    try:
        completed = subprocess.run(  # noqa: S603 - argv is explicit, shell=False
            arg_list,
            cwd=str(workdir),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        return RunResult(
            exit_code=124,
            stdout=stdout,
            stderr=f"timed out after {timeout_s}s",
            timed_out=True,
            isolation=ISOLATION,
            cwd=str(workdir.resolve()),
        )
    return RunResult(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        isolation=ISOLATION,
        cwd=str(workdir.resolve()),
    )
