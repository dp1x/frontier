"""Untrusted experiment execution with env scrubbing."""

from pathlib import Path

from frontier.execute import run_command, scrub_env


def test_scrub_env_drops_tokens_and_keys():
    dirty = {
        "PATH": "/usr/bin",
        "GITHUB_TOKEN": "secret",
        "OPENAI_API_KEY": "sk-x",
        "AWS_SECRET_ACCESS_KEY": "x",
        "SSH_AUTH_SOCK": "/tmp/ssh",
        "HARMLESS": "ok",
        "XAI_API_KEY": "x",
    }
    clean = scrub_env(dirty)
    assert "GITHUB_TOKEN" not in clean
    assert "OPENAI_API_KEY" not in clean
    assert "AWS_SECRET_ACCESS_KEY" not in clean
    assert "SSH_AUTH_SOCK" not in clean
    assert "XAI_API_KEY" not in clean
    assert clean["HARMLESS"] == "ok"
    assert "PATH" in clean


def test_run_command_captures_output_in_scratch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("LEAK_TOKEN", "should-not-appear")
    result = run_command(
        ["python", "-c", "import os,sys; sys.stdout.write(os.environ.get('LEAK_TOKEN','ABSENT'))"],
        cwd=tmp_path,
        timeout_s=15,
    )
    assert result.exit_code == 0
    assert result.stdout == "ABSENT"
    assert result.isolation == "env-scrubbed-scratch"
    assert result.cwd == str(tmp_path.resolve())


def test_run_command_timeout(tmp_path: Path):
    result = run_command(
        ["python", "-c", "import time; time.sleep(30)"],
        cwd=tmp_path,
        timeout_s=1,
    )
    assert result.timed_out is True
    assert result.exit_code != 0


def test_run_command_rejects_shell_strings(tmp_path: Path):
    try:
        run_command("echo pwned", cwd=tmp_path, timeout_s=5)  # type: ignore[arg-type]
        raised = False
    except (TypeError, ValueError):
        raised = True
    assert raised
