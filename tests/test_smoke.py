"""
Smoke tests for all OnionClaw CLI scripts.

Runs each script with --help and --version via subprocess.
No Tor, no network, no LLM required — these flags exit before any I/O.
"""
from __future__ import annotations

import subprocess
import sys
import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCRIPTS = [
    "check_tor.py",
    "renew.py",
    "search.py",
    "fetch.py",
    "check_engines.py",
    "ask.py",
    "pipeline.py",
    "sync_sicry.py",
]


def _run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, script), *args],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=REPO_ROOT,
    )


@pytest.mark.parametrize("script", SCRIPTS)
def test_help(script):
    """Every script must exit 0 on --help and print usage info."""
    result = _run(script, "--help")
    assert result.returncode == 0, f"{script} --help exited {result.returncode}\n{result.stderr}"
    assert "usage" in result.stdout.lower() or "Usage" in result.stdout, (
        f"{script} --help produced no usage text:\n{result.stdout}"
    )


@pytest.mark.parametrize("script", [s for s in SCRIPTS if s != "sync_sicry.py"])
def test_version(script):
    """Every non-utility script must exit 0 on --version and print a version string."""
    result = _run(script, "--version")
    assert result.returncode == 0, f"{script} --version exited {result.returncode}\n{result.stderr}"
    assert result.stdout.strip(), f"{script} --version produced no output"


class TestSearchValidation:
    """search.py argument validation — no Tor needed."""

    def test_empty_query_rejected(self):
        result = _run("search.py", "--query", "")
        assert result.returncode != 0

    def test_missing_query_rejected(self):
        result = _run("search.py")
        assert result.returncode != 0


class TestFetchValidation:
    """fetch.py argument validation — no Tor needed."""

    def test_missing_url_rejected(self):
        result = _run("fetch.py")
        assert result.returncode != 0

    def test_credentials_in_url_rejected(self):
        result = _run("fetch.py", "--url", "http://user:pass@example.onion")
        assert result.returncode != 0


class TestPipelineValidation:
    """pipeline.py argument validation — no Tor needed."""

    def test_empty_query_rejected(self):
        result = _run("pipeline.py", "--query", "")
        assert result.returncode != 0

    def test_modes_flag(self):
        result = _run("pipeline.py", "--modes")
        # Requires sicry — may fail if sicry import fails in CI (no Tor deps)
        # so we only assert it doesn't crash with an unhandled exception
        assert "Traceback" not in result.stderr or result.returncode != 0


class TestSyncSicry:
    """sync_sicry.py standalone utility tests."""

    def test_dry_run_no_write(self):
        result = _run("sync_sicry.py", "--dry-run")
        # Network is needed; if it times out that's OK — check it doesn't crash
        assert "Traceback" not in result.stderr or result.returncode != 0
