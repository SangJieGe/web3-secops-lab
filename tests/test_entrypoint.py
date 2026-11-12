"""Regression tests for the ``-m`` entry point and logger placement.

These exist because of a real bug: the JSON handler is attached to the
``web3_secops`` logger with ``propagate=False``, so a record emitted by a logger
*outside* that tree is silently dropped. Running ``python -m web3_secops.main``
sets ``__name__ == "__main__"``, which put every log line outside the tree — the
process exited 0 having printed nothing at all. For a collector that is the
worst failure mode: it looks like a clean run that found nothing.

The tests below run a **real subprocess**, because the bug only appears through
the interpreter's actual ``-m`` machinery; an in-process ``main()`` call does
not reproduce it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from web3_secops.logging_setup import configure_logging, get_logger, reset_logging

REPO_ROOT = Path(__file__).resolve().parents[1]
SEPOLIA_URL = "https://ethereum-sepolia-rpc.publicnode.com"


@pytest.fixture
def clean_logging():
    """Reset global logging state around a test that inspects handlers."""
    reset_logging()
    yield
    reset_logging()


# --------------------------------------------------------------------------- #
# Logger placement — the root cause, tested without a subprocess
# --------------------------------------------------------------------------- #


def test_get_logger_normalises_dunder_main(clean_logging, capsys) -> None:
    """A ``__main__`` logger must still reach the web3_secops handler."""
    configure_logging("INFO")
    get_logger("__main__").info("dunder_main_event", k=1)
    out = capsys.readouterr().out
    assert "dunder_main_event" in out, "records from __main__ were dropped"


def test_get_logger_normalises_bare_name(clean_logging, capsys) -> None:
    """A logger name outside the package tree must not vanish."""
    configure_logging("INFO")
    get_logger("loose_name").info("loose_event", k=2)
    out = capsys.readouterr().out
    assert "loose_event" in out


def test_get_logger_keeps_package_names(clean_logging, capsys) -> None:
    """Names already inside the tree keep their identity."""
    configure_logging("INFO")
    log = get_logger("web3_secops.block_scanner")
    assert log._logger.name == "web3_secops.block_scanner"
    log.info("kept_event")
    assert "kept_event" in capsys.readouterr().out


def test_handler_is_not_duplicated(clean_logging) -> None:
    """Calling configure_logging repeatedly must not stack our handlers."""
    import logging

    from web3_secops.logging_setup import _StdoutHandler

    configure_logging("INFO")
    configure_logging("DEBUG")
    configure_logging("WARNING")
    ours = [h for h in logging.getLogger("web3_secops").handlers if isinstance(h, _StdoutHandler)]
    assert len(ours) == 1, f"duplicate handlers: {ours}"


def test_repeated_calls_emit_exactly_once(clean_logging, capsys) -> None:
    """One record in, one line out — no double emission."""
    configure_logging("INFO")
    configure_logging("INFO")
    get_logger("web3_secops.x").info("once_event")
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1, f"expected 1 line, got {len(out)}: {out}"


# --------------------------------------------------------------------------- #
# Real subprocess runs
# --------------------------------------------------------------------------- #


def _run(module_args: list[str], env_extra: dict[str, str]) -> subprocess.CompletedProcess:
    """Run ``python -m <module_args>`` in a fresh interpreter."""
    env = dict(os.environ)
    env.update(env_extra)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", *module_args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=REPO_ROOT,
    )


def _assert_json_lines(stdout: str) -> list[dict]:
    """Every non-empty stdout line must be a standalone JSON object."""
    lines = [ln for ln in stdout.strip().splitlines() if ln.strip()]
    assert lines, "stdout was empty — nothing was logged"
    records = []
    for line in lines:
        obj = json.loads(line)  # raises if not valid JSON
        assert isinstance(obj, dict)
        assert {"timestamp", "level", "event"} <= set(obj), f"missing base keys: {obj}"
        records.append(obj)
    return records


@pytest.mark.parametrize("module", ["web3_secops.main", "web3_secops"])
def test_check_rpc_entry_point_prints_json(module: str) -> None:
    """Both ``python -m`` forms must emit parseable JSON Lines and exit 0.

    This is the regression guard for the silent-stdout bug. It tolerates a
    network failure (skips) but never tolerates silence: if the endpoint
    answers, the output must be valid JSON Lines on stdout and clean stderr.
    """
    result = _run(
        [module, "--check-rpc"],
        {
            "ETHEREUM_RPC_URL": SEPOLIA_URL,
            "EXPECTED_CHAIN_ID": "11155111",
            "STATE_DB_PATH": "/tmp/pytest-entry.db",
            "LOG_LEVEL": "INFO",
        },
    )
    if result.returncode == 3:
        pytest.skip(f"public endpoint unavailable: {result.stderr[:200]}")

    assert result.returncode == 0, f"exit={result.returncode} stderr={result.stderr}"
    records = _assert_json_lines(result.stdout)
    assert any(r["event"] == "rpc_check_ok" for r in records), records
    assert "Traceback" not in result.stderr, result.stderr
    # No duplicates: each event appears once per run.
    events = [r["event"] for r in records]
    assert len(events) == len(set(events)), f"duplicate events: {events}"


def test_help_works_offline_without_env() -> None:
    """``--help`` must not require configuration, in either entry form."""
    for module in ("web3_secops.main", "web3_secops"):
        result = _run([module, "--help"], {"ETHEREUM_RPC_URL": "", "EXPECTED_CHAIN_ID": ""})
        assert result.returncode == 0, result.stderr
        assert "--check-rpc" in result.stdout
        assert "--once" in result.stdout


def test_bare_invocation_does_not_loop() -> None:
    """No mode selected must print usage and exit, never block forever."""
    result = _run([], {"ETHEREUM_RPC_URL": SEPOLIA_URL, "EXPECTED_CHAIN_ID": "11155111"})
    assert result.returncode != 0, "a bare invocation should not succeed silently"
    assert "Traceback" not in result.stderr


def test_api_key_absent_from_subprocess_output() -> None:
    """A key in the URL must not appear in stdout or stderr of a real run."""
    secret = "TOTALLYSECRETKEY42"
    result = _run(
        ["web3_secops", "--check-rpc"],
        {
            "ETHEREUM_RPC_URL": f"https://eth-mainnet.g.alchemy.com/v2/{secret}",
            "EXPECTED_CHAIN_ID": "1",
            "STATE_DB_PATH": "/tmp/pytest-redact.db",
        },
    )
    combined = result.stdout + result.stderr
    assert secret not in combined, "API key leaked into process output"
    assert "<redacted>" in combined or result.returncode != 0
