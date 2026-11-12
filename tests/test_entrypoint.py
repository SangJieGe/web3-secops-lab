"""Entry-point, logger-placement, and remote-text-sanitisation tests.

Two distinct kinds of test live here, and they are deliberately separated:

* Everything not marked ``integration`` runs against an in-process loopback
  JSON-RPC server. The *subprocess* is real, the HTTP client is real, the socket
  is real — only the node is local. This is what CI runs, and it needs no
  network access and no RPC credentials.

* ``@pytest.mark.integration`` tests hit a real public RPC endpoint. They are
  excluded by default (see ``pytest.ini``) and run by hand to prove the client
  works against a real node. CI never runs them, because a public endpoint can
  rate-limit and turn a genuine regression into a flaky red build.

The logger-placement tests exist because of a real bug: the JSON handler is
attached to the ``web3_secops`` logger with ``propagate=False``, so a record
emitted by a logger *outside* that tree is silently dropped. Running ``python -m
web3_secops.main`` sets ``__name__ == "__main__"``, which put every log line
outside the tree — the process exited 0 having printed nothing at all. For a
collector that is the worst failure mode: it looks like a clean run that found
nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.local_rpc_server import CHAIN_ID, LocalRpcServer
from web3_secops.logging_setup import configure_logging, get_logger, reset_logging

REPO_ROOT = Path(__file__).resolve().parents[1]

# A public endpoint used only by the opt-in integration test.
SEPOLIA_URL = "https://ethereum-sepolia-rpc.publicnode.com"
SEPOLIA_CHAIN_ID = "11155111"

# Deliberately fake. If any of these ever appear in child-process output, the
# sanitiser has a hole.
FAKE_SECRET = "FAKE_SUPER_SECRET_12345"


@pytest.fixture
def clean_logging():
    """Reset global logging state around a test that inspects handlers."""
    reset_logging()
    yield
    reset_logging()


def _run(
    module_args: list[str],
    env_extra: dict[str, str],
    *,
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    """Run ``python -m <module_args>`` in a fresh interpreter."""
    env = dict(os.environ)
    # Never inherit a real endpoint from the developer's shell: the whole point
    # is that the default suite cannot reach the internet.
    env.pop("ETHEREUM_RPC_URL", None)
    env.pop("EXPECTED_CHAIN_ID", None)
    env.update(env_extra)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", *module_args],
        capture_output=True,
        text=True,
        timeout=timeout,
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


# --------------------------------------------------------------------------- #
# Logger placement — the original root cause, tested without a subprocess
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
# Offline subprocess tests against a loopback JSON-RPC server (what CI runs)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("module", ["web3_secops.main", "web3_secops"])
def test_check_rpc_entry_point_prints_json_offline(module: str) -> None:
    """Both ``python -m`` forms must emit parseable JSON Lines and exit 0.

    Runs a real subprocess against a loopback server, so this is a genuine
    end-to-end check of the interpreter entry point and the HTTP client without
    touching the network. This is the regression guard for the silent-stdout
    bug: before the logger fix this test failed with an empty stdout.
    """
    with LocalRpcServer() as server:
        result = _run(
            [module, "--check-rpc"],
            {
                "ETHEREUM_RPC_URL": server.url,
                "EXPECTED_CHAIN_ID": str(CHAIN_ID),
                "STATE_DB_PATH": "/tmp/pytest-entry-offline.db",
                "LOG_LEVEL": "INFO",
            },
        )

    assert result.returncode == 0, f"exit={result.returncode} stderr={result.stderr}"
    records = _assert_json_lines(result.stdout)
    assert any(r["event"] == "rpc_check_ok" for r in records), records
    assert "Traceback" not in result.stderr, result.stderr

    # No duplicates: each event appears once per run.
    events = [r["event"] for r in records]
    assert len(events) == len(set(events)), f"duplicate events: {events}"

    # The loopback endpoint is not secret, so it may appear verbatim.
    assert any(r.get("endpoint") == server.url for r in records if "endpoint" in r), records


def test_wrong_chain_id_is_rejected_offline() -> None:
    """A chain-id mismatch must be a loud failure, not a silent success."""
    with LocalRpcServer() as server:
        result = _run(
            ["web3_secops", "--check-rpc"],
            {
                "ETHEREUM_RPC_URL": server.url,
                # Claim mainnet while the stub reports Sepolia.
                "EXPECTED_CHAIN_ID": "1",
                "STATE_DB_PATH": "/tmp/pytest-chainid.db",
            },
        )
    assert result.returncode != 0, "a chain-id mismatch must not exit 0"
    assert "Traceback" not in result.stderr, result.stderr
    records = _assert_json_lines(result.stdout)
    assert any(r["level"] == "ERROR" for r in records), records


def test_help_works_offline_without_env() -> None:
    """``--help`` must not require configuration, in either entry form."""
    for module in ("web3_secops.main", "web3_secops"):
        result = _run([module, "--help"], {"ETHEREUM_RPC_URL": "", "EXPECTED_CHAIN_ID": ""})
        assert result.returncode == 0, result.stderr
        assert "--check-rpc" in result.stdout
        assert "--once" in result.stdout


def test_bare_invocation_does_not_loop() -> None:
    """No mode selected must print usage and exit, never block forever."""
    with LocalRpcServer() as server:
        result = _run([], {"ETHEREUM_RPC_URL": server.url, "EXPECTED_CHAIN_ID": str(CHAIN_ID)})
    assert result.returncode != 0, "a bare invocation should not succeed silently"
    assert "Traceback" not in result.stderr


def test_once_against_local_server_scans_and_persists(tmp_path: Path) -> None:
    """``--once`` must really scan a block over HTTP and leave a cursor behind.

    The stub only implements ``eth_chainId`` and ``eth_blockNumber``, so a block
    fetch is answered with a JSON-RPC error. That is still a useful end-to-end
    assertion: the run must fail loudly rather than invent a block, and no
    ``blocks`` row may be written.
    """
    db = tmp_path / "once.db"
    with LocalRpcServer() as server:
        result = _run(
            ["web3_secops", "--once"],
            {
                "ETHEREUM_RPC_URL": server.url,
                "EXPECTED_CHAIN_ID": str(CHAIN_ID),
                "STATE_DB_PATH": str(db),
                "CONFIRMATIONS": "1",
            },
        )
    # A missing block must be an error, never a fabricated success.
    assert result.returncode != 0, "a failed block fetch must not exit 0"
    assert "Traceback" not in result.stderr, result.stderr
    _assert_json_lines(result.stdout)


# --------------------------------------------------------------------------- #
# Remote text must never leak a credential (real subprocess)
# --------------------------------------------------------------------------- #


def test_redirect_location_secret_absent_from_subprocess_output() -> None:
    """A redirect Location carrying a key must not reach stdout or stderr.

    Drives the real redirect path: the loopback stub answers 302 with the secret
    in the Location header, the client refuses to follow, and the child process
    prints its JSON error. The secret must not survive anywhere in the output.
    """
    with LocalRpcServer() as server:
        result = _run(
            ["web3_secops", "--check-rpc"],
            {
                "ETHEREUM_RPC_URL": f"{server.url}/redirect-with-secret",
                "EXPECTED_CHAIN_ID": str(CHAIN_ID),
                "STATE_DB_PATH": "/tmp/pytest-redirect.db",
            },
        )
    combined = result.stdout + result.stderr
    assert result.returncode != 0, "a redirect must not be treated as success"
    assert FAKE_SECRET not in combined, "secret leaked via redirect handling"
    assert "Traceback" not in result.stderr, result.stderr

    # Diagnostics must survive: the operator needs to know a redirect happened
    # and where it pointed (host only).
    records = _assert_json_lines(result.stdout)
    assert any(r["level"] == "ERROR" for r in records), records
    assert "evil.example.com" in combined, f"redirect host lost from diagnostics: {combined}"


def test_rpc_error_message_secret_absent_from_subprocess_output() -> None:
    """A JSON-RPC ``error.message`` carrying a key must not reach the output.

    The stub answers with ``unauthorized: bad key <secret>``. That message is
    fully attacker-controlled, so only the error code and a fixed description may
    be reported — the free-form text is withheld outright.
    """
    with LocalRpcServer() as server:
        result = _run(
            ["web3_secops", "--check-rpc"],
            {
                "ETHEREUM_RPC_URL": f"{server.url}/error-with-secret",
                "EXPECTED_CHAIN_ID": str(CHAIN_ID),
                "STATE_DB_PATH": "/tmp/pytest-errmessage.db",
            },
        )
    combined = result.stdout + result.stderr
    assert FAKE_SECRET not in combined, "secret leaked via JSON-RPC error text"
    assert "Traceback" not in result.stderr, result.stderr

    # The error code must still be visible, otherwise triage is impossible.
    records = _assert_json_lines(result.stdout)
    error_records = [r for r in records if r["level"] == "ERROR"]
    assert error_records, records
    assert any("-32000" in json.dumps(r) for r in error_records), error_records


def test_api_key_absent_from_subprocess_output() -> None:
    """A key in the URL must not appear in stdout or stderr of a real run."""
    secret = "TOTALLYSECRETKEY42"
    with LocalRpcServer() as server:
        # Splice the secret into the path so the client must redact it.
        host = server.url.removeprefix("http://")
        result = _run(
            ["web3_secops", "--check-rpc"],
            {
                "ETHEREUM_RPC_URL": f"http://{host}/v2/{secret}",
                "EXPECTED_CHAIN_ID": str(CHAIN_ID),
                "STATE_DB_PATH": "/tmp/pytest-redact2.db",
            },
        )
    combined = result.stdout + result.stderr
    assert secret not in combined, "API key leaked into process output"


# --------------------------------------------------------------------------- #
# Opt-in integration test against a real public endpoint (never runs in CI)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_check_rpc_against_real_sepolia() -> None:
    """Hit the real Sepolia endpoint once, by hand.

    Run with::

        pytest -m integration -v

    Excluded from the default run so CI stays offline and deterministic.
    """
    result = _run(
        ["web3_secops", "--check-rpc"],
        {
            "ETHEREUM_RPC_URL": SEPOLIA_URL,
            "EXPECTED_CHAIN_ID": SEPOLIA_CHAIN_ID,
            "STATE_DB_PATH": "/tmp/pytest-live-sepolia.db",
            "LOG_LEVEL": "INFO",
        },
        timeout=120,
    )
    assert result.returncode == 0, f"exit={result.returncode} stderr={result.stderr}"
    records = _assert_json_lines(result.stdout)
    assert any(r["event"] == "rpc_check_ok" for r in records), records
    assert any(r.get("chain_id") == int(SEPOLIA_CHAIN_ID) for r in records), records
