"""Tests for configuration loading and the CLI entry point (M1-C).

These tests prove that:
  * every documented env var is read and validated
  * a missing/malformed RPC URL fails with a clear error
  * the RPC URL is only required when the network is actually needed
  * the CLI requires an explicit mode (no implicit infinite loop)
  * chain-id mismatch fails loudly
  * JSON Lines log records carry the required fields
  * M1 never emits fake security alerts
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from tests.conftest import TEST_URL, FakeNode, make_chain
from web3_secops import main as cli
from web3_secops.config import ConfigError, load_settings

CHAIN_ID = 11155111


def _records(captured: str) -> list[dict]:
    """Parse JSON Lines output, ignoring any non-JSON lines."""
    out = []
    for line in captured.strip().splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


@pytest.fixture(autouse=True)
def _fresh_logging():
    """Re-install the JSON handler per test.

    ``configure_logging`` binds a StreamHandler to ``sys.stdout`` at first use.
    Under pytest that is the *capture* object of whichever test happened to run
    first, so later ``capsys`` reads see nothing. Resetting before and after
    each test makes the handler bind to the current capture buffer.
    """
    from web3_secops.logging_setup import reset_logging

    reset_logging()
    yield
    reset_logging()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def test_settings_loaded_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    monkeypatch.setenv("CONFIRMATIONS", "12")
    monkeypatch.setenv("START_BLOCK_LOOKBACK", "20")
    monkeypatch.setenv("BLOCK_BATCH_SIZE", "5")
    monkeypatch.setenv("POLL_INTERVAL_SECONDS", "12")
    monkeypatch.setenv("REORG_WINDOW", "64")
    monkeypatch.setenv("STATE_DB_PATH", "/tmp/x.db")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    s = load_settings(env_file=None)
    assert s.rpc_url == TEST_URL
    assert s.expected_chain_id == CHAIN_ID
    assert s.scanner.confirmations == 12
    assert s.scanner.start_block_lookback == 20
    assert s.scanner.block_batch_size == 5
    assert s.scanner.poll_interval_seconds == 12.0
    assert s.scanner.reorg_window == 64
    assert s.state_db_path == "/tmp/x.db"
    assert s.log_level == "DEBUG"


def test_missing_rpc_url_only_fails_when_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loading settings is lazy; require_rpc() is what demands a URL."""
    monkeypatch.delenv("ETHEREUM_RPC_URL", raising=False)
    monkeypatch.delenv("EXPECTED_CHAIN_ID", raising=False)
    s = load_settings(env_file=None)
    assert s.rpc_configured is False  # offline tooling still works

    with pytest.raises(ConfigError, match="ETHEREUM_RPC_URL"):
        s.require_rpc()


def test_require_rpc_returns_url_and_chain_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    url, chain_id = load_settings(env_file=None).require_rpc()
    assert url == TEST_URL
    assert chain_id == CHAIN_ID


def test_rpc_url_must_use_http_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", "ftp://rpc.example.com")
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    with pytest.raises(ConfigError, match="http"):
        load_settings(env_file=None)


def test_negative_confirmations_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    monkeypatch.setenv("CONFIRMATIONS", "-1")
    with pytest.raises(ConfigError, match="CONFIRMATIONS"):
        load_settings(env_file=None)


def test_invalid_log_level_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "CHATTY")
    with pytest.raises(ConfigError, match="LOG_LEVEL"):
        load_settings(env_file=None)


def test_http_rpc_allowed_but_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plain HTTP is permitted (local dev nodes) but must be surfaced."""
    monkeypatch.setenv("ETHEREUM_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    s = load_settings(env_file=None)
    assert s.rpc_url is not None
    assert s.rpc_url.startswith("http://")


def test_safe_rpc_url_redacts_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", "https://eth.example.com/v2/SUPERSECRETKEY")
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    s = load_settings(env_file=None)
    assert s.rpc_url is not None
    assert "SUPERSECRETKEY" in s.rpc_url
    assert "SUPERSECRETKEY" not in s.safe_rpc_url, "safe_rpc_url leaked the key"


# ---------------------------------------------------------------------------
# CLI behaviour
# ---------------------------------------------------------------------------
def test_cli_requires_a_mode() -> None:
    """Bare invocation must not start an infinite loop; argparse rejects it."""
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code != 0


def test_check_rpc_reports_chain_and_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    node = FakeNode(chain_id=CHAIN_ID, head=1234, blocks=make_chain(0, 1234))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        code = cli.main(["--check-rpc", "--env-file", ""])

    records = _records(capsys.readouterr().out)
    ok = next(r for r in records if r["event"] == "rpc_check_ok")
    assert code == 0
    assert ok["chain_id"] == CHAIN_ID
    assert ok["block_number"] == 1234
    assert ok["expected_chain_id"] == CHAIN_ID


def test_check_rpc_fails_on_chain_id_mismatch(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", "1")  # node reports 11155111
    node = FakeNode(chain_id=CHAIN_ID, head=10, blocks=make_chain(0, 10))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        code = cli.main(["--check-rpc", "--env-file", ""])

    records = _records(capsys.readouterr().out)
    assert code == cli.EXIT_CONFIG
    mismatch = next(r for r in records if r["event"] == "rpc_check_chain_mismatch")
    assert mismatch["chain_id"] == CHAIN_ID
    assert mismatch["expected_chain_id"] == 1


def test_once_mode_scans_and_exits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    monkeypatch.setenv("STATE_DB_PATH", str(tmp_path / "s.db"))
    monkeypatch.setenv("START_BLOCK", "10")
    monkeypatch.setenv("CONFIRMATIONS", "0")
    monkeypatch.setenv("BLOCK_BATCH_SIZE", "3")

    node = FakeNode(chain_id=CHAIN_ID, head=50, blocks=make_chain(0, 50))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        code = cli.main(["--once", "--env-file", ""])

    records = _records(capsys.readouterr().out)
    done = next(r for r in records if r["event"] == "scan_once_finished")
    assert code == 0
    assert done["blocks_scanned"] == 3
    assert done["first_block"] == 10
    assert done["block_number"] == 12
    # Required structured-log fields.
    for field in ("timestamp", "level", "event", "chain_id"):
        assert field in done, f"missing required log field {field}"


def test_once_mode_returns_nonzero_on_rpc_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    monkeypatch.setenv("STATE_DB_PATH", str(tmp_path / "s.db"))
    monkeypatch.setenv("START_BLOCK", "10")
    monkeypatch.setenv("CONFIRMATIONS", "0")

    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(return_value=httpx.Response(500))
        code = cli.main(["--once", "--env-file", ""])

    records = _records(capsys.readouterr().out)
    assert code == cli.EXIT_RPC
    assert any(r["event"] == "rpc_error" for r in records)


def test_offline_run_without_rpc_url_does_not_loop(
    monkeypatch: pytest.MonkeyPatch, capsys, tmp_path: Path
) -> None:
    """--once without a URL must exit with a config error, not hang.

    The env vars are cleared explicitly: another test in the session may have
    set them, and a leaked ETHEREUM_RPC_URL would make this pass for the wrong
    reason (it would attempt a real scan instead of failing fast).
    """
    monkeypatch.delenv("ETHEREUM_RPC_URL", raising=False)
    monkeypatch.delenv("EXPECTED_CHAIN_ID", raising=False)
    code = cli.main(["--once", "--env-file", str(tmp_path / "absent.env")])
    assert code == cli.EXIT_CONFIG, f"expected config error, got {code}"
    assert code != 0
    records = _records(capsys.readouterr().out)
    assert any(r["event"] == "config_error" for r in records), records


def test_no_fake_security_alerts_are_emitted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    """M1 collects data only. It must never claim to have detected an attack."""
    monkeypatch.setenv("ETHEREUM_RPC_URL", TEST_URL)
    monkeypatch.setenv("EXPECTED_CHAIN_ID", str(CHAIN_ID))
    monkeypatch.setenv("STATE_DB_PATH", str(tmp_path / "s.db"))
    monkeypatch.setenv("START_BLOCK", "10")
    monkeypatch.setenv("CONFIRMATIONS", "0")
    monkeypatch.setenv("BLOCK_BATCH_SIZE", "5")

    node = FakeNode(chain_id=CHAIN_ID, head=50, blocks=make_chain(0, 50))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        cli.main(["--once", "--env-file", ""])

    records = _records(capsys.readouterr().out)
    # Only inspect the event names — the raw text also contains the temp DB path,
    # which includes this test's own name.
    events = " ".join(r["event"].lower() for r in records)
    for forbidden in ("alert", "attack", "exploit", "suspicious", "threat"):
        assert forbidden not in events, f"M1 must not emit {forbidden!r} events"
