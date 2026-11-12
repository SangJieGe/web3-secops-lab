# Web3 SecOps Lab

A read-only on-chain security operations lab: collect Ethereum data safely, store
it durably, and build toward SIEM-based detection.

**Status: M1 complete.** M1 is the data-collection layer only. See
[Scope and honesty](#scope-and-honesty) before assuming anything else works.

---

## What this is

A platform for **Web3 security monitoring and incident response**, built in
stages so each stage is independently runnable and verifiable.

```
Ethereum / EVM  →  RPC Collector  →  Block Scanner  →  Event Decoder
                                                      →  Detection Engine
                                                      →  SIEM (Wazuh)
                                                      →  Alerting & IR
                └────────── M1 (done) ──────────┘  └──── M2+ (not built) ────┘
```

| Stage | Component | Status |
| --- | --- | --- |
| M1-A | Read-only JSON-RPC client, allowlisted methods | **Implemented** |
| M1-B | Reorg-aware block scanner with SQLite cursor | **Implemented** |
| M1-C | CLI (`--check-rpc` / `--once` / `--watch`), config, JSON Lines logs | **Implemented** |
| M2 | Event decoder (ERC-20 / ERC-721 transfers, approvals) | Not started |
| M3 | Detection engine + Wazuh integration + alerting | Not started |

## Scope and honesty

M1 **collects** blocks. It does **not**:

- detect attacks, exploits or suspicious activity
- decode ERC-20 / ERC-721 events
- ship data to Wazuh or emit any alert
- sign, broadcast, or custody anything

If a future README claims otherwise, that claim is wrong. Everything in this
repository is a read-only collector plus its tests.

## Quick start

```bash
git clone https://github.com/SangJieGe/web3-secops-lab.git
cd web3-secops-lab
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env
# edit .env: set ETHEREUM_RPC_URL and EXPECTED_CHAIN_ID
```

Three modes, all read-only:

```bash
# 1. Verify connectivity, chain id, and current head. Writes nothing.
python -m web3_secops --check-rpc

# 2. Scan one batch of confirmed blocks, then exit.
python -m web3_secops --once

# 3. Scan continuously.
python -m web3_secops --watch
```

`python -m web3_secops.main <mode>` is equivalent and remains supported; both
forms are covered by tests that run a real subprocess, because a documented
command that silently prints nothing is worse than no command.

A bare invocation (no mode flag) prints usage and exits. It never starts an
infinite loop implicitly.

## Safety properties (M1)

These are enforced in code and covered by tests, not just documented:

- **Method allowlist, not a prefix check.** Only `eth_chainId`,
  `eth_blockNumber`, `eth_getBlockByNumber` can leave the process. A naive
  `method.startswith("eth_")` check would happily forward
  `eth_sendRawTransaction`; this project rejects unknown methods *before* HTTP is
  attempted, and the tests assert that no request was emitted.
- **No key material in logs.** The RPC URL is redacted (`/v2/<KEY>`,
  `?apikey=<KEY>` and similar) before it reaches any log record or the database.
- **No signing, ever.** There is no private key handling, no transaction
  construction, and no broadcast path in the codebase.
- **Bounded retries.** Exponential backoff with jitter and a hard attempt cap.
  Redirects are never followed — a 3xx is a failure, so a re-signed request
  cannot be replayed to an attacker-controlled host.
- **Integer money.** Wei values stay Python `int`. Floats never touch balances.
- **Durable cursor.** Block progress is committed in the same SQLite
  transaction as the block itself, so a crash cannot skip or double-count.
- **Reorg handling that fails loudly.** A fork is detected by `parentHash`
  mismatch, rolled back to the common ancestor inside `REORG_WINDOW`, and
  rescanned. A fork deeper than the window raises instead of guessing.

Full details: [docs/security-assessment.md](docs/security-assessment.md).

## Configuration

All configuration is environment-driven; see [`.env.example`](.env.example).

| Variable | Default | Meaning |
| --- | --- | --- |
| `ETHEREUM_RPC_URL` | — | Endpoint. **Required** for any networked mode |
| `EXPECTED_CHAIN_ID` | — | Chain id the node must report. **Required** for networked modes |
| `CONFIRMATIONS` | `12` | Blocks behind head treated as final |
| `START_BLOCK_LOOKBACK` | `20` | Blocks to look back on a fresh start |
| `START_BLOCK` | unset | Explicit start block; overrides lookback |
| `BLOCK_BATCH_SIZE` | `5` | Blocks per `--once` / per watch iteration |
| `POLL_INTERVAL_SECONDS` | `12` | Watch-mode sleep between batches |
| `REORG_WINDOW` | `64` | Max rollback depth before hard failure |
| `STATE_DB_PATH` | `./data/state.db` | SQLite cursor + block store |
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |
| `RPC_TIMEOUT_SECONDS` | `20` | Per-request timeout |
| `RPC_MAX_RETRIES` | `3` | Additional attempts after the first |

`ETHEREUM_RPC_URL` and `EXPECTED_CHAIN_ID` are validated lazily: offline tooling
and `--help` work without them, while `--check-rpc` / `--once` / `--watch` fail
with an explicit message.

## Logging

One JSON object per line on stdout, which is what Filebeat → Wazuh, Loki or
CloudWatch expects. Every record carries `timestamp`, `level`, `event`; the
relevant ones add `chain_id`, `block_number`, `duration_ms`.

```json
{"timestamp":"2026-11-12T09:41:32.109Z","level":"INFO","event":"block_scanned","logger":"web3_secops.block_scanner","chain_id":11155111,"block_number":10,"block_hash":"0x98c4...","tx_count":2,"is_new":true}
```

## Tests

```bash
pytest -q          # 100 tests, fully offline
ruff check .       # lint
ruff format --check .
```

The suite is **offline by design**: every RPC call is intercepted with `respx`
against a synthetic chain. No public endpoint is contacted, so the suite is
deterministic and safe in CI. Reorg scenarios are reproducible because the test
rewrites the synthetic chain mid-run.

Live-endpoint verification is a separate, manual step — see
[docs/operations.md](docs/operations.md#live-rpc-verification).

## Repository layout

```
src/web3_secops/
  rpc_client.py      # M1-A: allowlisted read-only JSON-RPC client
  block_scanner.py   # M1-B: cursor, reorg detection, SQLite store
  config.py          # M1-C: env parsing and validation
  main.py            # M1-C: CLI entry point
  logging_setup.py   # JSON Lines logging
tests/
  conftest.py        # synthetic chain + fake node
  test_rpc_client.py
  test_block_scanner.py
  test_main.py
docs/
  architecture.md
  threat-model.md
  security-assessment.md
  operations.md
```

## Documentation

- [Architecture](docs/architecture.md) — how the pieces fit and why
- [Threat model](docs/threat-model.md) — what this trusts, what it does not
- [Security assessment](docs/security-assessment.md) — controls and their tests
- [Operations](docs/operations.md) — running it, reorgs, live verification

## License

MIT. See [LICENSE](LICENSE).
