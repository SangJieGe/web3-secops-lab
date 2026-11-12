# Web3 SecOps Lab

A read-only on-chain security operations lab: collect Ethereum data safely, store
it durably, and build toward SIEM-based detection.

**Status: M1 complete, M2-A complete.** M1 is the data-collection layer; M2-A
adds a standalone event decoder. Log *collection* (M2-B) is not built, so
nothing fetches logs yet. See [Scope and honesty](#scope-and-honesty) before
assuming anything else works.

---

## What this is

A platform for **Web3 security monitoring and incident response**, built in
stages so each stage is independently runnable and verifiable.

```
Ethereum / EVM  →  RPC Collector  →  Block Scanner  →  Event Decoder
                                                      →  Detection Engine
                                                      →  SIEM (Wazuh)
                                                      →  Alerting & IR
                └────────── M1 (done) ──────────┘  └── M2-A (done) ──┘
```

| Stage | Component | Status |
| --- | --- | --- |
| M1-A | Read-only JSON-RPC client, allowlisted methods | **Implemented** |
| M1-B | Reorg-aware block scanner with SQLite cursor | **Implemented** |
| M1-C | CLI (`--check-rpc` / `--once` / `--watch`), config, JSON Lines logs | **Implemented** |
| M2-A | Standalone event decoder (ERC-20/721 transfers, approvals) | **Implemented** |
| M2-B | Log collection (`eth_getLogs`) and persistence | Not started |
| M3 | Detection engine + Wazuh integration + alerting | Not started |

## Scope and honesty

M1 **collects** blocks. M2-A **decodes** log objects passed to it by a caller. It
is *not* an event monitoring system — nothing in this repository fetches logs
yet, so no on-chain event has ever been decoded end-to-end from a live node at
this stage.

This repository does **not**:

- fetch logs (`eth_getLogs`) — that is M2-B, not built
- persist decoded events — there is no events table
- detect attacks, exploits or suspicious activity
- ship data to Wazuh or emit any alert
- sign, broadcast, or custody anything
- verify that a contract implements any token standard. A log whose layout
  matches ERC-20 `Transfer` only means the bytes look like one; any contract can
  emit that. See [docs/event-decoding.md](docs/event-decoding.md).

If a future README claims otherwise, that claim is wrong.

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
pytest -q          # 253 tests, fully offline
ruff check .       # lint
ruff format --check .
```

The suite is **offline by design** and this is enforced, not just claimed:

* Every in-process RPC call is intercepted with `respx` against a synthetic chain.
* The subprocess entry-point tests run a real `python -m` process against a real
  HTTP client, but the endpoint is a loopback JSON-RPC stub
  (`tests/local_rpc_server.py`) bound to `127.0.0.1` — never a public RPC host.
* Verified by running the whole suite inside `unshare -rn` (a network namespace
  with no route off the host): **253 passed** with only loopback up.

M1 contributes 119 tests; M2-A adds 134 decoder tests, which open no socket at
all — they build logs from literal hex in-process.

`pytest` contacts no public endpoint and requires no RPC API key, in CI or
locally.

### Live-endpoint verification (manual, opt-in)

Testing against real Sepolia is kept out of the default run because a shared
public endpoint is rate-limited and would make CI flaky. It is a marked
integration test that must be requested explicitly:

```bash
pytest -m integration -v          # hits a real public RPC endpoint
```

This is a manual pre-release check, not part of CI. See
[docs/operations.md](docs/operations.md#live-rpc-verification) for the full
procedure.

## Repository layout

```
src/web3_secops/
  __main__.py        # M1-C: package entry (`python -m web3_secops`)
  rpc_client.py      # M1-A: allowlisted read-only JSON-RPC client
  block_scanner.py   # M1-B: cursor, reorg detection, SQLite store
  event_decoder.py   # M2-A: standalone log → event decoder (no I/O)
  config.py          # M1-C: env parsing and validation
  main.py            # M1-C: CLI entry point
  logging_setup.py   # JSON Lines logging
tests/
  conftest.py        # synthetic chain + fake node
  local_rpc_server.py  # loopback JSON-RPC stub for subprocess tests
  test_rpc_client.py
  test_block_scanner.py
  test_main.py
  test_entrypoint.py # real subprocess, loopback endpoint, no public network
  test_event_decoder.py  # M2-A: 134 offline decode/validation tests
docs/
  architecture.md
  threat-model.md
  security-assessment.md
  operations.md
  event-decoding.md  # M2-A: topic0, indexed vs data, why layout ≠ standard
```

## Documentation

- [Architecture](docs/architecture.md) — how the pieces fit and why
- [Threat model](docs/threat-model.md) — what this trusts, what it does not
- [Security assessment](docs/security-assessment.md) — controls and their tests
- [Operations](docs/operations.md) — running it, reorgs, live verification
- [Event decoding](docs/event-decoding.md) — M2-A decoder, and why a matching
  log layout does not prove a contract implements a standard

## License

MIT. See [LICENSE](LICENSE).
