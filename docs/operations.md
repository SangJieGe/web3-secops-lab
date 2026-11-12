# Operations

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

## Configure

Minimum for any networked mode:

```dotenv
ETHEREUM_RPC_URL=https://your-provider.example/v2/YOUR_KEY
EXPECTED_CHAIN_ID=1
```

`ETHEREUM_RPC_URL` must be `https://` for anything remote. Plain `http://` is
only appropriate for a local node. The key in the URL is redacted in every log
line, but it is still a credential: keep `.env` out of git (it is ignored), and
`chmod 600` it.

Tuning knobs (defaults are sane for Ethereum mainnet):

```dotenv
CONFIRMATIONS=12
START_BLOCK_LOOKBACK=20
BLOCK_BATCH_SIZE=5
POLL_INTERVAL_SECONDS=12
REORG_WINDOW=64
STATE_DB_PATH=./data/state.db
LOG_LEVEL=INFO
```

## Run

### 1. Check the endpoint

```bash
python -m web3_secops --check-rpc
```

Issues exactly two calls (`eth_chainId`, `eth_blockNumber`), writes nothing, and
logs one structured record:

```json
{"timestamp":"...","level":"INFO","event":"rpc_check_ok","logger":"web3_secops.main","chain_id":1,"expected_chain_id":1,"block_number":23912345,"endpoint":"your-provider.example/v2/***","duration_ms":412}
```

Exit code 2 means the chain id did not match `EXPECTED_CHAIN_ID` — stop and fix
the config; do not scan a chain you did not intend to.

### 2. Scan one batch

```bash
python -m web3_secops --once
```

Reads at most `BLOCK_BATCH_SIZE` confirmed blocks, commits them, exits. Safe to
run from cron; the cursor makes it resumable and idempotent.

### 3. Watch continuously

```bash
python -m web3_secops --watch
```

One batch per `POLL_INTERVAL_SECONDS`. `Ctrl-C` exits 130 cleanly, with the
cursor at a committed block.

## Live RPC verification

Distinguishing the three states matters — a mocked test proves the client's
logic, not the endpoint's behaviour.

| State | What it proves | How to produce |
| --- | --- | --- |
| **MOCK TEST** | client/scanner logic against a synthetic chain | `pytest -q` |
| **LIVE RPC TEST** | the real endpoint answers the three read calls, and a real block round-trips into SQLite | commands below |
| **PRODUCTION DEPLOYMENT** | long-running, monitored, on real infra | *not done in M1* |

A live check, against a free public endpoint:

```bash
export ETHEREUM_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
export EXPECTED_CHAIN_ID=11155111
export STATE_DB_PATH=/tmp/live-check.db
export START_BLOCK_LOOKBACK=3
export CONFIRMATIONS=2
export BLOCK_BATCH_SIZE=3

python -m web3_secops --check-rpc
python -m web3_secops --once
```

Then verify the cursor actually persisted:

```bash
sqlite3 /tmp/live-check.db \
  "SELECT chain_id, last_block, updated_at FROM scan_state;
   SELECT block_number, substr(block_hash,1,18), tx_count FROM blocks ORDER BY block_number;"
```

Re-running `--once` must advance from the stored cursor, not restart — that is
the persistence proof.

### If the endpoint is rate-limited or down

Report the error; do not fabricate a result and do not buy a paid tier to make a
test pass. Expected signatures:

```json
{"level":"ERROR","event":"rpc_error","reason":"... HTTP 429 ..."}
```

Exit 3. The cursor is unchanged, so nothing is lost — retry later with a smaller
`BLOCK_BATCH_SIZE`.

## Interpreting reorgs

A reorg looks like this in the log:

```json
{"level":"WARNING","event":"reorg_detected","chain_id":1,"block_number":40,"stored_hash":"0xabc...","node_hash":"0xdef..."}
{"level":"WARNING","event":"reorg_rollback","chain_id":1,"ancestor":39,"rows_deleted":6}
```

- **Within `REORG_WINDOW`** — automatic. Rolled back to the ancestor and
  rescanned. No action needed.
- **`reorg_out_of_window` + exit 4** — the fork is deeper than the retained
  window. The scanner refuses to guess. Investigate before restarting: either
  raise `REORG_WINDOW` and rescan, or wipe the state DB and rescan from a known
  block. Both are deliberate operator decisions.

`REORG_WINDOW` trades disk for rollback depth. 64 blocks is ~13 minutes on
mainnet, which covers realistic reorgs; 900+ is overkill for a lab.

## Storage growth

`blocks` keeps `REORG_WINDOW` rows behind the cursor (older rows are trimmed).
Row size is ~120 bytes, so the working set is small and bounded. The full scan
history is intentionally *not* retained in M1 — M2 will write decoded events to
its own table.

## Exit codes

| Code | Meaning | Action |
| --- | --- | --- |
| 0 | Success | — |
| 2 | Config error | Fix `.env`; check chain id |
| 3 | RPC error | Check endpoint/key/quota; cursor intact |
| 4 | Scanner error incl. deep reorg | Investigate before restarting |
| 130 | Ctrl-C | None |

## Log ingestion

stdout is JSON Lines, one object per line. For Wazuh/Filebeat:

```yaml
filebeat.inputs:
  - type: stdin   # or container/file input
    json.keys_under_root: true
    json.add_error_key: true
```

M1 emits no alerts. Anything in M3 that claims to alert must be built on these
records, not on a separate ad-hoc format.
