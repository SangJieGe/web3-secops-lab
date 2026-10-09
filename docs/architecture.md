# Architecture

## Overview

Web3 SecOps Lab is a **read-only** pipeline that turns on-chain activity into
structured security alerts, then hands them to a traditional SOC stack (Wazuh).

```
 EVM node (JSON-RPC)
        │  eth_blockNumber / eth_getBlockByNumber / eth_getLogs
        ▼
 ┌──────────────┐   retries, jitter, batching
 │ rpc_client   │───────────────────────────────┐
 └──────────────┘                               │
        │ raw blocks / logs                     │
        ▼                                       │
 ┌──────────────┐   SQLite cursor + dedup       │
 │ block_scanner│───────────────────────────────┤
 └──────────────┘                               │
        │ NormalizedBlock                       │
        ├──────────────► ┌──────────────┐       │
        │                │ event_decoder│◄──────┘  eth_getLogs for watched contracts
        │                └──────┬───────┘
        │                       │ decoded events
        ▼                       ▼
 ┌──────────────────────────────────────┐
 │             detector                 │  rules: watched / large / flagged / drain
 └──────────────┬───────────────────────┘
                │ Finding[]
                ▼
        ┌──────────────┐
        │  AlertSink   │  logs/alerts.jsonl
        └──────┬───────┘
               │ tailed by Wazuh agent
               ▼
   Wazuh manager ──► decoders ──► rules ──► dashboards / active response
```

## Components

### `rpc_client.py`
Thin, synchronous JSON-RPC client built on `httpx`.

- **Read-only guard**: every method must start with `eth_`; anything else raises
  immediately. There is no code path that signs or broadcasts a transaction.
- **Retry policy**: bounded exponential backoff with full jitter on HTTP 408/429/5xx
  and JSON-RPC codes `-32603/-32000/429/503`.
- **Batching**: `batch()` sends multiple calls in one HTTP round-trip; if the node
  rejects batches it transparently falls back to sequential calls.
- **Wrappers**: `get_block_number`, `get_block`, `get_logs`, `eth_call`, `get_balance`.

### `block_scanner.py`
Walks blocks forward from a durable cursor.

- **Cursor**: `cursor` table in SQLite stores `last_block` per `chain_id`. Restart
  resumes exactly where it stopped.
- **Dedup / reorg handling**: `seen_blocks` table keeps `(number, hash)` for a bounded
  window; a block whose hash changed (reorg) is re-emitted, an identical one is skipped.
- **Confirmations**: `confirmations` offset keeps the scanner behind the tip to reduce
  reorg churn.
- **Cold start**: on first run it backfills `START_BLOCK_LOOKBACK` blocks.

### `event_decoder.py`
Dependency-free ABI decoding.

- `RawLog.from_rpc()` normalises JSON-RPC log objects.
- `AbiEvent.from_dict()` builds an event definition, deriving `topic0` from the
  signature when not supplied.
- `decode_event()` reads indexed params from `topics` and the rest from `data`,
  supporting static types (address/uint/int/bool/bytesN) and dynamic ones
  (string/bytes/array).
- `EventDecoder` is a topic0-keyed registry for O(1) lookup on the hot path. Decode
  failures are logged and swallowed so the scan loop never dies.

### `detector.py`
Transparent, rule-based detection. Each rule returns `Finding` objects.

| Rule | Trigger | Default severity |
|------|---------|------------------|
| `watched-outbound` | watched address sends a tx | per watchlist (high) |
| `watched-inbound` | watched address receives a tx | per watchlist (high) |
| `rapid-drain` | N outbound txs from a watched address within a window | critical |
| `large-transfer` | native value ≥ `min_notable_value` | medium |
| `flagged-interaction` | tx to a flagged contract | per config (high) |
| `token-movement` | watched address in a decoded Transfer event | per watchlist |

Severity ordering is `low < medium < high < critical`; `filter_by_severity()` gates
the sink.

### `main.py`
Orchestration loop.

1. Load `.env` + `config/watchlist.yaml`.
2. Resolve chain → RPC URL.
3. Build `RpcClient`, `CursorStore`, `BlockScanner`, `Detector`, `EventDecoder`, `AlertSink`.
4. Loop: scan → inspect → (optionally decode logs) → emit → sleep.
5. `--once` / `--max-blocks` for deterministic runs; SIGINT/SIGTERM for clean shutdown.

## Data contracts

### `NormalizedBlock` / `NormalizedTx`
Reduced representations carrying only the fields detection needs (hash, from, to,
value in wei, block number, index).

### `Finding` (alert payload)
```json
{
  "rule": "rapid-drain",
  "severity": "critical",
  "title": "Rapid outbound drain from Treasury",
  "description": "3 outbound txs from Treasury within 300s",
  "chain_id": 1,
  "block_number": 19000000,
  "tx_hash": "0x...",
  "timestamp": 1700000000.0,
  "context": {"address": "0x...", "label": "Treasury", "count": 3, "tags": ["treasury"]}
}
```

Alerts are appended as one JSON object per line to `ALERT_LOG_PATH`, which the Wazuh
agent tails. See `wazuh/` for decoders and rules.

## Design principles

1. **Read-only, always.** No keys, no signing, no broadcasting. Enforced at the
   RPC client boundary.
2. **Fail soft, never silent.** Decode/scan errors are logged and skipped; the loop
   keeps running. A silent failure is worse than a noisy one.
3. **Resumable.** Every restart continues from the last processed block.
4. **Auditable.** Dependencies are minimal and the decoding logic is explicit so a
   reviewer can read it end to end.
5. **SOC-native.** Output is JSON-lines designed for Wazuh; severity maps to rule levels.

## Scaling notes

- **Multi-chain**: run one process per chain (separate `chain_id` cursors); a supervisor
  launches them. A future revision may co-schedule them in one event loop.
- **Rate limits**: `BLOCK_BATCH_SIZE` and `POLL_INTERVAL_SECONDS` are the main knobs;
  use a paid RPC provider for sustained throughput.
- **Storage**: SQLite is fine for a single scanner; move the cursor/dedup store to
  Postgres if you fan out.
