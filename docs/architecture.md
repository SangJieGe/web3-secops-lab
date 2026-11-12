# Architecture

## Position in the platform

```
Ethereum / EVM nodes
        │  (read-only JSON-RPC over HTTPS)
        ▼
  RpcClient            ← the only egress point in the process
        │
        ▼
  BlockScanner ────────► StateStore (SQLite)
        │                 cursor + blocks, one transaction
        ▼
  structured JSON Lines on stdout
        │
        ▼
  (M2) event decoder → (M3) detection engine → Wazuh SIEM
```

M1 stops at "structured logs and a durable cursor". The decoder, the detection
engine and the SIEM hop exist in the diagram to show intent, not because they
are implemented.

## Module boundaries

| Module | Responsibility | Does **not** |
| --- | --- | --- |
| `rpc_client` | Method allowlist, transport, retries, response validation, URL redaction | Know about blocks, reorgs, or storage |
| `block_scanner` | Walk the chain, detect reorgs, commit cursor | Speak HTTP directly; format log lines |
| `StateStore` | SQLite schema, transactional cursor updates | Decide *what* to scan |
| `config` | Parse and validate the environment | Contact the network |
| `main` | Compose the above; own the exit codes | Reimplement any of it |

The single-egress rule matters: if the client is the only thing that can build
an HTTP request, auditing "can this process send a transaction?" reduces to
reading one file.

## Method allowlist

`READ_ONLY_METHODS = {"eth_chainId", "eth_blockNumber", "eth_getBlockByNumber"}`

The check is a set membership test, deliberately **not** `startswith("eth_")`.
The prefix form is the classic failure mode: `eth_sendRawTransaction` starts
with `eth_`, so a prefix check forwards the one call that moves funds. The
rejection happens before a request object is constructed, which is why the tests
can assert `route.call_count == 0` rather than merely "an exception was raised".

Adding a method is a two-line change (allowlist + a typed wrapper), reviewed
against the same rule: does it mutate state?

## Scan loop

```
next_block():  cursor is None ? initial_start_block(safe_head) : cursor + 1
               (None when cursor + 1 > safe_head  →  caught up)

scan_once():
  safe_head = head - CONFIRMATIONS
  start     = next_block(safe_head)
  end       = min(start + BLOCK_BATCH_SIZE - 1, safe_head)

  for number in start..end:
      block = rpc.get_block(number)

      if parentHash disagrees with the stored previous block:
          ancestor = walk back through stored blocks to the fork point
          store.rollback_to(ancestor)          # DELETE inside a transaction
          number = ancestor + 1                # rewind, do not skip ahead
          continue

      store.commit_block(block)                # block + cursor, one transaction
```

### Why the rewind matters

An earlier implementation simply `continue`d after a rollback. If the fork was
noticed at block 44 but the common ancestor was 39, blocks 40–43 were never
refetched and the store ended up with a permanent hole. The loop therefore
rewinds to `ancestor + 1`; if that is past the end of the current batch, the
batch ends and the next call picks up from the rewound cursor. This is covered
by `test_reorg_detected_and_scanner_recovers`, which asserts every block in
`ancestor+1 .. new_head` is present afterwards.

## Storage schema

```sql
CREATE TABLE scan_state (
    chain_id    INTEGER PRIMARY KEY,
    last_block  INTEGER NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE blocks (
    chain_id     INTEGER NOT NULL,
    block_number INTEGER NOT NULL,
    block_hash   TEXT    NOT NULL,
    parent_hash  TEXT    NOT NULL,
    timestamp    INTEGER NOT NULL,
    tx_count     INTEGER NOT NULL,
    PRIMARY KEY (chain_id, block_number)
);
```

`chain_id` is part of both primary keys, so one database can hold two chains
without the cursors colliding. The cursor lives in its own table rather than
being derived with `MAX(block_number)`, because the two must be able to diverge
transiently during a rollback and be updated atomically with the block insert.

## Failure semantics

| Event | Behaviour |
| --- | --- |
| RPC timeout / 5xx / 429 | Retry with backoff, then `RpcError`; cursor unmoved, block retried next call |
| Malformed JSON-RPC body | `RpcError`, no state change |
| Response `id` mismatch | `RpcError` — a swapped response is never trusted |
| JSON-RPC `error` field | `RpcError` carrying the code |
| 3xx redirect | Failure; never followed |
| Chain id mismatch | Exit code 2, no scan |
| Fork within `REORG_WINDOW` | Roll back to ancestor, log, rescan |
| Fork deeper than window | `ReorgOutOfWindowError`, exit code 4, human review |

Every failure mode leaves the database in a consistent state: the cursor either
moved to a block that was committed, or it did not move at all.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Configuration error (missing URL, chain-id mismatch, bad value) |
| 3 | RPC error |
| 4 | Scanner error, including reorg out of window |
| 130 | Interrupted (Ctrl-C) |
