# Security assessment

Every control below is implemented in code and has at least one test. Controls
are stated at the strength actually achieved — nothing here claims production
hardening that M1 does not provide.

## Summary

| Control | Strength | Proof |
| --- | --- | --- |
| Read-only method allowlist | Strong — closed set, pre-transport | `test_forbidden_method_sends_no_http_request` |
| RPC key redaction | Strong — path + query | `test_redact_url_strips_keys` |
| No signing path | Structural — no code exists | `test_allowlist_contents` |
| Response validation | Strong — id, version, shape | `test_id_mismatch_detected` |
| Transactional cursor | Strong — single SQLite txn | `test_commit_block_is_atomic` |
| Reorg handling | Strong within window | `test_reorg_detected_and_scanner_recovers` |
| Deep-reorg refusal | Strong — fail closed | `test_deep_reorg_beyond_window_raises` |
| Retry bounds | Strong — capped, jittered | `test_retries_exhausted_raises` |
| Redirect refusal | Strong — 3xx is an error | `test_redirect_not_followed` |
| Wei integer precision | Strong — `int` only | `test_normalize_large_wei_exact` |
| TLS verification | **Default only** — not pinned | n/a (see caveat) |
| Rate-limit backpressure | **Basic** — retry cap only | `test_retries_on_http_429_then_succeeds` |

## C1 — Read-only method allowlist

```python
READ_ONLY_METHODS = frozenset(
    {
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBlockByNumber",
    }
)
```

Enforced by set membership, not prefix matching. The distinction is the whole
point: `"eth_sendRawTransaction".startswith("eth_")` is `True`, so a prefix check
would forward a transaction-signing call to the node while believing it was
enforcing read-only access.

Rejection happens before a request object exists. The tests assert
`route.call_count == 0`, which is a stronger claim than "an exception was
raised" — it proves nothing was sent.

**What this does not do:** a compromised *provider* can still lie about the
chain. Read-only means we cannot change state, not that the answer is true.
Cross-checking against a second provider is M2 work.

## C2 — Credential handling

`redact_url()` is the only path from a URL to a log line.

- Last path segment dropped: `/v2/KEY`, `/v3/KEY`, `/KEY` → `/v2/***`
- Query string dropped entirely: `?apikey=KEY` → `?***`
- Credentials in the authority dropped: `user:pass@host` → `***@host`

The redacted form keeps scheme + host so logs remain useful for debugging
("which provider failed?") without leaking the key.

`Settings.safe_rpc_url` is what gets logged. `RpcClient.__repr__` is overridden
so an f-string of the client cannot leak either — `test_repr_does_not_expose_url`
covers that, because `repr` leaking is the most common way redaction silently
fails.

The URL is never persisted to SQLite. `.env` is git-ignored; CI fails if a
tracked `.env` ever appears.

## C3 — No key material, no signing

There is no private key handling anywhere in the source tree: no
`eth_account`, no `secp256k1`, no keystore loader, no `web3.py`. Transaction
*contents* are read as data and stored as counts and hashes; nothing is
constructed or signed.

This is a structural guarantee, not a policy: adding signing would require a new
dependency and a new allowlisted method, both of which are reviewable diffs.

## C4 — Response validation

A response is accepted only if **all** hold:

1. HTTP 200 (3xx and 4xx/5xx are errors, never silently coerced)
2. Body is a JSON object
3. `jsonrpc == "2.0"`
4. `id` equals the request id
5. exactly one of `result` / `error` is present
6. when `result` is expected, its shape matches what the caller asked for

Rule 4 is what stops a mixed-up or replayed response from being attributed to
the wrong request. Rule 5 rejects the ambiguous `{result: null, error: {...}}`
form some proxies emit.

Hex quantities are parsed with a strict parser that rejects signs, exponents,
and `0x`-prefixed non-hex. `"0x"` alone, `"-0x1"`, and `"0x1g"` are all errors
rather than silent zeros.

## C5 — Transactional cursor

```python
with self._conn:               # one transaction
    upsert blocks row
    update scan_state.last_block
```

Both writes commit or neither does. A `SIGKILL` between them leaves the cursor
where it was, so the block is refetched — duplicate work, never a gap. Re-scanning
the same block is idempotent (`is_new: false`, `test_rescan_of_same_block_is_idempotent`).

`chain_id` is part of both primary keys, so a single DB can hold two chains
without cursor collision (`test_chain_ids_are_isolated`).

## C6 — Reorg handling

Detection: the block's `parentHash` is compared against the stored hash of
`block_number - 1`. Equality is the normal case; inequality means the node's
chain forked below us.

Resolution:

1. Walk the stored window backwards to find the highest block whose hash still
   matches the node's version → common ancestor.
2. `DELETE` all rows above the ancestor and set the cursor to the ancestor, in
   one transaction.
3. Rewind the scan loop to `ancestor + 1` and refetch forward.

Step 3 is where an earlier version was wrong: it continued forward from the
block where the fork was *noticed*, permanently skipping the rewritten range.
The current implementation rewinds, and
`test_reorg_detected_and_scanner_recovers` asserts every block in the rewritten
range exists afterwards with the new fork's hash.

If no common ancestor is found within `REORG_WINDOW`, `ReorgOutOfWindowError` is
raised and the process exits 4. Guessing here would silently mix two forks in
one table.

## C7 — Retry and backpressure

- Retryable: timeout, connection error, HTTP 429, HTTP 5xx, and a small set of
  JSON-RPC server codes
- Non-retryable: HTTP 4xx (except 429), JSON-RPC `error` with a client-fault
  code, validation failures — these fail immediately rather than burning the
  retry budget
- Backoff: exponential with full jitter, capped by `RPC_MAX_RETRIES`
- Per-request timeout via `httpx.Timeout`

**Caveat:** honouring `Retry-After` is not implemented. Against a strict free
tier, jittered exponential backoff is adequate but not optimal; a provider that
returns `Retry-After: 3600` will simply fail after the retry budget. Recorded
here rather than overstated in the README.

## C8 — Redirects and TLS

`follow_redirects=False`. Any 3xx produces `RpcError` and no second request is
issued (`test_redirect_to_other_host_issues_no_second_request` asserts the
target host received zero calls). Chasing a redirect would re-send the request —
possibly with the key in the path — to a host chosen by the responder.

TLS: certificate verification uses `httpx`'s default, which is **verification
enabled**. There is no code path that disables it (`verify=False` appears
nowhere). Certificate *pinning* is not implemented; that is a deliberate
non-goal for a lab that must work against arbitrary providers.

Plain `http://` is accepted because local dev nodes (`http://127.0.0.1:8545`)
have no TLS. This is surfaced, not hidden: `.env.example` states HTTPS is
required for any remote endpoint.

## C9 — Precision

All Wei amounts are Python `int`. JSON-RPC hex → `int` via `int(x, 16)`; no
intermediate `float`. `test_float_wei_would_lose_precision` demonstrates the
hazard explicitly — `int(1e18)` and the true value `10**18` differ — so the
reason for the rule is recorded in the suite, not just in a comment.

Python `int` is arbitrary precision, so no BigInt ceiling applies.

## C10 — Logging

JSON Lines, one object per line, keys `timestamp` / `level` / `event` always
present. Structured fields are passed via `extra=` and filtered against
stdlib-reserved attributes, so a caller cannot accidentally shadow `level` or
`event`.

Log content never includes: the raw RPC URL, request bodies, or response bodies.
Only counts, block numbers, hashes and durations.

## Honest limitations

Stated plainly so nobody mistakes M1 for production hardening:

1. **No `Retry-After` support** (C7).
2. **No certificate pinning** (C8).
3. **Single provider** — no cross-validation of block data.
4. **No rate-limit budget** — a fast `--watch` against a free tier will hit 429s
   and exit; the fix is a smaller batch, not a smarter client, at this stage.
5. **No auth on the SQLite file beyond filesystem permissions** — `0600` is set
   at creation (`test_db_file_permissions_are_restricted`), but a local user with
   read access to the DB sees block metadata, not credentials.
6. **No audit log of rejected calls.** A rejected `eth_sendRawTransaction` is an
   event worth alerting on; today it raises to the caller and stops. M3 work.
7. **Reorg detection is parentHash-only.** It catches forks on the canonical
   chain; it does not detect a provider serving a fabricated-but-self-consistent
   chain.

Points 1–7 are the honest boundary of M1. None of them is a security hole in the
collector's stated purpose; each is a capability M2/M3 must add.
