# Threat model

Scope: the M1 read-only collector. Threats are listed with the control that
addresses them and the test that proves the control works. A control without a
test is a claim, not a control.

## Assets

| Asset | Why it matters |
| --- | --- |
| The RPC credential in `ETHEREUM_RPC_URL` | A leaked key is billable and, on some providers, grants more than reads |
| Integrity of the stored scan history | A silent gap or double-count invalidates every downstream detection |
| The host running the collector | A compromised collector becomes a foothold |
| Downstream SIEM trust | False events poison incident response |

Not in scope for M1: user funds, private keys, transaction signing — the
codebase has no such capability.

## Trust boundaries

```
[ process ] --HTTPS--> [ RPC provider ] --?--> [ the chain ]
    ^                        ^
    |                        └── trusted to answer eth_* reads, NOT trusted
    |                            to be honest about block content
    └── everything from the provider is untrusted input
```

The provider is a **semi-trusted** party. It is trusted to serve the chain you
asked for; it is not trusted to return well-formed data, to keep its redirects
honest, or to avoid rate-limiting you at the worst moment.

## Threats and controls

### T1 — Leaking the RPC API key

*Vector:* logging the endpoint, storing it in SQLite, or letting it into an
exception message or a CI log. A second, less obvious vector: the **remote peer**
putting a credential-shaped string into a field we echo back — the `Location`
header of a 3xx or `error.message` in a JSON-RPC error.

*Control:* `redact_url()` strips the last path segment (`/v2/<KEY>`,
`/v3/<KEY>`, `/<KEY>`) and the whole query string. `Settings` exposes
`safe_rpc_url`; only that value is ever logged. `RpcClient.url` is declared
`field(repr=False)` so the dataclass repr cannot resurface the raw URL through a
traceback or an f-string. The URL is never written to the database. The real
`.env` is git-ignored, and CI checks that no `.env` file is git-tracked (this is
a tracked-file check only — it is **not** secret scanning, and no such claim is
made).

Remote-controlled strings never reach a log verbatim: `Location` is reduced to a
bare host with the path dropped, and `error.message` goes through
`_scrub_remote_text` (URL shapes redacted, long opaque tokens masked, then
truncated). The error code and classification stay unmasked so failures remain
diagnosable.

*Tests:* `test_safe_rpc_url_redacts_key`,
`test_redact_url_strips_keys` (nine URL shapes),
`test_api_key_not_in_logs` (parses every emitted log record),
`test_repr_does_not_expose_url`,
`test_redirect_location_secret_absent_from_subprocess_output`,
`test_rpc_error_message_secret_absent_from_subprocess_output` (both run a real
`python -m` subprocess and grep stdout **and** stderr for the planted value,
asserting zero hits while also asserting the output is still non-empty).

*Residual risk:* a provider that embeds the key in a header echoed by a traceback
would bypass path/query redaction. Accepted: the collector does not log headers.

### T2 — Accidental state-changing RPC calls

*Vector:* `eth_sendRawTransaction` (or `eth_signTransaction`,
`personal_sign`, `eth_sign`) reaching the node. One bug here is a fund-moving
bug.

*Control:* strict allowlist of three read methods, evaluated **before** any HTTP
work. No generic `call(method, params)` is exposed to callers.

*Tests:* `test_forbidden_method_sends_no_http_request`,
`test_unknown_method_rejected_without_request` and
`test_eth_prefix_is_not_sufficient` — parametrised over
`eth_sendRawTransaction`, `eth_signTransaction`, `personal_sign`, `eth_sign` and
friends — assert `route.call_count == 0`, i.e. the request never existed. A
"raises an exception" assertion would not have caught a transport that raised
*after* sending.

*Residual risk:* none identified; the allowlist is a closed set.

### T3 — Trusting node-supplied data

*Vector:* the node returns malformed JSON, a different `id`, or a valid-looking
block whose `parentHash` lies, silently corrupting the scan history.

*Control:* the response must be HTTP 200 with a JSON object, matching `id`,
`jsonrpc: "2.0"`, and no `error` field. Hex quantities are parsed as `int`
strictly. `parentHash` is cross-checked against the stored previous block; a
mismatch is a reorg, not a silent overwrite. JSON-RPC payloads are never
`eval`'d or used as format strings.

*Tests:* `test_id_mismatch_detected`, `test_invalid_json_body`,
`test_rpc_error_response_raises`, `test_wrong_jsonrpc_version`,
`test_non_object_response_rejected`, `test_both_result_and_error_rejected`,
`test_neither_result_nor_error_rejected`, `test_malformed_quantity_rejected`.

### T3a — Node returns a different height than requested

*Vector:* a broken or hostile node answers `eth_getBlockByNumber("0x64")` with
block `0x65`. The payload is internally consistent — correct hash, correct parent
— so parent-hash checking cannot see anything wrong. Accepting it would store
block 101's contents under height 100 and silently skip block 100 forever, and
because the stored parent chain stays self-consistent, the corruption would never
surface as a reorg.

*Control:* the requested height is compared to the returned height at two
independent layers — in `RpcClient.get_block()` before the scanner receives the
block, and again in `BlockScanner.scan_once()` before the reorg check and before
any write. A mismatch raises and is **never** routed into reorg rollback, because
it is not evidence of a fork; treating it as one would delete perfectly good
history on the basis of a bad response.

*Tests:* `test_block_mismatch_is_rejected_and_nothing_is_persisted` (failure
raises, no row for 100 or 101, cursor untouched),
`test_mismatch_does_not_trigger_reorg_rollback` (previously stored rows are all
still present after the failure).

*Residual risk:* none identified for height substitution. A node that lies
consistently across every block it serves is indistinguishable from a legitimate
alternative chain; that is what T5 and cross-provider validation would address,
and neither is in M1.

### T4 — Silent data loss (gaps or double counting)

*Vector:* crash between "block fetched" and "cursor written"; or a reorg rollback
that skips the rewritten range.

*Control:* block insert and cursor update share one SQLite transaction, so no
crash can commit one without the other. After a rollback the loop rewinds to
`ancestor + 1` rather than continuing forward.

`BLOCK_BATCH_SIZE` bounds how many blocks **one** `scan_once` call may commit, and
a rollback does not refund that budget. A fork deeper than one batch therefore
takes several calls to recover, with the cursor carrying the resume point — an
unbounded recovery burst would otherwise be the easiest way to make a single
`--once` call run for an arbitrarily long time.

*Tests:* `test_commit_block_is_atomic`,
`test_commit_block_rolls_back_when_cursor_update_fails` (SQLite trigger aborts the
cursor update after the insert; asserts no surviving row, no moved cursor, DB
still writable, file reopens),
`test_cursor_does_not_advance_on_fetch_failure`,
`test_cursor_resumes_after_restart`,
`test_reorg_detected_and_scanner_recovers` (asserts blocks 40–60 present and
hash-consistent after a fork with ancestor 39),
`test_reorg_respects_batch_limit_and_leaves_no_holes` (batch 5, fork 12 deep, no
call exceeds the limit, full coverage after repeated calls),
`test_reorg_rewind_does_not_refund_commit_budget`.

*Residual risk:* filesystem-level corruption; SQLite's own journal handles it.

### T5 — Reorg deeper than the window

*Vector:* a deep reorg invalidates blocks older than `REORG_WINDOW`; continuing
would build detections on an orphaned chain.

*Control:* `ReorgOutOfWindowError` — a fatal, explicit failure with exit code 4.
The scanner refuses to guess.

*Tests:* `test_deep_reorg_beyond_window_raises`.

### T6 — Redirect to an attacker-controlled host

*Vector:* the provider (or a MITM on plain HTTP, or a compromised DNS record)
returns 3xx to a host that harvests the key.

*Control:* `follow_redirects=False`; any 3xx is a hard `RpcError`. The key, if
present, stays in a request that never leaves the process's intended destination.

*Tests:* `test_redirect_not_followed`.

*Residual risk:* plain `http://` endpoints are allowed for local dev nodes, where
a passive observer can read the key. `.env.example` documents HTTPS for any
remote endpoint; the risk is surfaced, not hidden.

### T7 — Unbounded resource use / retry storm

*Vector:* retrying forever against a rate-limited endpoint, hammering a free
tier, or a non-terminating loop from a bare CLI invocation.

*Control:* exponential backoff with jitter, a hard `max_retries` cap, a
per-request timeout, and `--check-rpc` / `--once` / `--watch` as an explicit
required choice — a bare invocation prints usage and exits.

*Tests:* `test_retries_on_http_503_then_succeeds`,
`test_retries_on_http_429_then_succeeds`,
`test_retries_on_timeout_then_succeeds`, `test_retries_exhausted_raises`,
`test_timeout_exhausted_raises`, `test_cli_requires_a_mode`.

### T8 — Precision loss in amounts

*Vector:* a float balance rounds and a downstream detector sees a wrong amount.

*Control:* all quantities are Python `int` Wei. The client parses hex to `int`
and never to `float`.

*Tests:* `test_normalize_large_wei_exact`, `test_large_wei_value_is_exact_end_to_end`,
`test_float_wei_would_lose_precision` (a float *would* lose precision —
asserted explicitly so the danger is documented, not just avoided).

## Out of scope for M1

Named so that nobody assumes coverage:

- Denial of service against the node (we are the client)
- Malicious blocks crafted to exploit a decoder — no decoder exists yet, so this
  becomes an M2 threat
- Supply-chain compromise of `httpx`/`jinja`-style dependencies; handled by
  Dependabot, not by this code
- Holder or protocol-level attacks (flash loans, oracle manipulation) — that is
  M3 detection work
- Physical/host compromise of the machine running the collector
