# Threat Model

A STRIDE-flavoured threat model for Web3 SecOps Lab. The lab is itself a security
tool, so this document also treats it as an **asset to be defended**.

## 1. Scope & assets

| Asset | Why it matters | Where it lives |
|-------|----------------|----------------|
| Watchlist (addresses, labels) | Reveals which treasuries/admins are monitored; useful recon for an attacker | `config/watchlist.yaml` (gitignored) |
| RPC credentials (API keys) | Paid-provider keys can be abused / cost money | `.env` (gitignored) |
| Alert stream | May contain sensitive operational intelligence | `logs/alerts.jsonl` |
| Scan state | Cursor/dedup; low sensitivity but tampering causes missed blocks | `data/state.db` |
| Wazuh deployment | Alerting backbone; compromise = blindness | `deploy/`, `wazuh/` |
| The repo itself | Defaults, docs, and example configs must not leak real data | Git history |

**Non-assets by design:** private keys and seed phrases. The lab holds none. If a
future change introduces signing, that is a scope change requiring a new review.

## 2. Trust boundaries

```
[ Internet ] --RPC--> [ rpc_client ] --data--> [ detector ] --findings--> [ sink ] --file--> [ Wazuh agent ]
     ^                                                                                            |
     |  untrusted: node responses may be malformed, stale, or malicious                           |
     +--------------------------------------------------------------------------------------------+
                                    (operator runs both halves)
```

1. **RPC boundary** — the node is *semi-trusted*. It can lie (wrong data), fail
   (rate-limit), or be compromised (MITM if `https` is downgraded). The lab must
   tolerate all three without crashing or misleading the operator.
2. **Config boundary** — `config/` and `.env` are operator-controlled and must never
   be committed.
3. **Sink boundary** — `logs/alerts.jsonl` crosses into Wazuh; injection of crafted
   JSON could confuse decoders.

## 3. STRIDE analysis

### Spoofing
- **Threat:** a malicious RPC endpoint impersonates the real chain (MITM).
- **Mitigation:** require `https://`; pin to reputable providers; optionally verify
  block hashes against a second source. Document that plain `http://` is unsupported.

### Tampering
- **Threat:** attacker edits `logs/alerts.jsonl` or `state.db` to hide activity.
- **Mitigation:** write-once directory perms; ship logs off-host immediately; Wazuh
  agent runs as a separate user with read-only access to the log path. Cursor
  tampering causes re-scan (safe) rather than missed blocks — the dedup table
  re-emits on hash mismatch.

### Repudiation
- **Threat:** operator denies an alert fired (or an attacker denies their on-chain action).
- **Mitigation:** on-chain evidence is immutable — every `Finding` carries `tx_hash`
  and `block_number`. Log shipping to Wazuh preserves a third-party timeline.

### Information Disclosure
- **Threat:** watchlist or API keys leak via git or logs.
- **Mitigation:** `.gitignore` excludes `.env`, `config/watchlist.yaml`, `data/`,
  `logs/`; only `.example` files are committed. Review commits for secrets before
  pushing. Doc/example content is scrubbed of real addresses.

### Denial of Service
- **Threat:** a hostile or failing node stalls the scanner; or a flood of matching
  events overwhelms the sink.
- **Mitigation:** bounded retries with backoff + jitter; the scan loop degrades to
  "caught up" and sleeps rather than hot-looping. Sink writes are append-only and
  cheap. A rate-limited node simply slows progress, it does not crash the process.
  Backfill window is bounded (`START_BLOCK_LOOKBACK`) to avoid unbounded work.

### Elevation of Privilege
- **Threat:** crafted on-chain data triggers code execution or privilege escalation
  in the decoder (e.g. via a malicious ABI).
- **Mitigation:** the decoder performs no `eval`, no dynamic imports, and no shell
  calls; it only slices hex strings. ABIs are loaded from local files the operator
  controls. Container runs as `nobody` with no capabilities and no write access to
  the image. Wazuh integration is a *read* of the alert file, not a remote command
  channel — `active-response` is intentionally **not** configured for these rules.

## 4. On-chain-specific considerations

| Concern | Handling |
|---------|----------|
| **Reorgs** | Scanner keeps `confirmations` behind the tip; dedup by `(number, hash)` so a reorged block re-emits with its new hash. |
| **Stale data** | Alerts include `block_number`; operators should confirm finality for high-severity actions before reacting. |
| **Chain reorg abuse** | Rapid-drain detection counts by timestamp; a reorg could duplicate counts, so dedup happens before inspection. |
| **Front-running / MEV** | Out of scope for detection here (no mempool subscription), but `large-transfer` on confirmed blocks still surfaces the outcome. |
| **Sanctioned entities** | Handled via `flagged_contracts` list, which the operator maintains from authoritative sources. |

## 5. Residual risks & accepted trade-offs

- **Single data source**: one RPC endpoint per chain. A lying node produces wrong
  alerts. Accepted for a lab; production should cross-check.
- **Rule-based only**: no anomaly scoring yet, so novel attack patterns may be missed.
  Tracked on the roadmap.
- **Local alert buffer**: if Wazuh is down, alerts accumulate on disk. Disk fill is a
  DoS vector — add log rotation/retention for production.

## 6. Out of scope

- Custody / key management (the lab holds no keys).
- Transaction execution or response automation.
- MEV / mempool-level surveillance.
- Smart-contract auditing (see `contracts/` for sample ABIs only).

## 7. Review triggers

Re-review this model whenever:
- A component gains write access to the chain or to a remote system.
- A new data source (second RPC, mempool, price oracle) is added.
- Alert routing changes (e.g. enabling Wazuh active-response).
