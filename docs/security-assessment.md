# Security Assessment

A self-assessment of Web3 SecOps Lab: what it does well, where it is thin, and the
hardening roadmap. Written from an attacker's perspective — assume the lab is a
target, not just a tool.

## 1. Methodology

- **Reading:** full source review of `src/web3_secops/` (all modules are small by design).
- **Abuse cases:** derived from `threat-model.md` §3 (STRIDE) and on-chain specifics.
- **Standards referenced:** OWASP ASVS (logging/monitoring), MITRE ATT&CK (mapping for
  Wazuh rules), CIS Docker Benchmark (container posture).

## 2. What is done right

| Area | Finding |
|------|---------|
| **Read-only enforcement** | RPC layer rejects any method not prefixed `eth_`. No signing path exists anywhere in the codebase. |
| **Secret hygiene** | `.env` and real `watchlist.yaml` are gitignored; only `.example` templates are committed. |
| **Least privilege (container)** | Runs as `nobody`, no added capabilities, no privileged mode. |
| **Fail-soft design** | Decode/scan errors are logged, not fatal; the loop keeps running. |
| **Resumability** | Durable cursor avoids gaps after restarts; dedup handles reorgs. |
| **Auditability** | Minimal dependencies; ABI decoding is explicit and dependency-free. |
| **No remote command channel** | Wazuh integration is filesystem-read only; `active-response` is intentionally not configured. |

## 3. Findings & gaps

### F-1 (Medium) — Single RPC source, no cross-validation
A compromised or lying node produces incorrect alerts. Currently one endpoint per chain.
**Recommendation:** add an optional secondary endpoint and compare block hashes for
high-severity paths; alert on divergence.

### F-2 (Medium) — Watchlist integrity is unverified
`config/watchlist.yaml` is trusted verbatim. Tampering silently blinds detection.
**Recommendation:** checksum the watchlist, log a hash at startup, and alert if it changes
unexpectedly. Optionally sign it.

### F-3 (Medium) — Alert file is unprotected at rest
`logs/alerts.jsonl` is plaintext on disk; local tampering hides evidence.
**Recommendation:** restrictive perms, immediate off-host shipping (already the Wazuh
model), and append-only storage where available.

### F-4 (Low) — Unbounded local buffer if Wazuh is down
Alerts accumulate on disk; could fill the volume.
**Recommendation:** log rotation + retention policy; monitor disk.

### F-5 (Low) — No anomaly baseline
Rules are static thresholds; low-and-slow drain evades `rapid-drain`.
**Recommendation:** add behavioural baselines (rate, counterparty set) and deviation scoring.

### F-6 (Low) — Decoder robustness not fuzzed
Malformed `data`/`topics` should be handled, but the parser has no fuzz coverage.
**Recommendation:** add property/fuzz tests (e.g. Hypothesis) over `decode_event`.

### F-7 (Info) — Severity → Wazuh level mapping is coarse
Levels 5–13 are used; fine-grained tuning may be needed per deployment.

## 4. MITRE ATT&CK mapping (for Wazuh rules)

| Lab rule | ATT&CK |
|----------|--------|
| `rapid-drain` | T1531 Account Access Removal (asset draining analogue) |
| `flagged-interaction` | T1071 Application Layer Protocol (C2 / sanctioned interaction analogue) |
| `critical` severity | T1567 Exfiltration Over Web Service (crypto-asset exfil analogue) |

> Note: on-chain mapping is analogous, not exact. Document the intent so analysts
> don't over-trust the mapping.

## 5. Container & deployment posture

- ✅ Non-root user, slim base image, no build toolchain in the final layer.
- ⚠️ `docker-compose.yml` for Wazuh uses demo credentials (`admin`/`SecretPassword`) —
  **must** be rotated before any non-lab use.
- ⚠️ Indexer security plugin disabled in the sample compose — acceptable only for an
  isolated lab network.

## 6. Hardening roadmap (prioritised)

1. **Rotate all demo credentials** and enable the indexer security plugin (before any
   deployment beyond a local lab).
2. **Add RPC cross-validation** for high-severity detections (addresses F-1).
3. **Integrity-check the watchlist** at startup (addresses F-2).
4. **Log rotation & disk monitoring** (addresses F-4).
5. **Fuzz tests for the decoder** (addresses F-6).
6. **Behavioural baselining** for drain detection (addresses F-5).

## 7. Verification checklist

Before treating a deployment as "good enough to matter":

- [ ] `pytest` passes; `ruff` and `mypy` are clean.
- [ ] `.env` and `config/watchlist.yaml` are present locally and absent from git.
- [ ] Container runs as non-root; `docker inspect` shows no added caps.
- [ ] A synthetic large transfer produces an alert in `logs/alerts.jsonl`.
- [ ] Wazuh decodes the alert and escalates severity per rules `100101`–`100103`.
- [ ] Demo credentials rotated; indexer security enabled if networked.
