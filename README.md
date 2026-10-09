# Web3 SecOps Lab

> A hands-on lab for **Web3 security operations**: on-chain event monitoring, threat detection, and Wazuh-based alerting.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

## What is this?

`web3-secops-lab` is a small, readable toolkit that watches EVM chains for security-relevant
activity and surfaces it into a traditional SOC pipeline (Wazuh). It is designed as a
**learning + reference lab**: every module is small enough to read end-to-end, yet the
pipeline is realistic enough to detect real things.

Typical use cases:

- Watch a list of sensitive addresses (treasury, multisig, admin EOAs) and alert on any movement.
- Scan blocks for large native-token transfers.
- Decode contract events and flag interactions with known-bad or high-privilege contracts.
- Feed structured alerts into Wazuh for correlation, dashboards, and incident response.

## Architecture

```
                    +-------------------+
                    |   EVM JSON-RPC    |
                    | (Eth/Base/Arb...) |
                    +---------+---------+
                              |
                     rpc_client.py  (retry, rate-limit, batching)
                              |
                     block_scanner.py  (cursor, backfill, dedup)
                              |
                     event_decoder.py  (ABI decode, topic match)
                              |
                        detector.py    (rules -> findings)
                              |
                        main.py        (loop + alert sink)
                              |
                 logs/alerts.jsonl  --(wazuh agent)-->  Wazuh manager
                                                          |
                                                    decoders + rules
                                                          |
                                                     dashboards / IR
```

See [`docs/architecture.md`](docs/architecture.md) for a detailed walkthrough.

## Project layout

```
web3-secops-lab/
├── src/web3_secops/
│   ├── rpc_client.py      # JSON-RPC transport: retries, batching, rate limit
│   ├── block_scanner.py   # Block iteration + persistent cursor + dedup
│   ├── event_decoder.py   # Log/event ABI decoding
│   ├── detector.py        # Detection rules over decoded activity
│   └── main.py            # Entry point / orchestration loop
├── config/
│   └── watchlist.example.yaml
├── tests/
│   ├── fixtures/
│   ├── test_rpc_client.py
│   ├── test_event_decoder.py
│   └── test_detector.py
├── deploy/
│   └── docker-compose.yml
├── wazuh/
│   ├── decoders/
│   └── rules/
├── contracts/             # Sample contracts / ABIs used in tests & demos
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── incident-response.md
│   └── security-assessment.md
├── .env.example
├── .gitignore
├── README.md
└── pyproject.toml
```

## Quick start

```bash
# 1. Clone
git clone https://github.com/<you>/web3-secops-lab.git
cd web3-secops-lab

# 2. Configure
cp .env.example .env
cp config/watchlist.example.yaml config/watchlist.yaml
# edit .env and watchlist.yaml with your RPC + addresses

# 3. Install (uv or pip)
uv sync           # or: pip install -e ".[dev]"

# 4. Run tests
pytest -q

# 5. Run the scanner
python -m web3_secops.main
```

### Run with Docker

```bash
cd deploy
docker compose up --build
```

## Configuration

Everything is driven by `.env` (secrets/endpoints) and `config/watchlist.yaml`
(what to watch). See `.env.example` for all knobs and
[`config/watchlist.example.yaml`](config/watchlist.example.yaml) for the schema.

## Security posture

This project is **read-only by design**:

- It never holds private keys and never signs or broadcasts transactions.
- All RPC calls are read-only (`eth_getLogs`, `eth_getBlockByNumber`, `eth_call`, ...).
- Alerts are pushed to a local file / Wazuh agent — no external write actions.

See [`docs/threat-model.md`](docs/threat-model.md) and
[`docs/security-assessment.md`](docs/security-assessment.md) for the full analysis.

## Documentation

| Doc | Contents |
|-----|----------|
| [architecture.md](docs/architecture.md) | Component design & data flow |
| [threat-model.md](docs/threat-model.md) | Assets, adversaries, STRIDE-style analysis |
| [incident-response.md](docs/incident-response.md) | Runbooks for common on-chain incidents |
| [security-assessment.md](docs/security-assessment.md) | Self-assessment, gaps, hardening roadmap |

## Roadmap

- [ ] Multi-chain concurrent scanning
- [ ] Wazuh decoder/rule pack (in progress)
- [ ] Anomaly scoring (baseline + deviation)
- [ ] Alert enrichment (token metadata, ENS, labels)
- [ ] Sigma-style portable detection rules

## Contributing

Issues and PRs welcome. Please run `pytest` and `ruff` before submitting.

## License

MIT — see [LICENSE](LICENSE).
