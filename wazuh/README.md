# Wazuh integration

Decoders and rules that turn Web3 SecOps Lab's JSON-lines alerts into first-class
Wazuh detections.

## Files

- `decoders/web3_secops_decoders.xml` — parses our alert JSON, extracts
  `rule.id`, `rule.severity`, `rule.title`, `web3.address`, `web3.tx_hash`,
  `web3.block_number`.
- `rules/web3_secops_rules.xml` — rule IDs **100100–100199** reserved for this lab.
  Maps severity → Wazuh level and defines rule-specific detections
  (`rapid-drain` → 13, `flagged-interaction` → 12, etc.).

## Install (manager)

```bash
# On the Wazuh manager host (or inside the manager container)
cp decoders/web3_secops_decoders.xml /var/ossec/etc/decoders/
cp rules/web3_secops_rules.xml        /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/decoders/web3_secops_decoders.xml \
                  /var/ossec/etc/rules/web3_secops_rules.xml
/var/ossec/bin/wazuh-logtest   # validate, then:
systemctl restart wazuh-manager
```

With the provided `deploy/docker-compose.yml`, the `decoders/` and `rules/` dirs are
mounted read-only into the manager at the paths above.

## Getting alerts in

Two options:

1. **Local agent (recommended):** install a Wazuh agent where the scanner runs and add
   to `ossec.conf`:

   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/app/logs/alerts.jsonl</location>
   </localfile>
   ```

2. **Agentless / forwarder:** ship `logs/alerts.jsonl` to the manager via your standard
   log pipeline (Filebeat, Fluent Bit, syslog).

## Validate

```bash
# Feed a sample alert through logtest and check the decode + rule level
echo '{"rule":"rapid-drain","severity":"critical","title":"Rapid outbound drain from Treasury","chain_id":1,"block_number":19000000,"tx_hash":"0xabc","context":{"address":"0x1111111111111111111111111111111111111111"}}' \
  | /var/ossec/bin/wazuh-logtest
```

Expected: decoded as `web3-secops`, matched by rule `100110` (level 13).

## Severity → level

| Lab severity | Wazuh rule | Level |
|--------------|------------|-------|
| low | 100100 | 5 |
| medium | 100101 | 8 |
| high | 100102 | 10 |
| critical | 100103 | 12 |
| rapid-drain | 100110 | 13 |
| flagged-interaction | 100111 | 12 |
| watched-* | 100112 | 10 |
| large-transfer | 100113 | 8 |
