# Incident Response Runbooks

Practical runbooks for the incidents this lab is built to surface. Each follows
**Detect → Triage → Contain → Eradicate → Recover → Learn**. Remember: this lab
*detects*; response actions are performed by humans (and the operator's existing
multi-sig / governance processes).

> **Golden rule:** confirm finality (`block_number` + confirmations) before acting on
> a high-severity alert. On L2s / fast chains, wait for the chain's finality horizon.

---

## IR-1: Rapid drain from a watched address (`rapid-drain`)

**Signal:** `rule = rapid-drain`, severity `critical`. Multiple outbound txs from a
watched address inside the configured window.

### Detect
- Wazuh rule `100110` (level 13) fires; dashboard shows the address and block.

### Triage (first 5 minutes)
1. Open the tx hashes from the `context` / alert history. Confirm on a block explorer.
2. Identify the destination addresses. Are they known/expected (e.g. a rebalancing
   multi-sig) or unknown?
3. Check whether the source address's signer set is compromised (phishing, key leak,
   malicious dApp approval).

### Contain
- If unauthorized: **revoke approvals** the compromised key granted, and move
  remaining assets via the multi-sig's recovery path.
- If a hot wallet: drain remaining funds to a cold/secure address.
- Notify signers out-of-band (never over the same channel that may be compromised).

### Eradicate & Recover
- Rotate all keys the compromised signer had access to.
- Re-establish monitoring; verify the watchlist still covers all critical addresses.

### Learn
- Was the drain detectable earlier (e.g. an `Approval` event that should have been on
  the watchlist)? Add the token/approval surface to `config/watchlist.yaml`.

---

## IR-2: Interaction with a flagged contract (`flagged-interaction`)

**Signal:** `rule = flagged-interaction`, severity `high`/`critical`.

### Triage
1. Which address initiated it? Was it a signer, a bot, or an attacker?
2. What is the flagged contract (mixer, sanctioned entity, known-honeypot)?
3. Did value transfer, or was it a zero-value interaction (a probe)?

### Contain
- If a signer initiated it: treat the signer as potentially compromised. Freeze the
  multi-sig's signing flow pending review.
- If a bot: pause the bot and audit its allow-list logic.

### Learn
- Add the offending address to `flagged_contracts` if it is a new adversary.
- Consider adding a *pre*-interaction guard (a policy bot) so flagged contracts are
  blocked before signing, not just alerted after.

---

## IR-3: Watched address activity (`watched-inbound` / `watched-outbound`)

**Signal:** any activity on a watchlist address. Often benign — this is the "eyes-on"
layer.

### Triage
1. Is the movement expected? Cross-check treasury plans, payroll, rebalancing.
2. For inbound: is it an unsolicited (possibly dusting / poisoning) transfer?
3. For outbound: does the destination match a known counterparty?

### Contain / Learn
- Benign → document and close.
- Unexpected inbound from an unknown source → consider **address-poisoning**; verify any
  "similar-looking" address before a future send.

---

## IR-4: Large native transfer (`large-transfer`)

**Signal:** `rule = large-transfer`, severity `medium`.

### Triage
- Above what USD threshold does this matter? (Set `large_transfer_usd` in the watchlist
  and enable price enrichment.)
- Is the sender a known exchange / bridge / treasury?

### Learn
- Tune `min_notable_value` to reduce noise; the goal is signal, not a firehose.

---

## IR-5: Token movement on watched address (`token-movement`)

**Signal:** decoded `Transfer` event involving a watched address.

### Triage
- Token + amount + counterparty. Is the token a new/unknown asset (possible airdrop
  scam / fake token)?
- Verify the token contract address against a trusted list.

### Learn
- Track known token contracts in `contracts/` and the watchlist to enrich future alerts.

---

## Escalation matrix

| Severity | Wazuh level | Page? | Response time |
|----------|-------------|-------|---------------|
| critical | 12–13 | yes | immediate |
| high | 10 | yes (business hours + on-call) | < 1 h |
| medium | 8 | no (queue) | same day |
| low | 5 | no | batched review |

## Post-incident

1. Write a short blameless post-mortem: timeline, impact, root cause, actions.
2. Update detection: add the missed pattern as a rule / watchlist entry.
3. Re-run the threat model if the incident revealed a new trust-boundary issue.
