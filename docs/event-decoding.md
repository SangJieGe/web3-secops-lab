# Event Decoding (M2-A)

How raw Ethereum logs become standardised events, and — just as important — what
that transformation does *not* prove.

## What this module is

`src/web3_secops/event_decoder.py` takes one log object exactly as a JSON-RPC
node returns it and produces one validated, JSON-serialisable event. It is
standalone: no HTTP, no block scanner, no database. Nothing in M1 changed to
accommodate it.

```
raw log (untrusted)  ──►  event_decoder  ──►  DecodedEvent  ──►  .to_dict()
```

Two entry points:

- `decode_log(raw, chain_id)` → `DecodedEvent | None`
  Returns `None` for an unsupported `topic0`; raises `LogDecodeError` when the
  log claims to be a known event but does not match that event's shape.
- `decode_logs(raw_logs, chain_id)` → `list[DecodedEvent]`
  Batch form. Preserves input order, skips unsupported events, and propagates
  structural errors for known events rather than dropping them.

## topic0 — the event's fingerprint

Ethereum logs do not carry event names. A log has an `address`, a list of
`topics`, and a `data` blob. `topics[0]` is the keccak256 hash of the event's
canonical signature string, and it is the only thing that tells you which event
was emitted.

For `Transfer(address,address,uint256)`:

```
keccak256("Transfer(address,address,uint256)")
  = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
```

The signature string has no spaces and uses canonical ABI type names, so
`uint` must be written `uint256` — otherwise the hash differs and the topic will
not match.

Supported here:

| Event | topic0 |
| --- | --- |
| `Transfer(address,address,uint256)` | `0xddf252ad…b3ef` |
| `Approval(address,address,uint256)` | `0x8c5be1e5…b925` |
| `ApprovalForAll(address,address,bool)` | `0x17307eab…6c31` |

## indexed vs data

Solidity splits an event's parameters into two places:

- **indexed** parameters become **topics**, after `topics[0]`. Each indexed value
  occupies one 32-byte topic. An `address` is padded on the left with 12 zero
  bytes, because a topic is always a full word. Topics are cheap to filter on,
  which is why `from` and `to` are indexed: a node can find all transfers to an
  address without scanning every log body.
- **non-indexed** parameters are ABI-encoded into **`data`**, packed one 32-byte
  word each. `data` is not filterable by topic.

An event may index at most three parameters. `Transfer(address,address,uint256)`
indexes the two addresses and leaves `value` in `data` — which is exactly why the
ERC-20 and ERC-721 `Transfer` events, despite sharing a `topic0`, look different
on the wire.

## How ERC-20 and ERC-721 Transfer are told apart

Both declare `Transfer(address,address,uint256)`. ERC-20's third parameter
(`value`) is **not** indexed; ERC-721 adds `tokenId` as a **third indexed**
parameter. The serialised logs therefore differ in shape:

| | topics | data |
| --- | --- | --- |
| ERC-20 `Transfer` | 3 (topic0, from, to) | 32 bytes — `value` |
| ERC-721 `Transfer` | 4 (topic0, from, to, tokenId) | empty (`0x`) |

The decoder uses **topic count as the discriminator**, never `topic0` alone.
A 4-topic log with non-empty `data` matches neither layout, so it is rejected
instead of being guessed into one. `Approval` follows the same rule
(`owner`/`spender`/`value` vs `owner`/`approved`/`tokenId`).

## Approval vs ApprovalForAll

- **`Approval(owner, spender, uint256)`** — grants one specific amount of an
  ERC-20 token, or one specific token id in ERC-721, to a spender. It is
  per-asset.
- **`ApprovalForAll(owner, operator, bool)`** — grants (or revokes) an operator
  blanket control over *every* token the owner holds in that collection. It is
  the riskier primitive: one transaction, all assets.

`ApprovalForAll` is emitted **identically by ERC-721 and ERC-1155**. There is
nothing in the log that distinguishes them, so this decoder reports its standard
as `erc721_or_erc1155`. Treating that log as proof of ERC-721 would be wrong.

## Why a matching layout does not prove ERC standard compliance

This is the single most important caveat in this document.

`topic0` is a hash of a string. Nothing prevents a contract from emitting a
log with the exact `Transfer` layout while implementing none of ERC-20: no
`balanceOf`, no `transfer`, no storage to speak of. The decoder's `standard`
field is a **layout candidate** derived from topic count — an observation about
the bytes, not a certification of the contract.

Downstream code must not treat `standard == "erc20"` as "this is an ERC-20
token". Confirming compliance requires calling the contract's interface, which
this stage does not do.

## Validation rules

Every field of a log is attacker-controlled, so everything is checked and
nothing is repaired. There is no truncation, no zero-padding of short values, no
guessing.

Two properties are worth calling out because they are easy to get wrong:

* **Whole-string matching.** Shapes are validated with `fullmatch`, never
  `^...$`. In Python, `$` also matches immediately *before* a trailing newline,
  so `^0x[0-9a-f]+$` accepts `"0x1\n"` and `int()` would happily turn that into
  `1`. A field must match end to end or it is rejected.
* **Bounded before decoded.** A known event accepts at most 4 topics (3 for
  `ApprovalForAll`), `data` at most 66 raw characters (`0x` + 32 bytes), and a
  quantity at most 64 hex digits. The bounds are applied to the raw strings
  before any list walk or `bytes.fromhex`, so an oversized payload is refused
  instead of being allocated first.

| Field | Rule |
| --- | --- |
| `address` | 42 chars, `0x` + 40 hex → valid 20-byte address |
| `topics[i]` | 66 chars, `0x` + 64 hex → valid 32-byte word |
| `topics` (Transfer / Approval) | at most 4 entries |
| `topics` (ApprovalForAll) | at most 3 entries |
| indexed address | first 12 bytes of the topic must be zero |
| `data` | `0x`-prefixed, even number of hex digits, at most 66 chars |
| `blockNumber`, `transactionIndex`, `logIndex` | canonical JSON-RPC quantity: `0x`-prefixed, at most 64 hex digits, no leading zeroes |
| `blockHash`, `transactionHash` | 32-byte hex |
| `removed` | must be a JSON boolean; `true` is rejected outright |
| ABI `bool` | exactly `0` or `1`; anything else is invalid encoding |
| ERC-20 `data` | exactly 32 bytes |
| ERC-721 `data` | exactly empty |

The `0x` prefix is matched case-sensitively: `0X` is a different string and is
rejected. The hex digits themselves may be upper or lower case, because EIP-55
addresses are mixed-case by design — they are lowercased on input and the output
is always lowercase.

Violations of a **known** event raise `LogDecodeError`. Unknown `topic0` returns
`None` — an unrecognised event is out of scope, not an error.

All addresses and hashes are normalised to lowercase on output. EIP-55 checksum
casing is accepted on input but not verified, because that needs keccak256 and
is not this layer's job.

`removed: true` is rejected because a log removed by a reorg describes history
that no longer exists on the chain. Accepting it would mean reporting a transfer
that, from the chain's point of view, never happened.

Error messages name the offending field but never interpolate the raw log. A
hostile node could otherwise smuggle a secret into an exception that later lands
in a log file.

## Output shape

```json
{
  "schema_version": 1,
  "chain_id": 11155111,
  "standard": "erc20",
  "event_type": "erc20_transfer",
  "event_name": "Transfer",
  "contract_address": "0x1111111111111111111111111111111111111111",
  "block_number": 123456,
  "block_hash": "0xaaaa...",
  "transaction_hash": "0xbbbb...",
  "transaction_index": 2,
  "log_index": 5,
  "args": {
    "from": "0x2222222222222222222222222222222222222222",
    "to": "0x3333333333333333333333333333333333333333",
    "value": "1000000000000000000"
  }
}
```

`value` is a **decimal string**, not a number. A `uint256` reaches
1.15 × 10⁷⁷, far beyond the range where a JSON number stays exact in every
consumer; JavaScript, for instance, would silently round it. Internally the value
is a Python `int` — floats are never used for token amounts.

`approved` in `ApprovalForAll` stays a JSON boolean. `bool` is an `int` subclass
in Python, so the renderer excludes it explicitly rather than turning `true` into
`"True"`.

Metadata numbers (`block_number`, `log_index`, …) remain JSON numbers: they are
bounded by chain height and log index, nowhere near the precision cliff.

### Event types

| `standard` | `event_type` | `args` |
| --- | --- | --- |
| `erc20` | `erc20_transfer` | `from`, `to`, `value` |
| `erc721` | `erc721_transfer` | `from`, `to`, `token_id` |
| `erc20` | `erc20_approval` | `owner`, `spender`, `value` |
| `erc721` | `erc721_approval` | `owner`, `approved`, `token_id` |
| `erc721_or_erc1155` | `approval_for_all` | `owner`, `operator`, `approved` |

## Scope

**Supported:** the five event layouts above, decoded from a log dict you already
have.

**Not supported in M2-A:**

- fetching logs (`eth_getLogs`) — M2-B
- persistence — no SQLite event table yet
- `token decimals` / `symbol` / price or USD valuation
- verifying that a contract actually implements a standard
- anonymous events (logs with no `topic0`)
- non-ERC event signatures
- attack detection or alerting of any kind

This is a decoder, not an event monitoring system.

## Testing

`tests/test_event_decoder.py` — 134 tests, fully offline, no socket opened.

Coverage includes all five valid layouts, mint/burn via the zero address,
`uint256` maximum values, lowercase normalisation, and the rejection paths:
wrong `topic0`, wrong topic count, wrong topic length, dirty indexed-address
padding, wrong `data` length, odd-length `data`, illegal `bool` encoding, illegal
address/hash/quantity, `removed: true`, missing fields, and layout mismatches for
known events. Batch behaviour is covered for ordering, unknown-event skipping,
and error propagation.

Two further groups pin the input-validation boundary: a trailing newline or any
surrounding whitespace on an address, hash, topic, quantity or `data` field is
rejected even when the string's length still looks correct, `0X` prefixes are
rejected, and oversized inputs (an absurd topic list, a kilobyte of `data`, a
65-digit quantity) are refused before conversion while all five legitimate
layouts still decode.

The rejection paths were verified by mutation: disabling each check in turn
(`removed`, `bool` range, address padding, quantity leading zeroes, the 3-vs-4
topic discriminator) makes the corresponding tests fail, which confirms the
tests constrain behaviour rather than merely observing it. The same holds for
this round: reverting `fullmatch` to `match` + `$` and dropping the size bounds
fails 12 tests, so the fixes are pinned rather than assumed.
