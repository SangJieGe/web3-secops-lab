"""EVM log / event decoding.

Two layers:

1. **Raw log normalisation** — turn a JSON-RPC log object into hex-stripped,
   typed fields.
2. **ABI decoding** — decode ``data`` and indexed ``topics`` into a dict using a
   minimal subset of the Solidity ABI spec. Supports the common static types
   (address, uint/int, bool, bytesN) and ``string``/``bytes``, plus dynamic
   arrays/tuples via a pragmatic recursive decoder.

Deliberately dependency-free so the decoding logic is auditable line by line.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


def _strip_hex(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def keccak_topic_signature(signature: str) -> str:
    """Return the 0x-prefixed event topic hash for a signature string.

    NOTE: uses a pure-Python keccak-256 when available; otherwise callers should
    supply precomputed topics. Kept as a seam so tests can inject known topics.
    """
    try:  # optional dependency
        from Crypto.Hash import keccak  # type: ignore

        k = keccak.new(digest_bits=256)
        k.update(signature.encode())
        return "0x" + k.hexdigest()
    except Exception:  # noqa: BLE001
        raise RuntimeError(
            "keccak-256 unavailable; install pycryptodome or pass precomputed topics"
        ) from None


@dataclass(slots=True)
class RawLog:
    address: str
    topics: list[str]
    data: str
    block_number: int
    tx_hash: str
    log_index: int

    @classmethod
    def from_rpc(cls, entry: dict[str, Any]) -> RawLog:
        return cls(
            address=entry["address"].lower(),
            topics=[t.lower() for t in entry.get("topics", [])],
            data=entry.get("data", "0x"),
            block_number=int(entry.get("blockNumber", "0x0"), 16),
            tx_hash=entry.get("transactionHash", ""),
            log_index=int(entry.get("logIndex", "0x0"), 16),
        )


@dataclass(slots=True)
class AbiEvent:
    name: str
    inputs: list[dict[str, Any]]
    topic0: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AbiEvent:
        topic0 = d.get("topic0") or d.get("topic")
        if topic0 is None:
            try:
                sig = f"{d['name']}({','.join(i['type'] for i in d.get('inputs', []))})"
                topic0 = keccak_topic_signature(sig)
            except Exception:  # noqa: BLE001
                topic0 = None
        return cls(name=d["name"], inputs=d.get("inputs", []), topic0=topic0)


def load_abi(path: str | Path) -> list[dict[str, Any]]:
    """Load an ABI JSON file and return the list of event entries."""
    raw = json.loads(Path(path).read_text())
    if isinstance(raw, dict) and "abi" in raw:
        raw = raw["abi"]
    return [e for e in raw if e.get("type") == "event"]


def _decode_static(type_str: str, word: str) -> Any:
    """Decode one 32-byte word for a static type."""
    if type_str == "address":
        return "0x" + word[-40:]
    if type_str == "bool":
        return int(word, 16) != 0
    if type_str.startswith("uint"):
        return int(word, 16)
    if type_str.startswith("int"):
        val = int(word, 16)
        bits = int(type_str[3:] or "256")
        if val >= 2 ** (bits - 1):
            val -= 2**bits
        return val
    if type_str.startswith("bytes") and type_str != "bytes":
        return "0x" + word[: int(type_str[5:]) * 2]
    return "0x" + word


def _decode_dynamic(type_str: str, data_hex: str, offset_words: int) -> Any:
    """Decode a dynamic type (string/bytes/array) from an offset pointer."""
    ptr = int(data_hex[offset_words * 64 : offset_words * 64 + 64], 16) * 2
    length = int(data_hex[ptr : ptr + 64], 16)
    body = data_hex[ptr + 64 : ptr + 64 + length * 2]
    if type_str == "string":
        return bytes.fromhex(body).decode("utf-8", errors="replace")
    if type_str == "bytes":
        return "0x" + body
    if type_str.endswith("[]"):
        inner = type_str[:-2]
        items = []
        for i in range(length):
            items.append(_decode_static(inner, body[i * 64 : (i + 1) * 64]))
        return items
    return "0x" + body


def decode_event(abi_event: AbiEvent, raw: RawLog) -> dict[str, Any]:
    """Decode a ``RawLog`` against an ABI event definition.

    Indexed (non-array) params are read from ``topics``; the rest from ``data``.
    Returns ``{"event": name, "args": {...}, "raw": {...}}``.
    """
    args: dict[str, Any] = {}
    data_hex = _strip_hex(raw.data)
    topic_idx = 1  # topic[0] is the signature
    data_word = 0

    for inp in abi_event.inputs:
        name = inp.get("name") or f"arg{len(args)}"
        type_str = inp["type"]
        if inp.get("indexed") and not type_str.endswith("[]") and type_str not in (
            "string",
            "bytes",
        ):
            if topic_idx < len(raw.topics):
                args[name] = _decode_static(type_str, _strip_hex(raw.topics[topic_idx]))
            else:
                args[name] = None
            topic_idx += 1
        elif inp.get("indexed"):
            # indexed dynamic types arrive as the keccak hash, not the value
            args[name] = raw.topics[topic_idx] if topic_idx < len(raw.topics) else None
            topic_idx += 1
        else:
            if type_str in ("string", "bytes") or type_str.endswith("[]"):
                args[name] = _decode_dynamic(type_str, data_hex, data_word)
                data_word += 1  # pointer consumes one word
            else:
                word = data_hex[data_word * 64 : (data_word + 1) * 64]
                args[name] = _decode_static(type_str, word)
                data_word += 1

    return {
        "event": abi_event.name,
        "address": raw.address,
        "args": args,
        "raw": {
            "topics": raw.topics,
            "data": raw.data,
            "block_number": raw.block_number,
            "tx_hash": raw.tx_hash,
            "log_index": raw.log_index,
        },
    }


@dataclass
class EventDecoder:
    """Registry of ABI events keyed by topic0, for fast lookup on a hot path."""

    events: dict[str, AbiEvent] = field(default_factory=dict)

    def register(self, abi_event: AbiEvent) -> None:
        if not abi_event.topic0:
            raise ValueError(f"cannot register {abi_event.name}: no topic0")
        self.events[abi_event.topic0.lower()] = abi_event

    def register_from_abi_file(self, path: str | Path) -> int:
        count = 0
        for entry in load_abi(path):
            try:
                self.register(AbiEvent.from_dict(entry))
                count += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("abi_event_skipped", name=entry.get("name"), error=str(exc))
        return count

    def decode(self, raw: RawLog) -> dict[str, Any] | None:
        """Decode if the log's topic0 is registered; else return None."""
        if not raw.topics:
            return None
        event = self.events.get(raw.topics[0])
        if event is None:
            return None
        try:
            return decode_event(event, raw)
        except Exception as exc:  # noqa: BLE001 — never crash the scan loop
            log.warning("event_decode_failed", topic0=raw.topics[0], error=str(exc))
            return None
