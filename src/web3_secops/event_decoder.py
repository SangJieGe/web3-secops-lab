"""Decode raw Ethereum JSON-RPC log objects into standardised events.

This module is deliberately standalone. It knows nothing about HTTP, the block
scanner, or SQLite: it takes one log dict as the node would serialise it and
either returns a validated :class:`DecodedEvent` or raises
:class:`LogDecodeError`. That keeps the trust boundary narrow and makes the
decoder trivial to test offline.

Trust model
-----------
Every field of a raw log is attacker-controlled. A node — or a contract — can
put anything in ``topics``, ``data`` or the surrounding metadata. Nothing here
attempts to repair bad input: no truncation, no padding, no guessing. A value
that does not match its expected shape is rejected, because a malformed log is
evidence, not something to coerce into looking valid.

What "decoded" does *not* mean
------------------------------
A log whose layout matches an ERC-20 ``Transfer`` does **not** prove the
emitting contract implements ERC-20. ``topic0`` is a hash of a signature and
anyone can emit one. The ``standard`` field is therefore a *layout candidate*
derived purely from the topic count, never a certification. ``ApprovalForAll``
is emitted identically by ERC-721 and ERC-1155, so it is labelled
``erc721_or_erc1155`` rather than being attributed to either one.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

__all__ = [
    "EVENT_SIGNATURES",
    "SCHEMA_VERSION",
    "DecodedEvent",
    "LogDecodeError",
    "decode_log",
    "decode_logs",
]


SCHEMA_VERSION: Final[int] = 1

#: ``topic0`` values this decoder understands. The key is the keccak256 hash of
#: the canonical event signature; the value is the human-readable signature used
#: in error messages and docs.
EVENT_SIGNATURES: Final[Mapping[str, str]] = {
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef": (
        "Transfer(address,address,uint256)"
    ),
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925": (
        "Approval(address,address,uint256)"
    ),
    "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31": (
        "ApprovalForAll(address,address,bool)"
    ),
}

TRANSFER_TOPIC0: Final[str] = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL_TOPIC0: Final[str] = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL_TOPIC0: Final[str] = (
    "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
)

#: Sentinel used for the zero address, which has a real meaning: mint (``from``)
#: and burn (``to``). It is kept verbatim, not dropped, because a transfer *from*
#: the zero address is how ERC-20/721 signal a mint.
ZERO_ADDRESS: Final[str] = "0x0000000000000000000000000000000000000000"

_MAX_UINT256: Final[int] = (1 << 256) - 1

# Hex string shapes are validated with ``fullmatch``, never ``match`` + ``$``.
#
# ``re``'s ``$`` also matches immediately *before* a trailing newline, so
# ``re.match(r"^0x[0-9a-f]+$", "0x1\n")`` succeeds and ``int()``/``bytes.fromhex``
# would then quietly accept a field a node never sent. ``fullmatch`` anchors at
# the real end of the string, so ``"0x1\n"`` fails as it must.
#
# Only the literal ``0x`` prefix is lowercase — that is the JSON-RPC spelling, and
# ``0X`` is rejected as a different string. The hex digits themselves accept either
# case, because EIP-55 addresses are mixed-case by design; callers lowercase the
# digits before matching, but never the prefix.
_HEX_DIGITS_RE = re.compile(r"[0-9a-f]+")
_HEX_DIGITS_OPTIONAL_RE = re.compile(r"[0-9a-f]*")

#: JSON-RPC QUANTITY: no leading zeroes unless the value is zero itself.
_CANONICAL_QUANTITY_RE = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)")

#: Upper bounds applied *before* any conversion or allocation.
MAX_TOPICS_TRANSFER_APPROVAL: Final[int] = 4
MAX_TOPICS_APPROVAL_FOR_ALL: Final[int] = 3
MAX_DATA_HEX_CHARS: Final[int] = 66  # "0x" + 32 bytes
MAX_QUANTITY_HEX_DIGITS: Final[int] = 64


class LogDecodeError(ValueError):
    """A log is structurally invalid for the event its ``topic0`` claims.

    Only *known* events raise this. An unknown ``topic0`` is not an error — it is
    simply not something this decoder handles, and :func:`decode_log` returns
    ``None`` for it.

    The message describes what was wrong with a field. It never interpolates the
    raw log wholesale: a hostile node could otherwise smuggle a secret into an
    exception that later lands in a log file.
    """


# ---------------------------------------------------------------------------
# Primitive validation
# ---------------------------------------------------------------------------
def _fail(field_name: str, detail: str) -> LogDecodeError:
    """Build an error that names the offending field but not its raw value."""
    return LogDecodeError(f"{field_name}: {detail}")


def _require_mapping(raw: Any) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise LogDecodeError(f"log must be a JSON object, got {type(raw).__name__}")
    return raw


def _require_address(value: Any, field_name: str) -> str:
    """Validate a 20-byte address and return it lowercased.

    Checksum casing is accepted on input and normalised away, since the EIP-55
    checksum cannot be verified without keccak256 and doing so is not this
    layer's job. Shape and length are enforced strictly, and ``fullmatch`` means
    a trailing newline cannot ride along inside a 42-character string.
    """
    if not isinstance(value, str):
        raise _fail(field_name, "must be a string")
    if len(value) != 42:
        raise _fail(field_name, f"must be 42 chars (0x + 40 hex), got {len(value)}")
    if not value.startswith("0x"):
        raise _fail(field_name, "must be 0x-prefixed")
    if not _HEX_DIGITS_RE.fullmatch(value[2:].lower()):
        raise _fail(field_name, "must be hex-encoded")
    return value.lower()


def _require_hash32(value: Any, field_name: str) -> str:
    """Validate a 32-byte hash/topic and return it lowercased."""
    if not isinstance(value, str):
        raise _fail(field_name, "must be a string")
    if len(value) != 66:
        raise _fail(field_name, f"must be 66 chars (0x + 64 hex), got {len(value)}")
    if not value.startswith("0x"):
        raise _fail(field_name, "must be 0x-prefixed")
    if not _HEX_DIGITS_RE.fullmatch(value[2:].lower()):
        raise _fail(field_name, "must be hex-encoded")
    return value.lower()


def _require_quantity(raw: Mapping[str, Any], field_name: str) -> int:
    """Decode a JSON-RPC QUANTITY (``0x``-prefixed hex integer).

    JSON-RPC quantity encoding forbids leading zeroes except for the value zero
    itself, and rejects ``0x`` with no digits. The whole string must match, so a
    trailing newline, trailing space or any other stray character is a rejection,
    not something ``int()`` gets to ignore.
    """
    value = raw.get(field_name)
    if not isinstance(value, str):
        raise _fail(field_name, "must be a string")
    if not value.startswith("0x"):
        raise _fail(field_name, "must be 0x-prefixed")
    digits = value[2:]
    # Bound the width before doing anything with the digits.
    if len(digits) > MAX_QUANTITY_HEX_DIGITS:
        raise _fail(
            field_name,
            f"exceeds {MAX_QUANTITY_HEX_DIGITS} hex digits, got {len(digits)}",
        )
    if not digits:
        raise _fail(field_name, "must contain at least one hex digit")
    if not _CANONICAL_QUANTITY_RE.fullmatch("0x" + digits.lower()):
        # Covers non-hex characters, leading zeroes, and stray whitespace alike.
        raise _fail(field_name, "must be a canonical hex quantity without leading zeroes")
    return int(digits, 16)


def _require_hex_data(value: Any, field_name: str, *, max_hex_chars: int | None = None) -> bytes:
    """Validate ``0x``-prefixed, even-length hex data and return its bytes.

    ``max_hex_chars`` bounds the *raw string* length before any conversion, so an
    oversized payload is rejected without first decoding it into memory.
    """
    if not isinstance(value, str):
        raise _fail(field_name, "must be a string")
    if not value.startswith("0x"):
        raise _fail(field_name, "must be 0x-prefixed")
    if max_hex_chars is not None and len(value) > max_hex_chars:
        raise _fail(field_name, f"exceeds {max_hex_chars} chars, got {len(value)}")
    digits = value[2:]
    if len(digits) % 2 != 0:
        raise _fail(field_name, f"must have an even number of hex digits, got {len(digits)}")
    if not _HEX_DIGITS_OPTIONAL_RE.fullmatch(digits.lower()):
        raise _fail(field_name, "must be hex-encoded")
    return bytes.fromhex(digits)


def _require_bool_field(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(field_name, "must be a JSON boolean")
    return value


def _decode_indexed_address(topic: str, field_name: str) -> str:
    """Decode an ABI-encoded indexed ``address`` topic.

    An indexed address occupies a full 32-byte word: 12 bytes of zero padding
    followed by the 20-byte address. If the padding is not zero the topic is not
    a valid address encoding — it could be a different type entirely (a ``bytes32``
    or a uint), so it is rejected rather than truncated.
    """
    if len(topic) != 66:
        raise _fail(field_name, "topic must be 32 bytes")
    body = topic[2:]
    padding, payload = body[:24], body[24:]
    if padding != "0" * 24:
        raise _fail(
            field_name,
            "indexed address must be zero-padded in its first 12 bytes",
        )
    return "0x" + payload


def _decode_uint256_word(raw_data: bytes, field_name: str) -> int:
    """Decode a single 32-byte ABI ``uint256`` word."""
    if len(raw_data) != 32:
        raise _fail(field_name, f"expected exactly 32 bytes, got {len(raw_data)}")
    return int.from_bytes(raw_data, "big")


def _decode_bool_word(raw_data: bytes, field_name: str) -> bool:
    """Decode a single 32-byte ABI ``bool`` word.

    ABI encodes ``bool`` as a full word that must be exactly 0 or 1. Anything
    else is invalid encoding, not a truthy/falsy value to be interpreted.
    """
    value = _decode_uint256_word(raw_data, field_name)
    if value not in (0, 1):
        raise _fail(field_name, f"bool must be encoded as 0 or 1, got {value}")
    return bool(value)


# ---------------------------------------------------------------------------
# Decoded event
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DecodedEvent:
    """A validated, standardised chain event.

    ``args`` holds decoded values: addresses as lowercase ``0x`` strings,
    integers as Python ``int``. :meth:`to_dict` is the JSON boundary and renders
    integers as decimal *strings*, because ``uint256`` exceeds the range where a
    JSON number stays exact in every consumer and floats are never acceptable
    for token amounts.
    """

    schema_version: int
    chain_id: int
    standard: str
    event_type: str
    event_name: str
    contract_address: str
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int
    args: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Render as a JSON-serialisable dict.

        Every ``int`` in ``args`` becomes a decimal string. Metadata numbers
        (``block_number``, ``log_index``, …) stay as JSON numbers: they are
        bounded by chain height and index, nowhere near the precision cliff.
        """
        rendered_args: dict[str, Any] = {}
        for key, value in self.args.items():
            # ``bool`` is an ``int`` subclass, so it must be excluded explicitly:
            # ``approved: True`` is a JSON boolean, not the string "True". Only
            # genuine integers (uint256 amounts) become decimal strings.
            if isinstance(value, bool):
                rendered_args[key] = value
            elif isinstance(value, int):
                rendered_args[key] = str(value)
            else:
                rendered_args[key] = value
        return {
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "standard": self.standard,
            "event_type": self.event_type,
            "event_name": self.event_name,
            "contract_address": self.contract_address,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "transaction_hash": self.transaction_hash,
            "transaction_index": self.transaction_index,
            "log_index": self.log_index,
            "args": rendered_args,
        }


# ---------------------------------------------------------------------------
# Raw log envelope
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _LogEnvelope:
    """The validated, non-topic parts of a raw log."""

    address: str
    topics: tuple[str, ...]
    data: bytes
    block_number: int
    block_hash: str
    transaction_hash: str
    transaction_index: int
    log_index: int


def _bound_topics(raw: Mapping[str, Any], max_topics: int) -> list[Any]:
    """Reject an oversized ``topics`` list *before* validating its members.

    Validation of each topic allocates a lowercased copy, so a node returning
    10,000 topics would cost 10,000 validations before the event layout check
    ever ran. Bounding the list first keeps the cost of a hostile log constant.
    """
    topics_raw = raw.get("topics")
    if not isinstance(topics_raw, (list, tuple)):
        raise _fail("topics", "must be a list")
    if len(topics_raw) > max_topics:
        raise _fail("topics", f"expected at most {max_topics} entries, got {len(topics_raw)}")
    return list(topics_raw)


def _parse_envelope(raw: Mapping[str, Any], *, max_topics: int) -> _LogEnvelope:
    """Validate every non-topic field of the raw log.

    Field order in the error messages follows the order an operator would check
    them, so the first failure reported is the most structurally fundamental one.

    ``max_topics`` is the bound for the event being decoded: 4 for
    Transfer/Approval, 3 for ApprovalForAll. The bound is enforced before member
    validation, and ``data`` is bounded by raw character count before decoding.
    """
    address = _require_address(raw.get("address"), "address")

    topics = tuple(
        _require_hash32(t, f"topics[{i}]") for i, t in enumerate(_bound_topics(raw, max_topics))
    )

    data = _require_hex_data(raw.get("data"), "data", max_hex_chars=MAX_DATA_HEX_CHARS)

    block_number = _require_quantity(raw, "blockNumber")
    block_hash = _require_hash32(raw.get("blockHash"), "blockHash")
    transaction_hash = _require_hash32(raw.get("transactionHash"), "transactionHash")
    transaction_index = _require_quantity(raw, "transactionIndex")
    log_index = _require_quantity(raw, "logIndex")

    removed = _require_bool_field(raw.get("removed"), "removed")
    if removed:
        # A log removed by a reorg is not an event that happened. Accepting it
        # would mean reporting history that no longer exists on the chain.
        raise _fail("removed", "log has been removed by a reorg and is not an event")

    return _LogEnvelope(
        address=address,
        topics=topics,
        data=data,
        block_number=block_number,
        block_hash=block_hash,
        transaction_hash=transaction_hash,
        transaction_index=transaction_index,
        log_index=log_index,
    )


# ---------------------------------------------------------------------------
# Per-event decoders
# ---------------------------------------------------------------------------
def _decode_transfer(env: _LogEnvelope, chain_id: int) -> DecodedEvent:
    """Dispatch ``Transfer`` by topic count; the layout *is* the discriminator.

    ERC-20 and ERC-721 share ``topic0`` and are told apart only by shape:
    ERC-20 carries ``value`` in ``data`` with 3 topics, ERC-721 carries
    ``tokenId`` as a 4th indexed topic with empty ``data``. A 4-topic log with
    non-empty data matches neither, and is rejected rather than guessed at.
    """
    if len(env.topics) == 3:
        # ERC-20: from, to indexed; value in data.
        if len(env.data) != 32:
            raise _fail(
                "data",
                f"ERC-20 Transfer requires exactly 32 bytes of value, got {len(env.data)}",
            )
        args = {
            "from": _decode_indexed_address(env.topics[1], "topics[1]"),
            "to": _decode_indexed_address(env.topics[2], "topics[2]"),
            "value": _decode_uint256_word(env.data, "data"),
        }
        standard, event_type = "erc20", "erc20_transfer"

    elif len(env.topics) == 4:
        # ERC-721: from, to, tokenId all indexed; data must be empty.
        if len(env.data) != 0:
            raise _fail(
                "data",
                f"ERC-721 Transfer requires empty data, got {len(env.data)} bytes; "
                "this log matches neither ERC-20 nor ERC-721 layout",
            )
        args = {
            "from": _decode_indexed_address(env.topics[1], "topics[1]"),
            "to": _decode_indexed_address(env.topics[2], "topics[2]"),
            "token_id": _decode_indexed_uint(env.topics[3], "topics[3]"),
        }
        standard, event_type = "erc721", "erc721_transfer"

    else:
        raise _fail(
            "topics",
            f"Transfer must have 3 (ERC-20) or 4 (ERC-721) topics, got {len(env.topics)}; "
            "this log matches neither layout",
        )

    return _build(env, chain_id, standard, event_type, "Transfer", args)


def _decode_approval(env: _LogEnvelope, chain_id: int) -> DecodedEvent:
    """Dispatch ``Approval`` by topic count, same discriminator as Transfer."""
    if len(env.topics) == 3:
        if len(env.data) != 32:
            raise _fail(
                "data",
                f"ERC-20 Approval requires exactly 32 bytes of value, got {len(env.data)}",
            )
        args = {
            "owner": _decode_indexed_address(env.topics[1], "topics[1]"),
            "spender": _decode_indexed_address(env.topics[2], "topics[2]"),
            "value": _decode_uint256_word(env.data, "data"),
        }
        standard, event_type = "erc20", "erc20_approval"

    elif len(env.topics) == 4:
        if len(env.data) != 0:
            raise _fail(
                "data",
                f"ERC-721 Approval requires empty data, got {len(env.data)} bytes; "
                "this log matches neither ERC-20 nor ERC-721 layout",
            )
        args = {
            "owner": _decode_indexed_address(env.topics[1], "topics[1]"),
            "approved": _decode_indexed_address(env.topics[2], "topics[2]"),
            "token_id": _decode_indexed_uint(env.topics[3], "topics[3]"),
        }
        standard, event_type = "erc721", "erc721_approval"

    else:
        raise _fail(
            "topics",
            f"Approval must have 3 (ERC-20) or 4 (ERC-721) topics, got {len(env.topics)}; "
            "this log matches neither layout",
        )

    return _build(env, chain_id, standard, event_type, "Approval", args)


def _decode_approval_for_all(env: _LogEnvelope, chain_id: int) -> DecodedEvent:
    """Decode ``ApprovalForAll``, which ERC-721 and ERC-1155 share verbatim.

    Because both standards emit an identical log, the event cannot attribute the
    contract to one of them. The standard is reported as ``erc721_or_erc1155``
    so downstream code cannot accidentally treat a compatible layout as proof.
    """
    if len(env.topics) != 3:
        raise _fail(
            "topics",
            f"ApprovalForAll requires exactly 3 topics, got {len(env.topics)}",
        )
    if len(env.data) != 32:
        raise _fail(
            "data",
            f"ApprovalForAll requires exactly 32 bytes of bool, got {len(env.data)}",
        )

    args = {
        "owner": _decode_indexed_address(env.topics[1], "topics[1]"),
        "operator": _decode_indexed_address(env.topics[2], "topics[2]"),
        "approved": _decode_bool_word(env.data, "data"),
    }
    return _build(env, chain_id, "erc721_or_erc1155", "approval_for_all", "ApprovalForAll", args)


def _decode_indexed_uint(topic: str, field_name: str) -> int:
    """Decode an indexed ``uint256`` topic (e.g. an ERC-721 ``tokenId``)."""
    if len(topic) != 66:
        raise _fail(field_name, "topic must be 32 bytes")
    return int(topic[2:], 16)


def _build(
    env: _LogEnvelope,
    chain_id: int,
    standard: str,
    event_type: str,
    event_name: str,
    args: dict[str, Any],
) -> DecodedEvent:
    return DecodedEvent(
        schema_version=SCHEMA_VERSION,
        chain_id=chain_id,
        standard=standard,
        event_type=event_type,
        event_name=event_name,
        contract_address=env.address,
        block_number=env.block_number,
        block_hash=env.block_hash,
        transaction_hash=env.transaction_hash,
        transaction_index=env.transaction_index,
        log_index=env.log_index,
        args=args,
    )


@dataclass(frozen=True, slots=True)
class _EventSpec:
    """What a known ``topic0`` implies about a log's shape.

    ``max_topics`` is bound *before* members are validated, so a hostile log with
    an enormous topic list costs a length check rather than thousands of
    validations. ``decode`` performs the layout-specific decoding.
    """

    name: str
    max_topics: int
    decode: Callable[[_LogEnvelope, int], DecodedEvent]


_EVENT_SPECS: Final[dict[str, _EventSpec]] = {
    TRANSFER_TOPIC0: _EventSpec("Transfer", MAX_TOPICS_TRANSFER_APPROVAL, _decode_transfer),
    APPROVAL_TOPIC0: _EventSpec("Approval", MAX_TOPICS_TRANSFER_APPROVAL, _decode_approval),
    APPROVAL_FOR_ALL_TOPIC0: _EventSpec(
        "ApprovalForAll", MAX_TOPICS_APPROVAL_FOR_ALL, _decode_approval_for_all
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def _validate_chain_id(chain_id: Any) -> int:
    """``chain_id`` must be a positive int, and never a bool.

    ``bool`` is an ``int`` subclass, so ``isinstance(True, int)`` passes; an
    explicit check keeps ``chain_id=True`` from silently becoming 1.
    """
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        raise LogDecodeError("chain_id must be an int")
    if chain_id <= 0:
        raise LogDecodeError("chain_id must be positive")
    return chain_id


def decode_log(raw: Any, chain_id: int) -> DecodedEvent | None:
    """Decode one raw JSON-RPC log.

    Returns ``None`` when ``topic0`` is not a signature this decoder supports.
    Raises :class:`LogDecodeError` when the log *claims* to be a known event but
    its shape does not match — silently accepting those would mean reporting a
    bogus event as fact.
    """
    cid = _validate_chain_id(chain_id)
    log = _require_mapping(raw)

    topics = log.get("topics")
    if not isinstance(topics, (list, tuple)):
        raise _fail("topics", "must be a list")
    if not topics:
        # No topics at all: no topic0, so nothing to identify. Anonymous events
        # are out of scope rather than an error.
        return None

    topic0 = _require_hash32(topics[0], "topics[0]")
    known = _EVENT_SPECS.get(topic0)
    if known is None:
        return None

    # The bound depends on the event, so it is applied only now that topic0 has
    # told us which event this claims to be. An unknown topic0 with a huge topic
    # list therefore still returns None, as agreed — it is out of scope, not
    # malformed.
    #
    # Validate the envelope only for logs this decoder actually handles, so an
    # unsupported event does not fail on metadata it will never be used for.
    env = _parse_envelope(log, max_topics=known.max_topics)
    return known.decode(env, cid)


def decode_logs(raw_logs: Iterable[Any], chain_id: int) -> list[DecodedEvent]:
    """Decode a batch, preserving input order.

    Unsupported events are skipped. A malformed *known* event raises, and that
    exception is not swallowed: a batch whose shape is not understood must fail
    loudly rather than quietly report a subset as if it were the whole picture.
    """
    decoded: list[DecodedEvent] = []
    for raw in raw_logs:
        event = decode_log(raw, chain_id)
        if event is not None:
            decoded.append(event)
    return decoded
