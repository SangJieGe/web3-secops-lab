"""Tests for event_decoder: static/dynamic decoding and registry lookup."""

from __future__ import annotations

from web3_secops.event_decoder import (
    AbiEvent,
    EventDecoder,
    RawLog,
    _decode_dynamic,
    _decode_static,
    _strip_hex,
)

from .fixtures.sample_data import ERC20_TRANSFER_LOG

TRANSFER_ABI = {
    "type": "event",
    "name": "Transfer",
    "topic0": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "inputs": [
        {"name": "from", "type": "address", "indexed": True},
        {"name": "to", "type": "address", "indexed": True},
        {"name": "value", "type": "uint256", "indexed": False},
    ],
}


def test_strip_hex():
    assert _strip_hex("0xab") == "ab"
    assert _strip_hex("ab") == "ab"


def test_decode_static_address():
    word = "0000000000000000000000001111111111111111111111111111111111111111"
    assert _decode_static("address", word) == "0x1111111111111111111111111111111111111111"


def test_decode_static_uint_and_bool():
    assert _decode_static("uint256", "00" * 31 + "0f") == 15
    assert _decode_static("bool", "00" * 31 + "01") is True


def test_decode_dynamic_string():
    # offset=0x20, length=0x05, "hello"
    data = (
        "00" * 31 + "20"
        + "00" * 31 + "05"
        + "68656c6c6f" + "00" * 27
    )
    assert _decode_dynamic("string", data, 0) == "hello"


def test_decode_erc20_transfer():
    raw = RawLog.from_rpc(ERC20_TRANSFER_LOG)
    out = EventDecoder and AbiEvent.from_dict(TRANSFER_ABI)
    from web3_secops.event_decoder import decode_event

    decoded = decode_event(out, raw)
    assert decoded["event"] == "Transfer"
    assert decoded["args"]["from"] == "0x1111111111111111111111111111111111111111"
    assert decoded["args"]["to"] == "0x2222222222222222222222222222222222222222"
    assert decoded["args"]["value"] == 1_000_000


def test_registry_decode_by_topic():
    dec = EventDecoder()
    dec.register(AbiEvent.from_dict(TRANSFER_ABI))
    raw = RawLog.from_rpc(ERC20_TRANSFER_LOG)
    decoded = dec.decode(raw)
    assert decoded is not None
    assert decoded["args"]["value"] == 1_000_000


def test_registry_unknown_topic_returns_none():
    dec = EventDecoder()
    dec.register(AbiEvent.from_dict(TRANSFER_ABI))
    raw = RawLog.from_rpc({**ERC20_TRANSFER_LOG, "topics": ["0xdeadbeef"]})
    assert dec.decode(raw) is None


def test_register_without_topic0_raises():
    dec = EventDecoder()
    import pytest

    with pytest.raises(ValueError):
        dec.register(AbiEvent(name="X", inputs=[], topic0=None))
