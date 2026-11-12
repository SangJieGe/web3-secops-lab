"""Tests for the standalone EVM event decoder.

Fully offline: no socket is opened, no node is contacted. Every log is built
in-process from literal hex, which is exactly the shape a node would hand back.

Two deliberate habits here:

* assertions check *specific field values*, not merely that a result is non-None
  — a decoder that returned the right shape with wrong contents would pass a
  weaker test;
* every rejection path is exercised, because "accepts valid input" is only half
  the contract of a parser that sits on an untrusted boundary.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from web3_secops.event_decoder import (
    SCHEMA_VERSION,
    DecodedEvent,
    LogDecodeError,
    decode_log,
    decode_logs,
)

# ---------------------------------------------------------------------------
# Fixtures and builders
# ---------------------------------------------------------------------------
CHAIN_ID = 11155111  # Sepolia, matching the rest of the project

TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL_TOPIC0 = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL_TOPIC0 = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"

# A topic0 that is well-formed but belongs to no supported event.
UNKNOWN_TOPIC0 = "0x" + "ab" * 32

CONTRACT = "0x1111111111111111111111111111111111111111"
FROM_ADDR = "0x2222222222222222222222222222222222222222"
TO_ADDR = "0x3333333333333333333333333333333333333333"
SPENDER_ADDR = "0x4444444444444444444444444444444444444444"
OPERATOR_ADDR = "0x5555555555555555555555555555555555555555"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

BLOCK_HASH = "0x" + "aa" * 32
TX_HASH = "0x" + "bb" * 32


def addr_topic(address: str) -> str:
    """ABI-encode an address as an indexed topic: 12 zero bytes + 20 address."""
    assert address.startswith("0x")
    assert len(address) == 42
    return "0x" + "0" * 24 + address[2:]


def uint_topic(value: int) -> str:
    """ABI-encode a uint256 as a 32-byte topic."""
    return "0x" + value.to_bytes(32, "big").hex()


def uint_data(value: int) -> str:
    """ABI-encode a uint256 as 32 bytes of data."""
    return "0x" + value.to_bytes(32, "big").hex()


def bool_data(value: bool) -> str:
    return "0x" + (1 if value else 0).to_bytes(32, "big").hex()


def make_log(
    *,
    address: str = CONTRACT,
    topics: list[str],
    data: str = "0x",
    block_number: str = "0x1e240",
    block_hash: str = BLOCK_HASH,
    transaction_hash: str = TX_HASH,
    transaction_index: str = "0x2",
    log_index: str = "0x5",
    removed: bool = False,
) -> dict[str, Any]:
    """Build a raw log with node-shaped (hex-string) metadata."""
    return {
        "address": address,
        "topics": topics,
        "data": data,
        "blockNumber": block_number,
        "blockHash": block_hash,
        "transactionHash": transaction_hash,
        "transactionIndex": transaction_index,
        "logIndex": log_index,
        "removed": removed,
    }


# ---------------------------------------------------------------------------
# 1. Valid events — ERC-20 Transfer
# ---------------------------------------------------------------------------
def test_erc20_transfer_decodes_all_fields() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(10**18),
    )

    event = decode_log(log, CHAIN_ID)

    assert isinstance(event, DecodedEvent)
    assert event.schema_version == SCHEMA_VERSION == 1
    assert event.chain_id == CHAIN_ID
    assert event.standard == "erc20"
    assert event.event_type == "erc20_transfer"
    assert event.event_name == "Transfer"
    assert event.contract_address == CONTRACT
    assert event.block_number == 123456
    assert event.block_hash == BLOCK_HASH
    assert event.transaction_hash == TX_HASH
    assert event.transaction_index == 2
    assert event.log_index == 5
    # value stays an int internally: 10**18 exceeds float's exact range.
    assert event.args == {"from": FROM_ADDR, "to": TO_ADDR, "value": 10**18}
    assert isinstance(event.args["value"], int)


def test_erc20_transfer_json_renders_value_as_decimal_string() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(10**18),
    )

    payload = decode_log(log, CHAIN_ID).to_dict()

    assert payload["args"]["value"] == "1000000000000000000"
    assert isinstance(payload["args"]["value"], str)
    # Metadata numbers stay JSON numbers — they are far below the precision cliff.
    assert payload["block_number"] == 123456
    assert isinstance(payload["block_number"], int)
    # Must round-trip through json without a custom encoder.
    assert json.loads(json.dumps(payload)) == payload


def test_erc20_transfer_mint_from_zero_address() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(ZERO_ADDRESS), addr_topic(TO_ADDR)],
        data=uint_data(500),
    )

    event = decode_log(log, CHAIN_ID)

    assert event.args["from"] == ZERO_ADDRESS
    assert event.args["to"] == TO_ADDR
    assert event.args["value"] == 500


def test_erc20_transfer_burn_to_zero_address() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(ZERO_ADDRESS)],
        data=uint_data(500),
    )

    event = decode_log(log, CHAIN_ID)

    assert event.args["from"] == FROM_ADDR
    assert event.args["to"] == ZERO_ADDRESS


def test_erc20_transfer_max_uint256_value() -> None:
    max_uint = (1 << 256) - 1
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(max_uint),
    )

    event = decode_log(log, CHAIN_ID)

    assert event.args["value"] == max_uint
    # The JSON form must be exact; a float would round this.
    assert event.to_dict()["args"]["value"] == str(max_uint)
    assert event.to_dict()["args"]["value"] == (
        "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    )


# ---------------------------------------------------------------------------
# 2. Valid events — ERC-721 Transfer
# ---------------------------------------------------------------------------
def test_erc721_transfer_uses_four_topics_and_empty_data() -> None:
    token_id = 42
    log = make_log(
        topics=[
            TRANSFER_TOPIC0,
            addr_topic(FROM_ADDR),
            addr_topic(TO_ADDR),
            uint_topic(token_id),
        ],
        data="0x",
    )

    event = decode_log(log, CHAIN_ID)

    assert event.standard == "erc721"
    assert event.event_type == "erc721_transfer"
    assert event.event_name == "Transfer"
    assert event.args == {"from": FROM_ADDR, "to": TO_ADDR, "token_id": token_id}


def test_transfer_is_not_misread_as_erc20_even_though_topic0_matches() -> None:
    """The 4-topic layout must not be decoded as ERC-20 just because topic0 is shared."""
    erc721_log = make_log(
        topics=[
            TRANSFER_TOPIC0,
            addr_topic(FROM_ADDR),
            addr_topic(TO_ADDR),
            uint_topic(7),
        ],
        data="0x",
    )

    event = decode_log(erc721_log, CHAIN_ID)

    assert event.standard == "erc721"
    assert "value" not in event.args
    assert event.args["token_id"] == 7


def test_erc721_transfer_max_token_id() -> None:
    max_uint = (1 << 256) - 1
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR), uint_topic(max_uint)],
        data="0x",
    )

    assert decode_log(log, CHAIN_ID).args["token_id"] == max_uint


# ---------------------------------------------------------------------------
# 3. Valid events — ERC-20 Approval
# ---------------------------------------------------------------------------
def test_erc20_approval_decodes_all_fields() -> None:
    log = make_log(
        topics=[APPROVAL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(SPENDER_ADDR)],
        data=uint_data(2**255),
    )

    event = decode_log(log, CHAIN_ID)

    assert event.standard == "erc20"
    assert event.event_type == "erc20_approval"
    assert event.event_name == "Approval"
    assert event.args == {"owner": FROM_ADDR, "spender": SPENDER_ADDR, "value": 2**255}


# ---------------------------------------------------------------------------
# 4. Valid events — ERC-721 Approval
# ---------------------------------------------------------------------------
def test_erc721_approval_decodes_all_fields() -> None:
    log = make_log(
        topics=[
            APPROVAL_TOPIC0,
            addr_topic(FROM_ADDR),
            addr_topic(SPENDER_ADDR),
            uint_topic(99),
        ],
        data="0x",
    )

    event = decode_log(log, CHAIN_ID)

    assert event.standard == "erc721"
    assert event.event_type == "erc721_approval"
    assert event.args == {"owner": FROM_ADDR, "approved": SPENDER_ADDR, "token_id": 99}


def test_approval_is_not_misread_as_erc20() -> None:
    log = make_log(
        topics=[APPROVAL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(SPENDER_ADDR), uint_topic(1)],
        data="0x",
    )

    event = decode_log(log, CHAIN_ID)

    assert event.standard == "erc721"
    assert "value" not in event.args


# ---------------------------------------------------------------------------
# 5. Valid events — ApprovalForAll
# ---------------------------------------------------------------------------
def test_approval_for_all_true() -> None:
    log = make_log(
        topics=[APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(OPERATOR_ADDR)],
        data=bool_data(True),
    )

    event = decode_log(log, CHAIN_ID)

    assert event.event_name == "ApprovalForAll"
    assert event.event_type == "approval_for_all"
    # Shared by ERC-721 and ERC-1155: must not be pinned to either.
    assert event.standard == "erc721_or_erc1155"
    assert event.args == {"owner": FROM_ADDR, "operator": OPERATOR_ADDR, "approved": True}


def test_approval_for_all_false() -> None:
    log = make_log(
        topics=[APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(OPERATOR_ADDR)],
        data=bool_data(False),
    )

    event = decode_log(log, CHAIN_ID)

    assert event.args["approved"] is False
    assert event.to_dict()["args"]["approved"] is False


def test_approval_for_all_standard_is_not_erc721_only() -> None:
    """Guard against a future refactor attributing the shared event to one standard."""
    log = make_log(
        topics=[APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(OPERATOR_ADDR)],
        data=bool_data(True),
    )

    assert decode_log(log, CHAIN_ID).standard != "erc721"


# ---------------------------------------------------------------------------
# 6. Casing normalisation
# ---------------------------------------------------------------------------
def test_uppercase_and_mixed_case_input_is_normalised_to_lowercase() -> None:
    upper_contract = "0x1111111111111111111111111111111111111111".upper().replace("0X", "0x")
    upper_topic_from = "0x" + ("0" * 24 + FROM_ADDR[2:]).upper()
    log = make_log(
        address=upper_contract,
        topics=[TRANSFER_TOPIC0.upper().replace("0X", "0x"), upper_topic_from, addr_topic(TO_ADDR)],
        data=uint_data(1),
    )

    event = decode_log(log, CHAIN_ID)

    assert event.contract_address == upper_contract.lower()
    assert event.args["from"] == FROM_ADDR
    # Every address and hash in the output is lowercase.
    payload = event.to_dict()
    for key in ("contract_address", "block_hash", "transaction_hash"):
        assert payload[key] == payload[key].lower()
    assert event.args["from"] == event.args["from"].lower()


def test_mixed_case_topic0_still_dispatches() -> None:
    mixed = "0x" + TRANSFER_TOPIC0[2:].upper()
    log = make_log(topics=[mixed, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)], data=uint_data(1))

    assert decode_log(log, CHAIN_ID) is not None


# ---------------------------------------------------------------------------
# 7. Unsupported events return None
# ---------------------------------------------------------------------------
def test_unknown_topic0_returns_none() -> None:
    log = make_log(topics=[UNKNOWN_TOPIC0, addr_topic(FROM_ADDR)], data="0x")

    assert decode_log(log, CHAIN_ID) is None


def test_log_with_no_topics_returns_none() -> None:
    """No topic0 means nothing to identify: out of scope, not an error."""
    log = make_log(topics=[], data="0x")

    assert decode_log(log, CHAIN_ID) is None


def test_unknown_event_with_broken_metadata_still_returns_none() -> None:
    """Envelope validation happens only for events we actually decode."""
    log = make_log(topics=[UNKNOWN_TOPIC0], data="0x")
    log["blockNumber"] = "not-a-quantity"

    assert decode_log(log, CHAIN_ID) is None


# ---------------------------------------------------------------------------
# 8. Transfer/Approval layout mismatches
# ---------------------------------------------------------------------------
def test_transfer_with_two_topics_is_rejected() -> None:
    log = make_log(topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR)], data=uint_data(1))

    with pytest.raises(LogDecodeError, match=r"topics: Transfer must have 3"):
        decode_log(log, CHAIN_ID)


def test_transfer_with_five_topics_is_rejected() -> None:
    log = make_log(
        topics=[
            TRANSFER_TOPIC0,
            addr_topic(FROM_ADDR),
            addr_topic(TO_ADDR),
            uint_topic(1),
            uint_topic(2),
        ],
        data="0x",
    )

    with pytest.raises(LogDecodeError, match=r"topics: expected at most 4 entries, got 5"):
        decode_log(log, CHAIN_ID)


def test_transfer_three_topics_with_empty_data_is_rejected() -> None:
    """3 topics claims ERC-20, which requires 32 bytes of value."""
    log = make_log(topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)], data="0x")

    with pytest.raises(LogDecodeError, match=r"data: ERC-20 Transfer requires exactly 32"):
        decode_log(log, CHAIN_ID)


def test_transfer_four_topics_with_nonempty_data_is_rejected() -> None:
    """4 topics claims ERC-721, which requires empty data — not a guess either way."""
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR), uint_topic(1)],
        data=uint_data(5),
    )

    with pytest.raises(LogDecodeError, match=r"matches neither ERC-20 nor ERC-721"):
        decode_log(log, CHAIN_ID)


def test_erc20_transfer_data_of_64_bytes_is_rejected() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data="0x" + "00" * 64,
    )

    # 130 raw chars exceeds the 66-char ceiling, so it is rejected on size before
    # the ERC-20 layout check ever runs.
    with pytest.raises(LogDecodeError, match=r"data: exceeds 66 chars, got 130"):
        decode_log(log, CHAIN_ID)


def test_erc20_transfer_data_of_31_bytes_is_rejected() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data="0x" + "00" * 31,
    )

    with pytest.raises(LogDecodeError, match=r"data: ERC-20 Transfer requires exactly 32"):
        decode_log(log, CHAIN_ID)


def test_approval_with_wrong_topic_count_is_rejected() -> None:
    log = make_log(topics=[APPROVAL_TOPIC0, addr_topic(FROM_ADDR)], data=uint_data(1))

    with pytest.raises(LogDecodeError, match=r"topics: Approval must have 3"):
        decode_log(log, CHAIN_ID)


def test_erc721_approval_with_nonempty_data_is_rejected() -> None:
    log = make_log(
        topics=[APPROVAL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(SPENDER_ADDR), uint_topic(1)],
        data=uint_data(9),
    )

    with pytest.raises(LogDecodeError, match=r"matches neither ERC-20 nor ERC-721"):
        decode_log(log, CHAIN_ID)


def test_approval_for_all_with_two_topics_is_rejected() -> None:
    log = make_log(
        topics=[APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR)],
        data=bool_data(True),
    )

    with pytest.raises(LogDecodeError, match=r"topics: ApprovalForAll requires exactly 3"):
        decode_log(log, CHAIN_ID)


def test_approval_for_all_with_empty_data_is_rejected() -> None:
    log = make_log(
        topics=[APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(OPERATOR_ADDR)],
        data="0x",
    )

    with pytest.raises(LogDecodeError, match=r"data: ApprovalForAll requires exactly 32"):
        decode_log(log, CHAIN_ID)


# ---------------------------------------------------------------------------
# 9. Invalid bool encoding
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_value", [2, 3, 255, (1 << 256) - 1])
def test_approval_for_all_rejects_bool_encoded_as_non_zero_or_one(bad_value: int) -> None:
    """ABI bool is exactly 0 or 1; anything else is invalid encoding, not truthy."""
    log = make_log(
        topics=[APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(OPERATOR_ADDR)],
        data=uint_data(bad_value),
    )

    with pytest.raises(LogDecodeError, match=r"bool must be encoded as 0 or 1"):
        decode_log(log, CHAIN_ID)


# ---------------------------------------------------------------------------
# 10. Invalid indexed address encoding
# ---------------------------------------------------------------------------
def test_indexed_address_with_nonzero_padding_is_rejected() -> None:
    """First 12 bytes must be zero; a dirty prefix means it is not an address."""
    dirty = "0x" + "ff" * 12 + FROM_ADDR[2:]
    log = make_log(topics=[TRANSFER_TOPIC0, dirty, addr_topic(TO_ADDR)], data=uint_data(1))

    with pytest.raises(LogDecodeError, match=r"zero-padded in its first 12 bytes"):
        decode_log(log, CHAIN_ID)


def test_indexed_address_with_short_topic_is_rejected() -> None:
    short = "0x" + "0" * 24 + FROM_ADDR[2:].rstrip("2")
    log = make_log(topics=[TRANSFER_TOPIC0, short, addr_topic(TO_ADDR)], data=uint_data(1))

    with pytest.raises(LogDecodeError, match=r"topics\[1\]: must be 66 chars"):
        decode_log(log, CHAIN_ID)


# ---------------------------------------------------------------------------
# 11. Invalid topic encoding
# ---------------------------------------------------------------------------
def test_topic_of_wrong_length_is_rejected() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, "0x" + "ab" * 16, addr_topic(TO_ADDR)],
        data=uint_data(1),
    )

    with pytest.raises(LogDecodeError, match=r"topics\[1\]: must be 66 chars"):
        decode_log(log, CHAIN_ID)


def test_topic0_of_wrong_length_is_rejected() -> None:
    log = make_log(topics=["0x" + "ab" * 16, addr_topic(FROM_ADDR)], data=uint_data(1))

    with pytest.raises(LogDecodeError, match=r"topics\[0\]: must be 66 chars"):
        decode_log(log, CHAIN_ID)


def test_non_hex_topic_is_rejected() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, "0x" + "zz" * 32, addr_topic(TO_ADDR)],
        data=uint_data(1),
    )

    with pytest.raises(LogDecodeError, match=r"must be hex-encoded"):
        decode_log(log, CHAIN_ID)


def test_topics_not_a_list_is_rejected() -> None:
    log = make_log(topics=[TRANSFER_TOPIC0])
    log["topics"] = "0xdeadbeef"

    with pytest.raises(LogDecodeError, match=r"topics: must be a list"):
        decode_log(log, CHAIN_ID)


# ---------------------------------------------------------------------------
# 12. Invalid data encoding
# ---------------------------------------------------------------------------
def test_odd_length_data_is_rejected() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data="0x" + "0" * 63,
    )

    with pytest.raises(LogDecodeError, match=r"even number of hex digits"):
        decode_log(log, CHAIN_ID)


def test_data_without_0x_prefix_is_rejected() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data="00" * 32,
    )

    with pytest.raises(LogDecodeError, match=r"data: must be 0x-prefixed"):
        decode_log(log, CHAIN_ID)


def test_non_hex_data_is_rejected() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data="0x" + "zz" * 32,
    )

    with pytest.raises(LogDecodeError, match=r"data: must be hex-encoded"):
        decode_log(log, CHAIN_ID)


# ---------------------------------------------------------------------------
# 13. Invalid address / hash / quantity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad_address",
    [
        "0x111",  # too short
        "0x" + "11" * 21,  # too long
        "1111111111111111111111111111111111111111",  # no prefix
        "0x" + "gg" * 20,  # non-hex
        "",
        12345,  # not a string
        None,
    ],
)
def test_invalid_contract_address_is_rejected(bad_address: Any) -> None:
    log = make_log(topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)])
    log["address"] = bad_address
    log["data"] = uint_data(1)

    with pytest.raises(LogDecodeError, match=r"address:"):
        decode_log(log, CHAIN_ID)


@pytest.mark.parametrize(
    "field_name",
    ["blockHash", "transactionHash"],
)
@pytest.mark.parametrize(
    "bad_hash",
    [
        "0x" + "aa" * 16,  # 16 bytes, not 32
        "0x" + "aa" * 33,  # 33 bytes
        "aa" * 32,  # no prefix
        "0x" + "zz" * 32,  # non-hex
        123,  # not a string
    ],
)
def test_invalid_hash_is_rejected(field_name: str, bad_hash: Any) -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
    )
    log[field_name] = bad_hash

    with pytest.raises(LogDecodeError, match=rf"{field_name}:"):
        decode_log(log, CHAIN_ID)


@pytest.mark.parametrize(
    "field_name",
    ["blockNumber", "transactionIndex", "logIndex"],
)
@pytest.mark.parametrize(
    "bad_quantity",
    [
        "123",  # no 0x prefix
        "0x",  # no digits
        "0xzz",  # non-hex
        "0x01",  # leading zero, forbidden by JSON-RPC
        42,  # not a string
        None,
    ],
)
def test_invalid_quantity_is_rejected(field_name: str, bad_quantity: Any) -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
    )
    log[field_name] = bad_quantity

    with pytest.raises(LogDecodeError, match=rf"{field_name}:"):
        decode_log(log, CHAIN_ID)


def test_zero_quantity_is_valid() -> None:
    """``0x0`` is the canonical encoding of zero and must not be mistaken for empty."""
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
        log_index="0x0",
        transaction_index="0x0",
    )

    event = decode_log(log, CHAIN_ID)

    assert event.log_index == 0
    assert event.transaction_index == 0


# ---------------------------------------------------------------------------
# 14. removed=true
# ---------------------------------------------------------------------------
def test_removed_log_is_rejected() -> None:
    """A reorged-away log is not an event that happened."""
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
        removed=True,
    )

    with pytest.raises(LogDecodeError, match=r"removed: log has been removed by a reorg"):
        decode_log(log, CHAIN_ID)


def test_removed_field_must_be_a_json_boolean() -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
    )
    log["removed"] = "false"  # string, not bool

    with pytest.raises(LogDecodeError, match=r"removed: must be a JSON boolean"):
        decode_log(log, CHAIN_ID)


# ---------------------------------------------------------------------------
# 15. Missing fields
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "missing",
    [
        "address",
        "topics",
        "data",
        "blockNumber",
        "blockHash",
        "transactionHash",
        "transactionIndex",
        "logIndex",
        "removed",
    ],
)
def test_missing_required_field_is_rejected(missing: str) -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
    )
    del log[missing]

    with pytest.raises(LogDecodeError):
        decode_log(log, CHAIN_ID)


def test_non_object_log_is_rejected() -> None:
    with pytest.raises(LogDecodeError, match=r"must be a JSON object"):
        decode_log(["not", "a", "dict"], CHAIN_ID)


# ---------------------------------------------------------------------------
# 16. chain_id validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad_chain", [0, -1, "1", None, 1.5, True])
def test_invalid_chain_id_is_rejected(bad_chain: Any) -> None:
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
    )

    with pytest.raises(LogDecodeError, match=r"chain_id"):
        decode_log(log, bad_chain)


# ---------------------------------------------------------------------------
# 17. Error messages must not echo the raw log
# ---------------------------------------------------------------------------
def test_error_message_does_not_leak_raw_log_contents() -> None:
    """A hostile node could smuggle a secret into a field an exception prints."""
    secret = "SECRET_SHOULD_NOT_APPEAR_IN_ERROR_1234"
    log = make_log(
        topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        data=uint_data(1),
    )
    log["blockHash"] = secret

    with pytest.raises(LogDecodeError) as excinfo:
        decode_log(log, CHAIN_ID)

    message = str(excinfo.value)
    assert secret not in message
    assert "blockHash" in message  # still names the field, so it is diagnosable


# ---------------------------------------------------------------------------
# 18. Batch decoding
# ---------------------------------------------------------------------------
def test_decode_logs_preserves_order_and_skips_unsupported() -> None:
    logs = [
        make_log(  # index 0 — ERC-20 transfer
            topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
            data=uint_data(1),
            log_index="0x0",
        ),
        make_log(topics=[UNKNOWN_TOPIC0], data="0x", log_index="0x1"),  # index 1 — skipped
        make_log(  # index 2 — ERC-721 transfer
            topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR), uint_topic(9)],
            data="0x",
            log_index="0x2",
        ),
        make_log(  # index 3 — ApprovalForAll
            topics=[APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(OPERATOR_ADDR)],
            data=bool_data(True),
            log_index="0x3",
        ),
    ]

    events = decode_logs(logs, CHAIN_ID)

    assert [e.event_type for e in events] == [
        "erc20_transfer",
        "erc721_transfer",
        "approval_for_all",
    ]
    # Order is stable and matches input order, with the unknown one omitted.
    assert [e.log_index for e in events] == [0, 2, 3]


def test_decode_logs_all_unsupported_returns_empty_list() -> None:
    logs = [make_log(topics=[UNKNOWN_TOPIC0], data="0x") for _ in range(3)]

    assert decode_logs(logs, CHAIN_ID) == []


def test_decode_logs_empty_input_returns_empty_list() -> None:
    assert decode_logs([], CHAIN_ID) == []


def test_decode_logs_propagates_known_event_error() -> None:
    """A malformed known event must fail the batch, not be silently dropped."""
    logs = [
        make_log(
            topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
            data=uint_data(1),
        ),
        make_log(  # broken ERC-20: empty data
            topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
            data="0x",
        ),
    ]

    with pytest.raises(LogDecodeError, match=r"ERC-20 Transfer requires exactly 32"):
        decode_logs(logs, CHAIN_ID)


def test_decode_logs_does_not_return_partial_result_on_error() -> None:
    """The exception must escape; no truncated list may be observed."""
    logs = [
        make_log(
            topics=[TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
            data="0x",
        )
    ]
    result: list[DecodedEvent] | None = None

    with pytest.raises(LogDecodeError):
        result = decode_logs(logs, CHAIN_ID)

    assert result is None


# ---------------------------------------------------------------------------
# Trailing-newline bypass (P1)
#
# ``re``'s ``$`` matches immediately before a trailing newline, so a field of the
# right length could end in "\n" and still pass a ``^...$`` match. These tests pin
# the boundary: every hex-shaped field must be fully matched, no exceptions.
# ---------------------------------------------------------------------------
def _erc20_transfer_log(**overrides: Any) -> dict[str, Any]:
    """A valid ERC-20 Transfer, for tests that only break one specific field."""
    base: dict[str, Any] = {
        "address": CONTRACT,
        "topics": [TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)],
        "data": uint_data(1),
        "blockNumber": "0x1e240",
        "blockHash": BLOCK_HASH,
        "transactionHash": TX_HASH,
        "transactionIndex": "0x2",
        "logIndex": "0x5",
        "removed": False,
    }
    base.update(overrides)
    return base


def test_contract_address_with_trailing_newline_is_rejected() -> None:
    """39 valid hex chars + "\n" is still 42 chars, so length alone cannot catch it."""
    bad = "0x" + "1" * 39 + "\n"
    assert len(bad) == 42, "precondition: the string must satisfy the length check"

    with pytest.raises(LogDecodeError, match=r"address: must be hex-encoded"):
        decode_log(_erc20_transfer_log(address=bad), CHAIN_ID)


def test_block_hash_with_trailing_newline_is_rejected() -> None:
    """63 valid hex chars + "\n" is still 66 chars."""
    bad = "0x" + "a" * 63 + "\n"
    assert len(bad) == 66, "precondition: the string must satisfy the length check"

    with pytest.raises(LogDecodeError, match=r"blockHash: must be hex-encoded"):
        decode_log(_erc20_transfer_log(blockHash=bad), CHAIN_ID)


def test_transaction_hash_with_trailing_newline_is_rejected() -> None:
    bad = "0x" + "b" * 63 + "\n"
    assert len(bad) == 66, "precondition: the string must satisfy the length check"

    with pytest.raises(LogDecodeError, match=r"transactionHash: must be hex-encoded"):
        decode_log(_erc20_transfer_log(transactionHash=bad), CHAIN_ID)


def test_topic0_with_trailing_newline_is_rejected() -> None:
    """topic0 identifies the event, so it is shape-checked before dispatch."""
    bad_topic0 = TRANSFER_TOPIC0 + "\n"

    with pytest.raises(LogDecodeError, match=r"topics\[0\]: must be 66 chars"):
        decode_log(
            _erc20_transfer_log(topics=[bad_topic0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)]),
            CHAIN_ID,
        )


def test_indexed_address_topic_with_trailing_newline_is_rejected() -> None:
    """An indexed address must not decode to a value carrying a newline."""
    bad_from = addr_topic(FROM_ADDR) + "\n"

    with pytest.raises(LogDecodeError, match=r"topics\[1\]: must be 66 chars"):
        decode_log(
            _erc20_transfer_log(topics=[TRANSFER_TOPIC0, bad_from, addr_topic(TO_ADDR)]), CHAIN_ID
        )


@pytest.mark.parametrize(
    "bad_quantity",
    ["0x1\n", "0x1\r\n", " 0x1", "0x1 ", "\t0x1", "0x1\t", "\n0x1"],
)
def test_quantities_with_surrounding_whitespace_are_rejected(bad_quantity: str) -> None:
    """blockNumber, transactionIndex and logIndex all reject stray whitespace."""
    for field in ("blockNumber", "transactionIndex", "logIndex"):
        with pytest.raises(LogDecodeError, match=rf"{field}:"):
            decode_log(_erc20_transfer_log(**{field: bad_quantity}), CHAIN_ID)


def test_quantity_with_trailing_newline_does_not_decode_to_a_valid_number() -> None:
    """The specific bug P1 fixed: "0x1\n" used to decode to 1 and be accepted."""
    with pytest.raises(LogDecodeError, match=r"blockNumber:"):
        decode_log(_erc20_transfer_log(blockNumber="0x1\n"), CHAIN_ID)


@pytest.mark.parametrize("field", ["blockNumber", "transactionIndex", "logIndex"])
def test_uppercase_0X_prefix_is_rejected(field: str) -> None:
    """JSON-RPC spells the prefix lowercase; "0X" is not the same string."""
    with pytest.raises(LogDecodeError, match=rf"{field}: must be 0x-prefixed"):
        decode_log(_erc20_transfer_log(**{field: "0X1"}), CHAIN_ID)


def test_uppercase_0X_address_prefix_is_rejected() -> None:
    with pytest.raises(LogDecodeError, match=r"address: must be 0x-prefixed"):
        decode_log(_erc20_transfer_log(address="0X" + "11" * 20), CHAIN_ID)


def test_data_with_trailing_newline_is_rejected() -> None:
    bad_data = "0x" + "00" * 31 + "01\n"

    with pytest.raises(LogDecodeError, match=r"data:"):
        decode_log(_erc20_transfer_log(data=bad_data), CHAIN_ID)


def test_uppercase_hex_digits_are_still_accepted_and_normalised() -> None:
    """Uppercase digits are legitimate hex; only the 0x prefix is case-sensitive."""
    log = _erc20_transfer_log(
        address="0x" + "AB" * 20,
        blockHash="0x" + "CD" * 32,
        transactionHash="0x" + "EF" * 32,
        topics=[
            "0x" + TRANSFER_TOPIC0[2:].upper(),
            "0x" + addr_topic(FROM_ADDR)[2:].upper(),
            addr_topic(TO_ADDR),
        ],
        data="0x" + "00" * 31 + "0A",
    )

    event = decode_log(log, CHAIN_ID)

    assert event is not None
    assert event.contract_address == "0x" + "ab" * 20
    assert event.block_hash == "0x" + "cd" * 32
    assert event.transaction_hash == "0x" + "ef" * 32
    assert event.args["value"] == 10
    # Everything emitted is lowercase, with no stray characters.
    assert "\n" not in event.contract_address
    for value in (event.contract_address, event.block_hash, event.transaction_hash):
        assert value == value.lower()


def test_quantity_zero_is_still_accepted() -> None:
    """ "0x0" is the one legitimate zero; the no-leading-zero rule must not break it."""
    event = decode_log(_erc20_transfer_log(logIndex="0x0"), CHAIN_ID)

    assert event is not None
    assert event.log_index == 0


# ---------------------------------------------------------------------------
# Input size bounds (P2)
#
# Bounds are enforced before conversion/allocation: a known event's topic list and
# data are bounded, and quantities are capped at 64 hex digits.
# ---------------------------------------------------------------------------
def test_transfer_with_many_topics_is_rejected_before_validation() -> None:
    """1000 topics must fail on count, not on 1000 individual validations."""
    topics = [TRANSFER_TOPIC0] + [addr_topic(FROM_ADDR)] * 999

    with pytest.raises(LogDecodeError, match=r"topics: expected at most 4 entries, got 1000"):
        decode_log(_erc20_transfer_log(topics=topics), CHAIN_ID)


def test_approval_with_five_topics_is_rejected() -> None:
    topics = [
        APPROVAL_TOPIC0,
        addr_topic(FROM_ADDR),
        addr_topic(TO_ADDR),
        uint_topic(1),
        uint_topic(2),
    ]

    with pytest.raises(LogDecodeError, match=r"topics: expected at most 4 entries, got 5"):
        decode_log(_erc20_transfer_log(topics=topics), CHAIN_ID)


def test_approval_for_all_with_four_topics_is_rejected() -> None:
    """ApprovalForAll accepts exactly 3 topics, so 4 is over the bound."""
    topics = [APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR), uint_topic(1)]

    with pytest.raises(LogDecodeError, match=r"topics: expected at most 3 entries, got 4"):
        decode_log(_erc20_transfer_log(topics=topics, data=uint_data(1)), CHAIN_ID)


def test_data_longer_than_32_bytes_is_rejected_before_decoding() -> None:
    """A 1 KB payload must be refused on length, not decoded into memory first."""
    huge = "0x" + "00" * 1024

    with pytest.raises(LogDecodeError, match=r"data: exceeds 66 chars, got 2050"):
        decode_log(_erc20_transfer_log(data=huge), CHAIN_ID)


def test_quantity_longer_than_64_hex_digits_is_rejected() -> None:
    with pytest.raises(LogDecodeError, match=r"blockNumber: exceeds 64 hex digits, got 65"):
        decode_log(_erc20_transfer_log(blockNumber="0x" + "f" * 65), CHAIN_ID)


def test_quantity_of_exactly_64_hex_digits_is_accepted() -> None:
    """The 64-digit cap must not reject a legitimate uint256-sized quantity."""
    value = "0x" + "f" * 64

    event = decode_log(_erc20_transfer_log(blockNumber=value), CHAIN_ID)

    assert event is not None
    assert event.block_number == int("f" * 64, 16)


def test_unknown_topic0_with_oversized_topic_list_still_returns_none() -> None:
    """An unsupported event stays out of scope even if its shape is absurd."""
    log = _erc20_transfer_log(
        topics=[UNKNOWN_TOPIC0] + [addr_topic(FROM_ADDR)] * 50, data="0x" + "00" * 500
    )

    assert decode_log(log, CHAIN_ID) is None


@pytest.mark.parametrize(
    ("topics", "data"),
    [
        ([TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)], uint_data(10**18)),
        ([TRANSFER_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR), uint_topic(7)], "0x"),
        ([APPROVAL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)], uint_data(2**255)),
        ([APPROVAL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR), uint_topic(9)], "0x"),
        ([APPROVAL_FOR_ALL_TOPIC0, addr_topic(FROM_ADDR), addr_topic(TO_ADDR)], uint_data(1)),
    ],
)
def test_size_bounds_do_not_reject_any_legitimate_event(topics: list[str], data: str) -> None:
    """All five supported layouts still decode after the new bounds were added."""
    event = decode_log(_erc20_transfer_log(topics=topics, data=data), CHAIN_ID)

    assert event is not None
    assert event.args
