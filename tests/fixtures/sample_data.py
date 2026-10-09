"""Sample raw RPC payloads used by tests. No network calls."""

BLOCK_RAW = {
    "number": "0x10",
    "hash": "0xabc123",
    "parentHash": "0xparent",
    "timestamp": "0x64000000",
    "transactions": [
        {
            "hash": "0xtx1",
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "0xde0b6b3a7640000",  # 1 ETH
        },
        {
            "hash": "0xtx2",
            "from": "0x9999999999999999999999999999999999999999",
            "to": "0x1111111111111111111111111111111111111111",
            "value": "0x0",
        },
    ],
}

ERC20_TRANSFER_LOG = {
    "address": "0xTOKEN",
    "topics": [
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        "0x0000000000000000000000001111111111111111111111111111111111111111",
        "0x0000000000000000000000002222222222222222222222222222222222222222",
    ],
    "data": "0x00000000000000000000000000000000000000000000000000000000000f4240",
    "blockNumber": "0x10",
    "transactionHash": "0xtx1",
    "logIndex": "0x0",
}
