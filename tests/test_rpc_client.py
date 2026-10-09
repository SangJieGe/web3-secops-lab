"""Tests for rpc_client: read-only guard, retries, decoding of results."""

from __future__ import annotations

import httpx
import pytest
import respx

from web3_secops.rpc_client import RpcClient, RpcError


@pytest.fixture
def client():
    c = RpcClient("https://rpc.test", max_retries=2, base_backoff=0.01)
    yield c
    c.close()


def test_rejects_non_readonly_method(client):
    with pytest.raises(ValueError, match="non-read-only"):
        client.call("eth_sendRawTransaction", ["0xdead"])


def test_rejects_non_eth_method(client):
    with pytest.raises(ValueError):
        client.call("personal_unlockAccount", [])


@respx.mock
def test_get_block_number(client):
    respx.post("https://rpc.test").mock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x10"})
    )
    assert client.get_block_number() == 16


@respx.mock
def test_rpc_error_raised(client):
    respx.post("https://rpc.test").mock(
        return_value=httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no method"}},
        )
    )
    with pytest.raises(RpcError) as exc:
        client.call("eth_blockNumber")
    assert exc.value.code == -32601


@respx.mock
def test_retries_then_succeeds(client):
    route = respx.post("https://rpc.test")
    route.side_effect = [
        httpx.Response(503),
        httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": "0x2a"}),
    ]
    assert client.get_block_number() == 42
    assert route.call_count == 2


@respx.mock
def test_batch_returns_in_order(client):
    respx.post("https://rpc.test").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"jsonrpc": "2.0", "id": 1, "result": "0x1"},
                {"jsonrpc": "2.0", "id": 2, "result": "0x2"},
            ],
        )
    )
    out = client.batch([("eth_blockNumber", []), ("eth_gasPrice", [])])
    assert out == ["0x1", "0x2"]


@respx.mock
def test_batch_falls_back_when_node_rejects(client):
    route = respx.post("https://rpc.test")
    route.side_effect = [
        httpx.Response(400),  # batch unsupported
        httpx.Response(200, json={"jsonrpc": "2.0", "id": 3, "result": "0x10"}),
        httpx.Response(200, json={"jsonrpc": "2.0", "id": 4, "result": "0x10"}),
    ]
    out = client.batch([("eth_blockNumber", []), ("eth_blockNumber", [])])
    assert out == ["0x10", "0x10"]
