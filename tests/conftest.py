"""Shared fixtures: synthetic blocks and a mocked RPC transport.

Every fixture here is **synthetic**. No real chain data, no real RPC endpoint,
no API key. A fake chain is built as a dict of blocks so tests can rewrite it
mid-run to simulate a reorg deterministically.
"""

from __future__ import annotations

import hashlib
from typing import Any

import httpx
import pytest
import respx

from web3_secops.rpc_client import RpcClient

TEST_URL = "https://rpc.test.invalid/v2/TESTKEY123"


# ---------------------------------------------------------------------------
# Synthetic chain construction
# ---------------------------------------------------------------------------
def _fake_hash(*parts: Any) -> str:
    """Deterministic 32-byte hex hash from arbitrary parts."""
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()
    return "0x" + digest


def make_block(
    number: int,
    *,
    parent_hash: str | None = None,
    fork: str = "main",
    tx_count: int = 2,
    timestamp: int | None = None,
) -> dict[str, Any]:
    """Build a raw JSON-RPC block dict.

    ``fork`` changes the resulting hashes, so calling ``make_block(n, fork="b")``
    produces the alternative-branch version of block ``n`` with the same chain
    of parent links.
    """
    block_hash = _fake_hash("block", fork, number)
    if parent_hash is None:
        parent_hash = _fake_hash("block", fork, number - 1)

    txs = [
        {
            "hash": _fake_hash("tx", fork, number, i),
            "from": "0x" + "11" * 20,
            "to": "0x" + "22" * 20,
            "value": hex(10**18 * (i + 1)),
            "transactionIndex": hex(i),
        }
        for i in range(tx_count)
    ]

    return {
        "number": hex(number),
        "hash": block_hash,
        "parentHash": parent_hash,
        "timestamp": hex(timestamp if timestamp is not None else 1_700_000_000 + number * 12),
        "transactions": txs,
    }


def make_chain(start: int, end: int, *, fork: str = "main", tx_count: int = 2) -> dict[int, Any]:
    """Build a contiguous synthetic chain as ``{number: block}``."""
    blocks = {}
    for number in range(start, end + 1):
        blocks[number] = make_block(number, fork=fork, tx_count=tx_count)
    return blocks


# ---------------------------------------------------------------------------
# A fake node that respx can route to
# ---------------------------------------------------------------------------
class FakeNode:
    """Serves eth_chainId / eth_blockNumber / eth_getBlockByNumber from a dict.

    Behaves enough like a real node to exercise the client end to end: it echoes
    the request id, returns JSON-RPC error objects for unknown methods, and
    records every request body so tests can prove what was *not* sent.
    """

    def __init__(
        self,
        chain_id: int = 11155111,
        head: int | None = None,
        blocks: dict[int, Any] | None = None,
    ) -> None:
        self.chain_id = chain_id
        self.blocks: dict[int, Any] = dict(blocks or {})
        self._head = head if head is not None else (max(self.blocks) if self.blocks else 0)
        self.requests: list[dict[str, Any]] = []

    # -- state manipulation used by reorg tests ---------------------------
    def set_chain(self, blocks: dict[int, Any]) -> None:
        self.blocks = dict(blocks)
        self._head = max(self.blocks) if self.blocks else self._head

    def set_head(self, head: int) -> None:
        self._head = head

    def calls_to(self, method: str) -> list[dict[str, Any]]:
        return [r for r in self.requests if r.get("method") == method]

    # -- respx handler ----------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        payload = httpx.Response(200).json  # placeholder to keep signature clear
        del payload
        import json

        body = json.loads(request.content)
        self.requests.append(body)

        if isinstance(body, list):
            return httpx.Response(200, json=[self._handle_one(item) for item in body])
        return httpx.Response(200, json=self._handle_one(body))

    def _handle_one(self, body: dict[str, Any]) -> dict[str, Any]:
        request_id = body.get("id")
        method = body.get("method")
        params = body.get("params") or []

        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": request_id, "result": hex(self.chain_id)}

        if method == "eth_blockNumber":
            return {"jsonrpc": "2.0", "id": request_id, "result": hex(self._head)}

        if method == "eth_getBlockByNumber":
            raw_tag = params[0] if params else "latest"
            number = self._head if raw_tag == "latest" else int(raw_tag, 16)
            block = self.blocks.get(number)
            if block is None:
                return {"jsonrpc": "2.0", "id": request_id, "result": None}
            return {"jsonrpc": "2.0", "id": request_id, "result": block}

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"method {method} not found"},
        }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_node() -> FakeNode:
    """Node with 100 blocks (0..99) and head at 99."""
    return FakeNode(head=99, blocks=make_chain(0, 99))


@pytest.fixture
def routed(fake_node: FakeNode):
    """Activate a respx router answering TEST_URL with ``fake_node``.

    Only tests that want the default fake node should request this. Tests that
    need custom responses (errors, retries, redirects) open their own
    ``respx.mock()`` block and therefore must NOT request this fixture —
    stacking two active routers makes request matching ambiguous.
    """
    with respx.mock(assert_all_called=False) as router:
        router.post(TEST_URL).mock(side_effect=fake_node.handler)
        yield router


@pytest.fixture
def client() -> RpcClient:
    """Client with near-zero backoff so retry tests finish instantly."""
    c = RpcClient(
        TEST_URL,
        timeout=2.0,
        max_retries=2,
        base_backoff=0.0,
        max_backoff=0.0,
    )
    yield c
    c.close()


@pytest.fixture
def chain_blocks() -> dict[int, Any]:
    """A plain synthetic chain for scanner tests that do not need a node."""
    return make_chain(0, 199)
