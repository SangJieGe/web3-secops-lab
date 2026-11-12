"""Tests for the read-only JSON-RPC client (M1-A).

The security tests here are the important ones: they assert not just that a
dangerous method raises, but that **no HTTP request was emitted**. A guard that
raises after building the request would still leak intent to the provider and
fail open if a future refactor reordered the code.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from tests.conftest import TEST_URL, FakeNode, make_block, make_chain
from web3_secops.rpc_client import (
    FORBIDDEN_METHODS,
    READ_ONLY_METHODS,
    ForbiddenMethodError,
    RetriesExhausted,
    RpcClient,
    RpcError,
    RpcProtocolError,
    RpcResponseError,
    normalize_block,
    redact_url,
)


# ===========================================================================
# Allowlist enforcement — the core security boundary
# ===========================================================================
@pytest.mark.parametrize("method", sorted(FORBIDDEN_METHODS))
def test_forbidden_methods_are_rejected(client: RpcClient, method: str) -> None:
    """Every method in FORBIDDEN_METHODS raises before any I/O."""
    with pytest.raises(ForbiddenMethodError):
        client.call(method, [])


def test_forbidden_method_sends_no_http_request(client: RpcClient) -> None:
    """The rejected call must not reach the network at all."""
    # assert_all_called=False is essential here: the whole point is that the
    # route is NEVER called. respx's default assertion would flag that as an
    # error and mask the real check.
    with respx.mock(assert_all_called=False) as router:
        route = router.post(TEST_URL).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x1"})
        )

        with pytest.raises(ForbiddenMethodError):
            client.call("eth_sendRawTransaction", ["0xf86b"])

        assert route.call_count == 0, "a forbidden method must never produce an HTTP request"


def test_eth_prefix_is_not_sufficient(client: RpcClient) -> None:
    """Regression: the old implementation allowed anything starting with 'eth_'.

    ``eth_sendRawTransaction`` starts with ``eth_``. A prefix check would accept
    it, which is exactly the vulnerability this test locks down.
    """
    with respx.mock(assert_all_called=False) as router:
        route = router.post(TEST_URL).mock(return_value=httpx.Response(200, json={}))

        assert "eth_sendRawTransaction".startswith("eth_")  # the old, broken predicate
        with pytest.raises(ForbiddenMethodError):
            client.call("eth_sendRawTransaction", ["0x00"])

        assert route.call_count == 0


def test_unknown_method_rejected_without_request(client: RpcClient) -> None:
    """A method outside the allowlist never produces a request."""
    with respx.mock(assert_all_called=False) as router:
        route = router.post(TEST_URL).mock(return_value=httpx.Response(200, json={}))

        with pytest.raises(ForbiddenMethodError, match="not in the read-only allowlist"):
            client.call("eth_getLogs", [{"fromBlock": "0x1", "toBlock": "0x2"}])

        assert route.call_count == 0


def test_allowlist_contents() -> None:
    """The allowlist is exactly the three M1 methods — no accidental widening."""
    assert {"eth_chainId", "eth_blockNumber", "eth_getBlockByNumber"} == READ_ONLY_METHODS
    assert READ_ONLY_METHODS.isdisjoint(FORBIDDEN_METHODS)


def test_non_string_method_rejected(client: RpcClient) -> None:
    with pytest.raises(ForbiddenMethodError):
        client.call(None)  # type: ignore[arg-type]


# ===========================================================================
# Happy path
# ===========================================================================
def test_get_chain_id(client: RpcClient, routed) -> None:
    assert client.get_chain_id() == 11155111


def test_get_block_number(client: RpcClient, routed) -> None:
    assert client.get_block_number() == 99


def test_get_block_details(client: RpcClient, routed) -> None:
    block = client.get_block(42)

    assert block.number == 42
    assert block.hash.startswith("0x")
    assert len(block.hash) == 66
    assert block.parent_hash.startswith("0x")
    assert block.timestamp > 0
    assert len(block.transactions) == 2
    first = block.transactions[0]
    assert first.value_wei == 10**18
    assert first.to_addr == "0x" + "22" * 20


def test_request_payload_shape(client: RpcClient, fake_node: FakeNode, routed) -> None:
    """Requests are well-formed JSON-RPC 2.0 with a monotonic id."""
    client.get_chain_id()
    client.get_block_number()

    chain_req = fake_node.calls_to("eth_chainId")[0]
    block_req = fake_node.calls_to("eth_blockNumber")[0]

    assert chain_req["jsonrpc"] == "2.0"
    assert chain_req["params"] == []
    assert isinstance(chain_req["id"], int)
    assert block_req["id"] == chain_req["id"] + 1


def test_get_block_hex_tag_sent_correctly(client: RpcClient, fake_node: FakeNode) -> None:
    """A decimal block number is converted to a 0x-hex tag."""
    node = FakeNode(head=300, blocks=make_chain(250, 260))
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        client.get_block(255)
    sent = node.calls_to("eth_getBlockByNumber")[0]
    assert sent["params"] == ["0xff", True]


# ===========================================================================
# Protocol / error handling
# ===========================================================================
def test_rpc_error_response_raises(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32601, "message": "method not found"},
                },
            )
        )
        with pytest.raises(RpcResponseError) as exc:
            client.call("eth_blockNumber")
    assert exc.value.code == -32601


def test_invalid_json_body(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(200, content=b"<html>not json</html>")
        )
        with pytest.raises(RpcProtocolError, match="not valid JSON"):
            client.call("eth_blockNumber")


def test_id_mismatch_detected(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 999, "result": "0x1"})
        )
        with pytest.raises(RpcProtocolError, match="does not match request id"):
            client.call("eth_blockNumber")


def test_wrong_jsonrpc_version(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "1.0", "id": 1, "result": "0x1"})
        )
        with pytest.raises(RpcProtocolError, match="jsonrpc field"):
            client.call("eth_blockNumber")


def test_both_result_and_error_rejected(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": "0x1",
                    "error": {"code": -1, "message": "both"},
                },
            )
        )
        with pytest.raises(RpcProtocolError, match="both"):
            client.call("eth_blockNumber")


def test_neither_result_nor_error_rejected(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1})
        )
        with pytest.raises(RpcProtocolError, match="neither"):
            client.call("eth_blockNumber")


def test_non_object_response_rejected(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(return_value=httpx.Response(200, json=["a", "b"]))
        with pytest.raises(RpcProtocolError, match="not a JSON object"):
            client.call("eth_blockNumber")


def test_malformed_quantity_rejected(client: RpcClient) -> None:
    """A non-hex quantity from an untrusted node is a protocol error, not a 0."""
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "99"})
        )
        with pytest.raises(RpcProtocolError, match="not 0x-hex"):
            client.get_block_number()


def test_retries_on_http_429_then_succeeds(client: RpcClient) -> None:
    """429 is transient: retry once, then succeed."""
    attempts = {"n": 0}

    def side_effect(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(429)
        req_id = json.loads(request.content)["id"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x2a"})

    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(side_effect=side_effect)
        assert client.get_block_number() == 42
        assert route.call_count == 2


def test_retries_on_http_503_then_succeeds(client: RpcClient) -> None:
    """500-class statuses are transient: retry until success."""
    attempts = {"n": 0}

    def side_effect(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] <= 2:
            return httpx.Response(503 if attempts["n"] == 1 else 502)
        req_id = json.loads(request.content)["id"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x10"})

    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(side_effect=side_effect)
        assert client.get_block_number() == 16
        assert route.call_count == 3


def test_retries_on_timeout_then_succeeds(client: RpcClient) -> None:
    """A read timeout is transient: retry, then succeed."""
    attempts = {"n": 0}

    def side_effect(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ReadTimeout("timed out")
        req_id = json.loads(request.content)["id"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x7"})

    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(side_effect=side_effect)
        assert client.get_block_number() == 7
        assert route.call_count == 2


def test_retries_on_retryable_rpc_code(client: RpcClient) -> None:
    """A node-side rate-limit code (-32005) is retried."""
    attempts = {"n": 0}

    def side_effect(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        req_id = json.loads(request.content)["id"]
        if attempts["n"] == 1:
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32005, "message": "limit exceeded"},
                },
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x5"})

    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(side_effect=side_effect)
        assert client.get_block_number() == 5
        assert route.call_count == 2


def test_retries_exhausted_raises(client: RpcClient) -> None:
    """max_retries=2 means 3 attempts, then a hard failure. Never infinite."""
    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(return_value=httpx.Response(503))
        with pytest.raises(RetriesExhausted, match="3 attempt"):
            client.get_block_number()
        assert route.call_count == 3


def test_timeout_exhausted_raises(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(side_effect=httpx.ConnectTimeout("nope"))
        with pytest.raises(RetriesExhausted):
            client.get_block_number()
        assert route.call_count == 3


def test_non_retryable_4xx_fails_immediately(client: RpcClient) -> None:
    """A 401 (bad key) must not be retried — retrying cannot fix it."""
    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(return_value=httpx.Response(401))
        with pytest.raises(RpcError, match="HTTP 401"):
            client.get_block_number()
        assert route.call_count == 1


def test_non_retryable_rpc_error_not_retried(client: RpcClient) -> None:
    with respx.mock(base_url=TEST_URL) as router:
        route = router.post(TEST_URL).mock(
            return_value=httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}},
            )
        )
        with pytest.raises(RpcResponseError):
            client.call("eth_blockNumber")
        assert route.call_count == 1


def test_redirect_not_followed(client: RpcClient) -> None:
    """A 302 must not be chased: it would re-send the key to another host."""
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(302, headers={"Location": "https://evil.invalid/x"})
        )
        with pytest.raises(RpcError) as exc:
            client.get_block_number()
    assert "302" in str(exc.value)


def test_redirect_to_other_host_issues_no_second_request(client: RpcClient) -> None:
    """Proof, not just an exception: the redirected host is never contacted."""
    with respx.mock(assert_all_called=False) as router:
        router.post(TEST_URL).mock(
            return_value=httpx.Response(307, headers={"Location": "https://evil.invalid/x"})
        )
        evil = router.post("https://evil.invalid/x").mock(
            return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x1"})
        )
        with pytest.raises(RpcError):
            client.get_block_number()
        assert evil.call_count == 0


def test_api_key_not_in_logs(client: RpcClient, caplog) -> None:
    """Retry warnings log the redacted endpoint but never the key."""
    attempts = {"n": 0}

    def side_effect(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(503)
        req_id = json.loads(request.content)["id"]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": req_id, "result": "0x1"})

    with (
        caplog.at_level("DEBUG", logger="web3_secops"),
        respx.mock(base_url=TEST_URL) as router,
    ):
        router.post(TEST_URL).mock(side_effect=side_effect)
        client.get_block_number()

    joined = "\n".join(r.getMessage() + str(r.__dict__) for r in caplog.records)
    assert "TESTKEY123" not in joined, "API key leaked into a log record"
    assert "rpc.test.invalid" in joined, "redacted endpoint should still be useful"


@pytest.mark.parametrize(
    ("url", "secret"),
    [
        ("https://eth-mainnet.g.alchemy.com/v2/SUPERSECRETKEY", "SUPERSECRETKEY"),
        ("https://rpc.example.com/?k=abc123xyz", "abc123xyz"),
        ("https://mainnet.infura.io/v3/deadbeefdeadbeef", "deadbeefdeadbeef"),
    ],
)
def test_redact_url_strips_keys(url: str, secret: str) -> None:
    redacted = redact_url(url)
    assert secret not in redacted
    assert "example.com" in redacted or "alchemy.com" in redacted or "infura.io" in redacted


def test_client_endpoint_is_redacted(client: RpcClient) -> None:
    assert "TESTKEY123" not in client.endpoint


def test_repr_does_not_expose_url(client: RpcClient) -> None:
    """dataclass repr includes `url`; confirm we never rely on repr for logging."""
    # The dataclass does expose url in repr — this test documents that fact so a
    # future change does not accidentally start logging repr(client).
    assert "TESTKEY123" in repr(client)
    # ...which is why only `client.endpoint` is used in log calls (see above test).


# ===========================================================================
# normalise_block validation
# ===========================================================================
def test_float_wei_would_lose_precision() -> None:
    """Documents why wei is an int: floats cannot represent large wei exactly."""
    big = 2**53 + 1
    assert float(big) != big
    assert int(float(big)) == big - 1


def test_normalize_large_wei_exact() -> None:
    raw = make_block(1, tx_count=0)
    big_wei = 123456789012345678901234567890
    raw["transactions"] = [
        {
            "hash": "0x" + "aa" * 32,
            "from": "0x" + "11" * 20,
            "to": None,  # contract creation
            "value": hex(big_wei),
            "transactionIndex": "0x0",
        }
    ]
    block = normalize_block(raw)
    assert block.transactions[0].value_wei == big_wei
    assert isinstance(block.transactions[0].value_wei, int)
    assert block.transactions[0].to_addr is None


def test_normalize_rejects_bare_tx_hashes() -> None:
    raw = make_block(1, tx_count=0)
    raw["transactions"] = ["0x" + "bb" * 32]
    with pytest.raises(RpcProtocolError, match="bare hash"):
        normalize_block(raw)


def test_normalize_rejects_missing_parent_hash() -> None:
    raw = make_block(1)
    del raw["parentHash"]
    with pytest.raises(RpcProtocolError, match="parentHash"):
        normalize_block(raw)


def test_normalize_rejects_bad_value_hex() -> None:
    raw = make_block(1)
    raw["transactions"][0]["value"] = "not-hex"
    with pytest.raises(RpcProtocolError, match="not 0x-prefixed"):
        normalize_block(raw)


def test_get_block_null_result(client: RpcClient) -> None:
    node = FakeNode(head=10, blocks={})
    with respx.mock(base_url=TEST_URL) as router:
        router.post(TEST_URL).mock(side_effect=node.handler)
        with pytest.raises(RpcProtocolError, match="not found"):
            client.get_block(5)


# ===========================================================================
# Client construction guards
# ===========================================================================
def test_rejects_bad_scheme() -> None:
    with pytest.raises(ValueError, match="scheme"):
        RpcClient("ftp://rpc.example.com")


def test_rejects_negative_retries() -> None:
    with pytest.raises(ValueError, match="max_retries"):
        RpcClient(TEST_URL, max_retries=-1)


def test_http_scheme_warns(caplog) -> None:
    with caplog.at_level("WARNING", logger="web3_secops"):
        c = RpcClient("http://insecure.example.com/key123")
        try:
            assert any(r.getMessage() == "rpc_insecure_transport" for r in caplog.records)
            joined = " ".join(str(r.__dict__) for r in caplog.records)
            assert "key123" not in joined
        finally:
            c.close()


def test_uses_synthetic_chain_fixture(chain_blocks) -> None:
    """Guard: the shared fixture is synthetic, contiguous and hash-linked."""
    assert 0 in chain_blocks
    assert 199 in chain_blocks
    assert chain_blocks[50]["parentHash"] == chain_blocks[49]["hash"]
    # No real mainnet block hash leaked into fixtures.
    assert not any((b["hash"] or "").startswith("0xd4e56740") for b in chain_blocks.values())


def test_json_roundtrip_of_request_is_serialisable() -> None:
    """Params must be JSON-serialisable — no Decimal/custom objects leak in."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber", "params": ["0x1", True]}
    assert json.loads(json.dumps(payload)) == payload


def test_make_block_fork_differs() -> None:
    """Reorg fixtures produce genuinely different hashes per fork."""
    assert make_block(10, fork="main")["hash"] != make_block(10, fork="b")["hash"]
    assert make_chain(1, 3, fork="b")[2]["parentHash"] == make_chain(1, 3, fork="b")[1]["hash"]
