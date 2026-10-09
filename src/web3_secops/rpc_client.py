"""Minimal read-only EVM JSON-RPC client.

Design goals
------------
* **Read-only** — only ``eth_*`` view methods are ever called. No signing,
  no ``eth_sendRawTransaction``, no accounts.
* **Resilient** — bounded exponential backoff with jitter on transient errors.
* **Batching** — send several JSON-RPC calls in one HTTP round-trip.
* **Simple** — one dependency (httpx), fully synchronous, easy to read.
"""

from __future__ import annotations

import itertools
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

log = structlog.get_logger(__name__)

# JSON-RPC error codes worth retrying (transient / node-side)
RETRYABLE_CODES = {-32603, -32000, 429, 503}
# HTTP statuses worth retrying
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


class RpcError(RuntimeError):
    """Raised when the node returns a JSON-RPC error object."""

    def __init__(self, code: int, message: str, payload: dict[str, Any] | None = None):
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.payload = payload or {}


@dataclass(slots=True)
class RpcClient:
    """Synchronous, read-only JSON-RPC client.

    Example
    -------
    >>> client = RpcClient("https://eth.llamarpc.com")
    >>> block = client.get_block_number()
    >>> client.close()
    """

    url: str
    timeout: float = 30.0
    max_retries: int = 4
    base_backoff: float = 0.5
    max_backoff: float = 8.0
    chain_id: int | None = None
    _id_counter: itertools.count = field(
        default_factory=lambda: itertools.count(1), repr=False
    )
    _client: httpx.Client = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.timeout),
            headers={"Content-Type": "application/json", "User-Agent": "web3-secops-lab/0.1"},
            follow_redirects=True,
        )

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> RpcClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- low level ---------------------------------------------------------
    def _next_id(self) -> int:
        return next(self._id_counter)

    def _backoff(self, attempt: int) -> float:
        delay = min(self.base_backoff * (2**attempt), self.max_backoff)
        return delay * (0.5 + random.random() * 0.5)  # full jitter

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        """Make a single JSON-RPC call, returning the ``result`` field.

        Retries transient failures with exponential backoff + jitter.
        Guarantees only read-only ``eth_*`` methods are issued.
        """
        if not method.startswith("eth_"):
            raise ValueError(f"refusing non-read-only method: {method!r}")

        payload = {"jsonrpc": "2.0", "id": self._next_id(), "method": method,
                   "params": params or []}
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                resp = self._client.post(self.url, json=payload)
                if resp.status_code in RETRYABLE_STATUS:
                    raise httpx.HTTPStatusError(
                        f"HTTP {resp.status_code}", request=resp.request, response=resp
                    )
                resp.raise_for_status()
                body = resp.json()
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    sleep = self._backoff(attempt)
                    log.warning("rpc_transport_retry", method=method, attempt=attempt,
                                sleep=round(sleep, 2), error=str(exc))
                    time.sleep(sleep)
                    continue
                raise RpcError(-1, f"transport failure: {exc}") from exc

            if "error" in body and body["error"]:
                err = body["error"]
                code = int(err.get("code", -1))
                if code in RETRYABLE_CODES and attempt < self.max_retries:
                    sleep = self._backoff(attempt)
                    log.warning("rpc_error_retry", method=method, code=code,
                                attempt=attempt, sleep=round(sleep, 2))
                    time.sleep(sleep)
                    continue
                raise RpcError(code, err.get("message", "unknown"), err.get("data"))

            return body.get("result")

        raise RpcError(-1, f"exhausted retries: {last_exc}")

    def batch(self, calls: list[tuple[str, list[Any]]]) -> list[Any]:
        """Execute multiple calls in one HTTP round-trip.

        ``calls`` is a list of ``(method, params)`` tuples. Returns results in
        the same order. Falls back to sequential calls if the node rejects
        batches (some providers disable it).
        """
        for method, _ in calls:
            if not method.startswith("eth_"):
                raise ValueError(f"refusing non-read-only method: {method!r}")

        if not calls:
            return []

        payload = [
            {"jsonrpc": "2.0", "id": self._next_id(), "method": m, "params": p}
            for m, p in calls
        ]
        try:
            resp = self._client.post(self.url, json=payload)
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:  # noqa: BLE001 — degrade gracefully
            log.warning("rpc_batch_failed_fallback", error=str(exc), count=len(calls))
            return [self.call(m, p) for m, p in calls]

        by_id = {item["id"]: item for item in body} if isinstance(body, list) else {}
        results: list[Any] = []
        for item in payload:
            entry = by_id.get(item["id"], {})
            if entry.get("error"):
                err = entry["error"]
                raise RpcError(int(err.get("code", -1)), err.get("message", "unknown"))
            results.append(entry.get("result"))
        return results

    # -- convenience wrappers ---------------------------------------------
    def get_block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def get_block(self, block: int | str, full_tx: bool = False) -> dict[str, Any]:
        tag = hex(block) if isinstance(block, int) else block
        return self.call("eth_getBlockByNumber", [tag, full_tx])

    def get_logs(
        self,
        from_block: int,
        to_block: int,
        address: str | list[str] | None = None,
        topics: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
        }
        if address:
            params["address"] = address
        if topics:
            params["topics"] = topics
        return self.call("eth_getLogs", [params]) or []

    def eth_call(self, to: str, data: str, block: int | str = "latest") -> str:
        tag = hex(block) if isinstance(block, int) else block
        return self.call("eth_call", [{"to": to, "data": data}, tag])

    def get_balance(self, address: str, block: int | str = "latest") -> int:
        tag = hex(block) if isinstance(block, int) else block
        return int(self.call("eth_getBalance", [address, tag]), 16)
