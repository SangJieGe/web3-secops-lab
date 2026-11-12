"""Read-only Ethereum JSON-RPC client (M1-A).

Security boundary
-----------------
This module is the *only* place in the project that talks to a remote EVM node.
Its job is to make that conversation impossible to abuse.

1. **Explicit method allowlist** — only methods named in :data:`READ_ONLY_METHODS`
   may be sent. A prefix check such as ``method.startswith("eth_")`` is *not*
   sufficient: ``eth_sendRawTransaction`` and ``eth_sendTransaction`` are also
   ``eth_``-prefixed and both mutate chain state. Any method outside the
   allowlist raises :class:`ForbiddenMethodError` **before** a socket is opened,
   so no HTTP request is ever emitted.
2. **Bounded retries** — transient failures (HTTP 408/429/5xx, transport
   errors, and node-side JSON-RPC codes) are retried with exponential backoff
   plus jitter, capped by ``max_retries``. Permanent failures are raised
   immediately; nothing retries forever.
3. **Untrusted input** — every byte of the RPC response is treated as attacker
   controlled. The envelope is validated (JSON-RPC 2.0, matching ``id``, exactly
   one of ``result``/``error``), and payloads are decoded into plain Python
   values with explicit hex/int handling. Nothing is ever passed to ``eval``.
4. **No secrets in logs** — the RPC URL frequently embeds an API key
   (``https://eth-mainnet.g.alchemy.com/v2/<KEY>``). Log records carry only a
   redacted endpoint, never the raw URL.

This client cannot sign, cannot send a transaction, and holds no key material.
"""

from __future__ import annotations

import itertools
import json
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .logging_setup import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Read-only allowlist
# ---------------------------------------------------------------------------
# Everything this client is permitted to call. Adding a method here is a
# security-relevant change and must be reviewed: it must not mutate state, spend
# gas, unlock accounts, or sign anything.
#
# Explicitly *excluded* upstream (documented so reviewers see we considered them):
#   eth_sendRawTransaction, eth_sendTransaction, eth_sign, eth_signTransaction,
#   eth_signTypedData*, personal_*, wallet_*, account_*, miner_*, admin_*,
#   debug_*, txpool_* (leaks/mutates mempool state), eth_newFilter (server state).
READ_ONLY_METHODS: frozenset[str] = frozenset(
    {
        "eth_chainId",
        "eth_blockNumber",
        "eth_getBlockByNumber",
    }
)

# Methods we explicitly and permanently refuse, kept as a named set so tests can
# assert we reject exactly the dangerous ones we claim to reject.
FORBIDDEN_METHODS: frozenset[str] = frozenset(
    {
        "eth_sendRawTransaction",
        "eth_sendTransaction",
        "eth_sign",
        "eth_signTransaction",
        "eth_signTypedData",
        "eth_signTypedData_v4",
        "personal_unlockAccount",
        "personal_sendTransaction",
        "personal_sign",
        "wallet_addEthereumChain",
        "wallet_switchEthereumChain",
        "wallet_sendCalls",
    }
)

# HTTP statuses that indicate a transient condition worth retrying.
RETRYABLE_HTTP_STATUS: frozenset[int] = frozenset({408, 429, 500, 502, 503, 504})

# JSON-RPC error codes the node may return for a transient condition.
#   -32603 internal error, -32005 limit exceeded, plus the two non-standard
#   codes several providers use for rate limiting / unavailable upstream.
RETRYABLE_RPC_CODES: frozenset[int] = frozenset({-32603, -32005, 429, 503})

# Block identifier accepted by eth_getBlockByNumber.
BlockTag = str | int


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class RpcError(RuntimeError):
    """Transport-level or protocol-level failure talking to the node."""


class ForbiddenMethodError(RpcError, ValueError):
    """A method outside the read-only allowlist was requested.

    Raised *before* any network I/O happens.
    """


class RpcProtocolError(RpcError):
    """The node returned a response that violates JSON-RPC 2.0 or our schema."""


class RpcResponseError(RpcError):
    """The node returned a well-formed JSON-RPC ``error`` object.

    ``message`` comes straight off the wire and is fully attacker-controlled: a
    compromised or malicious node can echo the request URL — including its API
    key — back inside it. It is therefore *not* interpolated into the exception
    text. Only the numeric ``code`` appears in the message, which is enough to
    diagnose the failure class; the raw text is kept on the attribute for
    callers that explicitly opt in, and is sanitised before being stored.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"RPC error {code} (remote message withheld)")
        self.code = code
        # Retained for debugging, but never rendered into a log line by default.
        self.message = _scrub_remote_text(message)
        self.data = data


class RetriesExhausted(RpcError):
    """All retry attempts for a transient failure were used up."""


# ---------------------------------------------------------------------------
# URL redaction
# ---------------------------------------------------------------------------
def redact_url(url: str) -> str:
    """Return a log-safe form of an RPC URL.

    Providers commonly encode the API key in the path (``/v2/<KEY>``) or in a
    query string (``?api_key=<KEY>``). Both are stripped. The scheme and host
    are kept because they are operationally useful and not secret.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"

    if not parts.scheme or not parts.netloc:
        return "<unparseable-url>"

    host = parts.hostname or ""
    path = parts.path.rstrip("/")
    # Key material commonly sits in the path: /v2/<KEY> (Alchemy), /v3/<KEY>
    # (Infura), /<KEY> (Ankr, QuickNode-style endpoints). Keep at most the first
    # segment when there is more than one, and redact a single opaque segment
    # that cannot be a known route word.
    segments = [s for s in path.split("/") if s]
    safe_route_words = {"v1", "v2", "v3", "rpc", "jsonrpc", "mainnet", "sepolia"}
    if len(segments) > 1:
        path = "/" + segments[0] + "/<redacted>"
    elif segments and segments[0].lower() not in safe_route_words:
        path = "/<redacted>"
    elif segments:
        path = "/" + segments[0]

    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"

    # Query strings are dropped entirely: they carry keys far more often than
    # they carry operationally useful information.
    return urlunsplit((parts.scheme, netloc, path, "", ""))


# Keys that remote text is allowed to mention. Anything longer / more opaque is
# treated as potential key material and replaced.
_BENIGN_REMOTE_TOKENS = {
    "invalid",
    "argument",
    "arguments",
    "method",
    "params",
    "parameter",
    "request",
    "unauthorized",
    "forbidden",
    "missing",
    "header",
    "headers",
    "project",
    "projectid",
    "apikey",
    "api",
    "key",
    "rate",
    "limit",
    "exceeded",
    "too",
    "many",
    "requests",
    "internal",
    "server",
    "error",
    "unknown",
    "block",
    "transaction",
    "not",
    "found",
    "quantity",
    "hex",
}


def _scrub_remote_text(text: Any, max_len: int = 200) -> str:
    """Return a diagnostic-safe form of text that came off the wire.

    Remote error messages are attacker-controlled. A hostile or compromised node
    can put the caller's API key in one. This keeps the text useful for
    debugging — the message is still readable — while removing anything that
    looks like a URL, a long opaque token, or a hex blob.

    This is deliberately lossy: it is *not* a general-purpose sanitiser, it just
    guarantees that credential-shaped strings never survive.
    """
    if not isinstance(text, str):
        return "<non-string remote text>"

    out = text[:max_len]

    # Any URL anywhere in the text: keep scheme+host, drop path/query entirely.
    # A path is allowed only when it is a single known-benign route word.
    def _url_sub(match: re.Match[str]) -> str:
        return redact_url(match.group(0))

    out = re.sub(r"https?://[^\s\"'<>]+", _url_sub, out)

    # Any long high-entropy token (API keys, JWTs, hex blobs).
    def _token_sub(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.lower() in _BENIGN_REMOTE_TOKENS:
            return token
        if len(token) >= 32 and re.fullmatch(r"[0-9a-fA-F]+", token):
            return "<redacted>"
        if len(token) >= 20 and re.search(r"\d", token) and re.search(r"[A-Za-z]", token):
            return "<redacted>"
        if "-" in token and token.count("-") >= 2 and len(token) >= 24:
            # UUID-ish
            return "<redacted>"
        return token

    out = re.sub(r"[A-Za-z0-9_\-\.]{16,}", _token_sub, out)
    return out


def _redirect_destination(location: str) -> str:
    """Reduce a ``Location`` header to a log-safe host (or a placeholder).

    A redirect target is chosen by the remote node, not by us, so it must never
    be printed verbatim: a node under adversarial control can encode the
    caller's API key in the path or query of the redirect it hands back. The
    host alone is enough to tell an operator "something is rewriting our
    traffic", which is the only actionable signal here.
    """
    if not location:
        return "<no location>"

    try:
        parts = urlsplit(location)
    except ValueError:
        return "<unparseable location>"

    host = parts.hostname
    if not host:
        # Relative redirect, e.g. "/v2/key" or "//host/path". No host to show.
        return "<relative location>"

    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    if parts.scheme:
        return f"{parts.scheme}://{netloc}/<redacted-path>"
    return f"//{netloc}/<redacted-path>"


# ---------------------------------------------------------------------------
# Payload decoding helpers
# ---------------------------------------------------------------------------
def _require_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RpcProtocolError(f"{what} is not a JSON object (got {type(value).__name__})")
    return value


def _require_str(obj: dict[str, Any], key: str, what: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise RpcProtocolError(f"{what}.{key} missing or not a non-empty string")
    return value


def _require_quantity(obj: dict[str, Any], key: str, what: str) -> int:
    """Decode a JSON-RPC QUANTITY (hex string) into a Python int.

    Accepts only canonical ``0x``-prefixed hex. Anything else is rejected rather
    than guessed at, because a malformed quantity from an untrusted node is a
    signal, not something to coerce.
    """
    raw = obj.get(key)
    if not isinstance(raw, str):
        raise RpcProtocolError(f"{what}.{key} missing or not a string")
    if not raw.startswith("0x"):
        raise RpcProtocolError(f"{what}.{key} is not 0x-prefixed hex: {raw[:16]!r}")
    try:
        return int(raw, 16)
    except ValueError as exc:
        raise RpcProtocolError(f"{what}.{key} is not valid hex: {raw[:16]!r}") from exc


# ---------------------------------------------------------------------------
# Normalised domain objects
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class NormalizedTx:
    """One transaction, reduced to the fields M1 actually consumes.

    ``value_wei`` is an ``int``. Wei amounts routinely exceed the 2**53 limit
    where float arithmetic silently loses precision, so floats are never used.
    """

    hash: str
    from_addr: str
    to_addr: str | None
    value_wei: int
    transaction_index: int


@dataclass(frozen=True, slots=True)
class NormalizedBlock:
    """A block reduced to M1's fields, with all hex already decoded."""

    number: int
    hash: str
    parent_hash: str
    timestamp: int
    transactions: tuple[NormalizedTx, ...]


def normalize_block(raw: dict[str, Any]) -> NormalizedBlock:
    """Validate and decode a raw ``eth_getBlockByNumber`` result.

    Raises :class:`RpcProtocolError` on any structural problem. A block whose
    transactions are returned as bare hashes (``full_tx=False``) is rejected
    with a clear message instead of silently producing an empty tx list.
    """
    block = _require_dict(raw, "block")
    number = _require_quantity(block, "number", "block")
    block_hash = _require_str(block, "hash", "block")
    parent_hash = _require_str(block, "parentHash", "block")
    timestamp = _require_quantity(block, "timestamp", "block")

    raw_txs = block.get("transactions")
    if not isinstance(raw_txs, list):
        raise RpcProtocolError("block.transactions missing or not a list")

    txs: list[NormalizedTx] = []
    for idx, entry in enumerate(raw_txs):
        if not isinstance(entry, dict):
            raise RpcProtocolError(
                "block.transactions contains a bare hash; "
                "eth_getBlockByNumber must be called with full_transactions=True"
            )
        tx = _require_dict(entry, f"transaction[{idx}]")
        to_addr = tx.get("to")
        if to_addr is not None and not isinstance(to_addr, str):
            raise RpcProtocolError(f"transaction[{idx}].to is neither a string nor null")
        txs.append(
            NormalizedTx(
                hash=_require_str(tx, "hash", f"transaction[{idx}]"),
                from_addr=_require_str(tx, "from", f"transaction[{idx}]"),
                to_addr=to_addr,
                value_wei=_require_quantity(tx, "value", f"transaction[{idx}]"),
                transaction_index=(
                    _require_quantity(tx, "transactionIndex", f"transaction[{idx}]")
                    if "transactionIndex" in tx
                    else idx
                ),
            )
        )

    return NormalizedBlock(
        number=number,
        hash=block_hash,
        parent_hash=parent_hash,
        timestamp=timestamp,
        transactions=tuple(txs),
    )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
@dataclass
class RpcClient:
    """Synchronous, strictly read-only Ethereum JSON-RPC client.

    Example
    -------
    >>> with RpcClient("https://eth.llamarpc.com") as client:
    ...     chain_id = client.get_chain_id()
    ...     head = client.get_block_number()
    """

    # ``repr=False`` keeps the raw endpoint out of tracebacks, debugger output and
    # any f-string that formats a client. Dataclass reprs are otherwise an easy
    # way to leak a URL that carries an API key; ``.endpoint`` is the redacted
    # form and is the only project-approved way to render it.
    url: str = field(repr=False)
    timeout: float = 20.0
    max_retries: int = 3
    base_backoff: float = 0.5
    max_backoff: float = 8.0
    _id_counter: itertools.count = field(
        default_factory=lambda: itertools.count(1), init=False, repr=False
    )
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url:
            raise ValueError("rpc url must be a non-empty string")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        scheme = urlsplit(self.url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"rpc url scheme must be http(s), got {scheme!r}")
        if scheme == "http":
            log.warning(
                "rpc_insecure_transport",
                endpoint=redact_url(self.url),
                detail="plain HTTP sends the API key and all data in clear text",
            )
        self._client = self._build_client()

    def _build_client(self) -> httpx.Client:
        # follow_redirects is deliberately False. A redirect from an RPC provider
        # is not expected, and following one would silently re-send the request —
        # including any key in the URL — to a host we did not choose.
        return httpx.Client(
            timeout=httpx.Timeout(self.timeout),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "web3-secops-lab/0.2 (read-only)",
            },
            follow_redirects=False,
        )

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> RpcClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def endpoint(self) -> str:
        """Redacted endpoint, safe to log."""
        return redact_url(self.url)

    # -- internals ---------------------------------------------------------
    def _next_id(self) -> int:
        return next(self._id_counter)

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at ``max_backoff``."""
        ceiling = min(self.base_backoff * (2**attempt), self.max_backoff)
        return random.uniform(0.0, ceiling)

    def _validate_method(self, method: str) -> None:
        """Reject anything outside the allowlist. Called before any I/O."""
        if not isinstance(method, str):
            raise ForbiddenMethodError(f"method must be a string, got {type(method).__name__}")
        if method in FORBIDDEN_METHODS:
            raise ForbiddenMethodError(
                f"method {method!r} is explicitly forbidden: it can mutate state or sign data"
            )
        if method not in READ_ONLY_METHODS:
            raise ForbiddenMethodError(
                f"method {method!r} is not in the read-only allowlist ({sorted(READ_ONLY_METHODS)})"
            )

    def _parse_envelope(self, body: Any, expected_id: int) -> Any:
        """Validate a JSON-RPC 2.0 envelope and return ``result``."""
        if not isinstance(body, dict):
            raise RpcProtocolError(f"response is not a JSON object (got {type(body).__name__})")
        if body.get("jsonrpc") != "2.0":
            raise RpcProtocolError(
                f"response jsonrpc field is {body.get('jsonrpc')!r}, expected '2.0'"
            )

        response_id = body.get("id")
        # Providers sometimes echo the id as a string; compare numerically.
        if not _ids_match(response_id, expected_id):
            raise RpcProtocolError(
                f"response id {response_id!r} does not match request id {expected_id!r}"
            )

        has_result = "result" in body
        has_error = "error" in body and body["error"] is not None
        if has_result and has_error:
            raise RpcProtocolError("response contains both 'result' and 'error'")
        if not has_result and not has_error:
            raise RpcProtocolError("response contains neither 'result' nor 'error'")

        if has_error:
            err = body["error"]
            if not isinstance(err, dict):
                raise RpcProtocolError("error field is not a JSON object")
            code = err.get("code")
            if not isinstance(code, int):
                raise RpcProtocolError("error.code is not an integer")
            raise RpcResponseError(code, str(err.get("message", "unknown")), err.get("data"))

        return body["result"]

    # -- public API --------------------------------------------------------
    def call(self, method: str, params: list[Any] | None = None) -> Any:
        """Issue a single read-only JSON-RPC call and return its ``result``.

        Raises :class:`ForbiddenMethodError` (no I/O), :class:`RpcResponseError`
        (node-reported error), :class:`RpcProtocolError` (malformed response),
        or :class:`RetriesExhausted` (transient failure outlived the retry
        budget).
        """
        self._validate_method(method)
        if self._client is None:
            raise RuntimeError("client is closed")

        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or [],
        }
        request_id: int = payload["id"]
        last_error: Exception | None = None
        max_attempts = self.max_retries + 1

        for attempt in range(max_attempts):
            try:
                response = self._client.post(self.url, json=payload)
            except httpx.TransportError as exc:
                # Timeouts, connection resets, DNS blips, TLS flakes.
                last_error = exc
                if attempt < max_attempts - 1:
                    delay = self._backoff(attempt)
                    log.warning(
                        "rpc_transport_retry",
                        method=method,
                        endpoint=self.endpoint,
                        attempt=attempt + 1,
                        max_attempts=max_attempts,
                        sleep_ms=round(delay * 1000),
                        error=type(exc).__name__,
                    )
                    time.sleep(delay)
                    continue
                raise RetriesExhausted(
                    f"{method}: transport failure after {max_attempts} attempt(s): "
                    f"{type(exc).__name__}"
                ) from exc

            if response.status_code in RETRYABLE_HTTP_STATUS:
                last_error = RpcError(f"HTTP {response.status_code}")
                if attempt < max_attempts - 1:
                    delay = self._backoff(attempt)
                    log.warning(
                        "rpc_http_retry",
                        method=method,
                        endpoint=self.endpoint,
                        status=response.status_code,
                        attempt=attempt + 1,
                        max_attempts=max_attempts,
                        sleep_ms=round(delay * 1000),
                    )
                    time.sleep(delay)
                    continue
                raise RetriesExhausted(
                    f"{method}: HTTP {response.status_code} persisted after "
                    f"{max_attempts} attempt(s)"
                )

            if response.is_redirect:
                # follow_redirects=False, so a 3xx arrives here intact. Treat it
                # as a hard failure: chasing it would re-send the request —
                # including any key in the URL — to a host we did not choose.
                #
                # The Location header is fully attacker-controlled and may
                # itself contain the caller's credential (a redirect designed to
                # exfiltrate it). Only the destination host is retained, which
                # is the one diagnostic detail worth having; the path and query
                # are dropped wholesale.
                location = response.headers.get("location", "")
                safe_dest = _redirect_destination(location)
                raise RpcError(
                    f"{method}: unexpected HTTP {response.status_code} redirect "
                    f"to {safe_dest}; refusing to follow"
                )

            if response.status_code >= 400:
                # Permanent client/server error: retrying will not help.
                raise RpcError(f"{method}: HTTP {response.status_code} from {self.endpoint}")

            try:
                body = response.json()
            except (json.JSONDecodeError, ValueError) as exc:
                # A non-JSON body is a protocol failure, not a transient one.
                raise RpcProtocolError(
                    f"{method}: response body is not valid JSON "
                    f"({len(response.content)} bytes from {self.endpoint})"
                ) from exc

            try:
                return self._parse_envelope(body, request_id)
            except RpcResponseError as exc:
                if exc.code in RETRYABLE_RPC_CODES and attempt < max_attempts - 1:
                    delay = self._backoff(attempt)
                    log.warning(
                        "rpc_node_error_retry",
                        method=method,
                        endpoint=self.endpoint,
                        code=exc.code,
                        attempt=attempt + 1,
                        max_attempts=max_attempts,
                        sleep_ms=round(delay * 1000),
                    )
                    time.sleep(delay)
                    continue
                raise

        # Unreachable in practice: the loop either returns or raises.
        raise RetriesExhausted(f"{method}: retries exhausted (last error: {last_error})")

    # -- typed wrappers ----------------------------------------------------
    def get_chain_id(self) -> int:
        """``eth_chainId`` → int."""
        result = self.call("eth_chainId")
        if not isinstance(result, str) or not result.startswith("0x"):
            raise RpcProtocolError(f"eth_chainId result is not 0x-hex: {result!r}")
        try:
            return int(result, 16)
        except ValueError as exc:
            raise RpcProtocolError(f"eth_chainId result is not valid hex: {result!r}") from exc

    def get_block_number(self) -> int:
        """``eth_blockNumber`` → int, the current chain head."""
        result = self.call("eth_blockNumber")
        if not isinstance(result, str) or not result.startswith("0x"):
            raise RpcProtocolError(f"eth_blockNumber result is not 0x-hex: {result!r}")
        try:
            return int(result, 16)
        except ValueError as exc:
            raise RpcProtocolError(f"eth_blockNumber result is not valid hex: {result!r}") from exc

    def get_block(self, block: BlockTag, full_transactions: bool = True) -> NormalizedBlock:
        """``eth_getBlockByNumber`` → :class:`NormalizedBlock`.

        ``full_transactions`` defaults to True because M1 needs per-transaction
        fields. Passing ``False`` is supported but produces a block with an
        empty transaction tuple only if the node returns hashes — which
        :func:`normalize_block` rejects. Callers that want raw JSON should use
        :meth:`get_raw_block`.

        When ``block`` is a concrete height, the returned block's own ``number``
        must equal it. Without this check a faulty, lagging, or malicious node
        can answer block 100 with the contents of block 101 (or 99), and the
        scanner would happily persist the wrong block under the key it asked
        for — corrupting the chain of parent hashes that reorg detection depends
        on, and advancing the cursor past a block that was never stored.
        """
        tag = _to_block_tag(block)
        result = self.call("eth_getBlockByNumber", [tag, full_transactions])
        if result is None:
            raise RpcProtocolError(f"block {tag} not found (node returned null)")
        normalized = normalize_block(result)

        if isinstance(block, int) and normalized.number != block:
            raise RpcProtocolError(
                f"requested block {block} but node returned block {normalized.number} "
                f"(hash {normalized.hash[:10]}…); refusing to use a mismatched block"
            )
        return normalized

    def get_raw_block(self, block: BlockTag, full_transactions: bool = True) -> dict[str, Any]:
        """``eth_getBlockByNumber`` → the raw dict, unvalidated.

        Provided for callers that need fields M1 does not normalise. The caller
        owns validation in that case.
        """
        tag = _to_block_tag(block)
        result = self.call("eth_getBlockByNumber", [tag, full_transactions])
        if result is None:
            raise RpcProtocolError(f"block {tag} not found (node returned null)")
        return _require_dict(result, "block")


def _ids_match(response_id: Any, expected_id: int) -> bool:
    """Compare request/response ids, tolerating string-typed echoes.

    Some providers echo the id as ``"1"`` instead of ``1``. The value must still
    match — we only relax the type, never the value.
    """
    if response_id == expected_id:
        return True
    if isinstance(response_id, str):
        try:
            return int(response_id) == expected_id
        except ValueError:
            return False
    return False


def _to_block_tag(block: BlockTag) -> str:
    """Convert a block number or tag into an ``eth_getBlockByNumber`` parameter."""
    if isinstance(block, bool):
        raise TypeError("block must be an int or a tag string, not bool")
    if isinstance(block, int):
        if block < 0:
            raise ValueError("block number must be >= 0")
        return hex(block)
    if isinstance(block, str):
        if block in ("latest", "earliest", "pending", "safe", "finalized"):
            return block
        # Allow a caller to pass an already-hex-encoded number.
        if block.startswith("0x"):
            try:
                int(block, 16)
            except ValueError as exc:
                raise ValueError(f"invalid hex block tag: {block!r}") from exc
            return block
        raise ValueError(f"invalid block tag: {block!r}")
    raise TypeError(f"block must be int or str, got {type(block).__name__}")
