"""A tiny in-process JSON-RPC server for entry-point tests.

The entry-point tests must exercise a *real* ``python -m`` subprocess going
through a *real* HTTP client, or they would not have caught the silent-stdout
bug they exist to guard. But they must also never touch the public internet:
CI runs without RPC credentials and a public endpoint can rate-limit, which
would turn a genuine regression into a flaky skip.

The compromise is a loopback HTTP server speaking just enough JSON-RPC 2.0 for
``eth_chainId`` and ``eth_blockNumber``. The subprocess talks to it over a real
socket, so buffering, flushing, redirect handling and URL redaction are all
exercised for real — nothing is mocked inside the child process.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

CHAIN_ID = 11155111  # Sepolia, to match the documented live-verification chain
HEAD = 0x5B8D80  # 6_000_000 — arbitrary but stable

# Planted in remote-controlled fields (redirect Location, JSON-RPC error text).
# If this ever shows up in a child process's output, the sanitiser has a hole.
SECRET_IN_REMOTE_TEXT = "FAKE_SUPER_SECRET_12345"


class _Handler(BaseHTTPRequestHandler):
    """Minimal JSON-RPC 2.0 responder."""

    protocol_version = "HTTP/1.1"

    # Silence the default stderr access log; tests capture stderr and a chatty
    # server would make "no unexpected output on stderr" assertions meaningless.
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)

        # A specific path makes the stub misbehave on purpose, so the
        # redirect- and error-sanitising paths can be driven end to end.
        if self.path.startswith("/redirect-with-secret"):
            self.send_response(302)
            self.send_header(
                "location", f"https://evil.example.com/steal?k={SECRET_IN_REMOTE_TEXT}"
            )
            self.send_header("content-length", "0")
            self.end_headers()
            return

        if self.path.startswith("/error-with-secret"):
            try:
                request = json.loads(raw)
            except json.JSONDecodeError:
                request = {}
            self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32000,
                        "message": f"unauthorized: bad key {SECRET_IN_REMOTE_TEXT}",
                    },
                },
            )
            return

        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid json"})
            return

        request_id = request.get("id")
        method = request.get("method")

        if method == "eth_chainId":
            self._send(200, {"jsonrpc": "2.0", "id": request_id, "result": hex(CHAIN_ID)})
        elif method == "eth_blockNumber":
            self._send(200, {"jsonrpc": "2.0", "id": request_id, "result": hex(HEAD)})
        else:
            # Everything else is a node-side error, which also exercises the
            # sanitiser path if a caller ever adds an unexpected method.
            self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "method not found"},
                },
            )

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LocalRpcServer:
    """Context manager running the JSON-RPC stub on a loopback port."""

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.url: str = ""

    def __enter__(self) -> LocalRpcServer:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        # Port 0 asks the OS for a free port; read it back so parallel test runs
        # cannot collide.
        host, port = self._server.server_address[:2]
        self.url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
