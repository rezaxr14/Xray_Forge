"""stdio transport: one JSON-RPC message per line.

stdout is reserved for protocol traffic.  Anything a library prints is
redirected to stderr so it can never corrupt the stream.
"""

from __future__ import annotations

import json
import sys
import threading
from typing import IO

from xray_forge.core.log import get_logger
from xray_forge.engine import methods
from xray_forge.engine.rpc import PARSE_ERROR, RpcError

log = get_logger(__name__)

MAX_MESSAGE_BYTES = 8 * 1024 * 1024


def serve(stdin: IO[str] | None = None, stdout: IO[str] | None = None) -> int:
    stdin = stdin or sys.stdin
    out_stream = stdout or sys.stdout
    if stdout is None:
        sys.stdout = sys.stderr          # stray print() goes to stderr
    write_lock = threading.Lock()

    def send(msg: dict) -> None:
        data = json.dumps(msg, ensure_ascii=False, separators=(",", ":"), default=str)
        with write_lock:
            try:
                out_stream.write(data + "\n")
                out_stream.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass  # client went away; the read loop will end too

    dispatcher, jobs = methods.build(send)
    workers: list[threading.Thread] = []

    def handle(line: str) -> None:
        resp = None
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            send({"jsonrpc": "2.0", "id": None,
                  "error": RpcError(PARSE_ERROR, f"parse error: {e}").to_dict()})
            return
        if isinstance(req, list):    # batches are not supported
            send({"jsonrpc": "2.0", "id": None, "error": RpcError(
                -32600, "batch requests are not supported").to_dict()})
            return
        resp = dispatcher.handle(req)
        if resp is not None:
            send(resp)

    try:
        for raw in stdin:
            line = raw.strip()
            if not line:
                continue
            if len(line) > MAX_MESSAGE_BYTES:
                send({"jsonrpc": "2.0", "id": None, "error": RpcError(
                    -32600, "message too large").to_dict()})
                continue
            # requests run on their own thread so a slow call never blocks
            # job.cancel or the next request
            t = threading.Thread(target=handle, args=(line,), daemon=True)
            workers.append(t)
            t.start()
            workers[:] = [w for w in workers if w.is_alive()]
    finally:
        jobs.cancel_all()
        jobs.join(5.0)
        for w in workers:
            w.join(2.0)
    return 0
