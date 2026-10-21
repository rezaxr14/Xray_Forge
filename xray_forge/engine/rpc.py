"""Minimal JSON-RPC 2.0 dispatcher (transport-agnostic)."""

from __future__ import annotations

import inspect
from typing import Any, Callable

from xray_forge.core.log import get_logger

log = get_logger(__name__)

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
APP_ERROR = -32000


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data

    def to_dict(self) -> dict:
        d = {"code": self.code, "message": self.message}
        if self.data is not None:
            d["data"] = self.data
        return d


def invalid_params(msg: str) -> RpcError:
    return RpcError(INVALID_PARAMS, msg)


def seconds(v, what: str, lo: float, hi: float) -> float:
    """A timeout in seconds: a real number (not a bool/str) within ``lo..hi``."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise invalid_params(f"{what} must be {lo:g}..{hi:g} seconds")
    return float(v)


class Dispatcher:
    def __init__(self) -> None:
        self._methods: dict[str, Callable[..., Any]] = {}

    def method(self, name: str | None = None):
        def deco(fn):
            self._methods[name or fn.__name__] = fn
            return fn
        return deco

    def names(self) -> list[str]:
        return sorted(self._methods)

    def _call(self, name: str, params: Any) -> Any:
        fn = self._methods.get(name)
        if fn is None:
            raise RpcError(METHOD_NOT_FOUND, f"unknown method: {name}")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise invalid_params("params must be an object")
        sig = inspect.signature(fn)
        accepts_kw = any(p.kind is p.VAR_KEYWORD for p in sig.parameters.values())
        if not accepts_kw:
            unknown = set(params) - set(sig.parameters)
            if unknown:
                raise invalid_params(f"unknown params: {', '.join(sorted(unknown))}")
        try:
            sig.bind(**params)
        except TypeError as e:
            raise invalid_params(str(e)) from None
        return fn(**params)

    def handle(self, request: Any) -> dict | None:
        """Process one decoded request; returns a response dict or None
        for notifications."""
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" \
                or not isinstance(request.get("method"), str):
            return {"jsonrpc": "2.0", "id": request.get("id")
                    if isinstance(request, dict) else None,
                    "error": RpcError(INVALID_REQUEST, "invalid request").to_dict()}
        rid = request.get("id")
        is_notification = "id" not in request
        try:
            result = self._call(request["method"], request.get("params"))
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        except RpcError as e:
            err = e
        except Exception as e:  # a bug or a domain failure; never kill the loop
            log.exception("method %s failed", request.get("method"))
            err = RpcError(APP_ERROR, f"{type(e).__name__}: {e}")
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": rid, "error": err.to_dict()}
