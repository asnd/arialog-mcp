"""Hermetic stand-in for the VRLI 8.18 API v2 (sessions, events, aggregated-events, version).

Mimics the documented behaviour that matters to clients:
* constraints live in the URL path (``field/<OP value>``), values percent-encoded;
* a query WITHOUT a timestamp constraint only covers the last minute;
* bearer sessions with a TTL.

Fault injection (POST /_stub/faults, DELETE to reset) lets tests exercise failure paths.
The payload shapes follow the public API docs; they are NOT verified against a real 8.18
appliance — see ARCHITECTURE.md open items.
"""

from __future__ import annotations

import os
import re
import secrets
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

HOSTS = ["esx-01", "esx-02", "esx-03"]
MIN = 60_000


def make_dataset(anchor_ms: int) -> list[dict[str, Any]]:
    """~2h of synthetic ESXi syslog ending at ``anchor_ms``.

    Baseline noise on three hosts, plus a SCSI-error burst on esx-02 from T-30m to T-25m and a
    few 'Lost access to volume' lines inside it (a classic APD pattern).
    """
    events: list[dict[str, Any]] = []

    def add(ts: int, host: str, app: str, text: str) -> None:
        events.append(
            {
                "text": text,
                "timestamp": ts,
                "fields": [
                    {"name": "hostname", "content": host},
                    {"name": "appname", "content": app},
                ],
            }
        )

    start = anchor_ms - 120 * MIN
    for i, ts in enumerate(range(start, anchor_ms, MIN)):
        for h_idx, host in enumerate(HOSTS):
            add(
                ts + h_idx * 1000,
                host,
                "Hostd",
                f"Accepted password for user svc-backup from 10.0.0.{(i % 200) + 1}",
            )
    burst_start = anchor_ms - 30 * MIN
    for n, ts in enumerate(range(burst_start, burst_start + 5 * MIN, 250)):
        add(
            ts,
            "esx-02",
            "vmkernel",
            f"ScsiDeviceIO: 3449: Cmd(0x45a2{n % 16:x}) 0x28, CmdSN 0x{n:x} "
            f"from world {1000 + n % 7} to dev "
            '"naa.600508b1001c3d0d" failed H:0x0 D:0x2 P:0x0 Valid sense data: 0x3 0x11 0x0.',
        )
    for k in range(4):
        add(
            burst_start + 90_000 + k * 20_000,
            "esx-02",
            "vmkernel",
            f"Lost access to volume 5f0d1c2e-7a3b4c5d-8e9f-0a1b2c3d4e5{k} (datastore-prod) "
            "due to connectivity issues. Recovery attempt is in progress",
        )
    events.sort(key=lambda e: e["timestamp"])
    return events


_OP = re.compile(r"^(>=|<=|!=|>|<|=|CONTAINS|NOT_CONTAINS|MATCHES|EXISTS|LAST)(?: (.*))?$", re.S)


def parse_constraints(path: str) -> list[tuple[str, str, str | None]]:
    parts = path.split("/") if path else []
    if len(parts) % 2:
        raise ValueError("constraints must be field/expression pairs")
    out: list[tuple[str, str, str | None]] = []
    for field, expr in zip(parts[::2], parts[1::2], strict=True):
        m = _OP.match(unquote(expr))
        if not m:
            raise ValueError(f"bad constraint expression: {unquote(expr)!r}")
        out.append((unquote(field), m.group(1), m.group(2)))
    return out


def create_app(
    *,
    anchor_ms: int | None = None,
    now_fn: Callable[[], int] | None = None,
    username: str | None = None,
    password: str | None = None,
) -> Starlette:
    anchor = anchor_ms if anchor_ms is not None else int(time.time() * 1000)
    now = now_fn or (lambda: anchor)
    user = username or os.environ.get("STUB_USER", "svc-test")
    pwd = password or os.environ.get("STUB_PASS", "placeholder")
    dataset = make_dataset(anchor)
    sessions: dict[str, float] = {}
    state: dict[str, Any] = {}

    def reset() -> None:
        state.clear()
        state.update(
            unavailable_next=0,
            partial=False,
            bad_json=False,
            latency_s=0.0,
            login_count=0,
            request_count=0,
            login_failures=0,
            ttl=1800,
        )

    reset()

    def window(cons: list[tuple[str, str, str | None]]) -> tuple[int, int]:
        lo, hi = now() - MIN, now() + 1  # documented default: the last minute only
        have_ts = False
        for field, op, val in cons:
            if field != "timestamp":
                continue
            if not have_ts:
                lo, hi, have_ts = -(2**62), 2**62, True
            v = int(val or 0)
            if op == "LAST":
                lo, hi = now() - v, now() + 1
            elif op == ">=":
                lo = max(lo, v)
            elif op == ">":
                lo = max(lo, v + 1)
            elif op == "<":
                hi = min(hi, v)
            elif op == "<=":
                hi = min(hi, v + 1)
        return lo, hi

    def match(ev: dict[str, Any], cons: list[tuple[str, str, str | None]]) -> bool:
        fields = {f["name"]: f["content"] for f in ev["fields"]}
        for field, op, val in cons:
            if field == "timestamp":
                continue
            target = ev["text"] if field == "text" else fields.get(field)
            if op == "EXISTS":
                ok = target is not None
            elif target is None:
                ok = op in ("!=", "NOT_CONTAINS")
            elif op == "CONTAINS":
                ok = (val or "").lower() in target.lower()
            elif op == "NOT_CONTAINS":
                ok = (val or "").lower() not in target.lower()
            elif op == "=":
                ok = target == val
            elif op == "!=":
                ok = target != val
            elif op == "MATCHES":
                ok = re.search(val or "", target) is not None
            else:
                ok = False
            if not ok:
                return False
        return True

    def select(path: str) -> list[dict[str, Any]]:
        cons = parse_constraints(path)
        lo, hi = window(cons)
        return [e for e in dataset if lo <= e["timestamp"] < hi and match(e, cons)]

    async def gate(request: Request, *, auth: bool = True) -> Response | None:
        state["request_count"] += 1
        if state["latency_s"]:
            import asyncio

            await asyncio.sleep(state["latency_s"])
        if state["unavailable_next"] > 0:
            state["unavailable_next"] -= 1
            return JSONResponse({"errorMessage": "Service starting"}, status_code=503)
        if auth:
            token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            if sessions.get(token, 0) < time.monotonic():
                return JSONResponse({"errorMessage": "Invalid session"}, status_code=401)
        return None

    async def login(request: Request) -> Response:
        if state["unavailable_next"] > 0:
            state["unavailable_next"] -= 1
            return JSONResponse({"errorMessage": "Service starting"}, status_code=503)
        body = await request.json()
        state["login_count"] += 1
        if (
            body.get("username") != user
            or body.get("password") != pwd
            or body.get("provider") not in ("Local", "ActiveDirectory", "vIDM")
        ):
            state["login_failures"] += 1
            return JSONResponse({"errorMessage": "Invalid credentials"}, status_code=401)
        token = secrets.token_hex(16)
        sessions[token] = time.monotonic() + state["ttl"]
        return JSONResponse({"userId": "u-1", "sessionId": token, "ttl": state["ttl"]})

    def body_or_bad_json(payload: dict[str, Any]) -> Response:
        if state["bad_json"]:
            return Response("<html>oops</html>", media_type="text/html")
        return JSONResponse(payload)

    async def events(request: Request) -> Response:
        if (r := await gate(request)) is not None:
            return r
        try:
            found = select(request.path_params.get("path", ""))
        except ValueError as exc:
            return JSONResponse({"errorMessage": str(exc)}, status_code=400)
        limit = int(request.query_params.get("limit", "100"))
        found.sort(
            key=lambda e: e["timestamp"],
            reverse=request.query_params.get("order-by-direction", "DESC") == "DESC",
        )
        complete = True
        if state["partial"]:
            found, complete = found[: max(1, len(found) // 2)], False
        return body_or_bad_json({"complete": complete, "events": found[:limit], "duration": 3})

    async def aggregated(request: Request) -> Response:
        if (r := await gate(request)) is not None:
            return r
        path = request.path_params.get("path", "")
        try:
            cons = parse_constraints(path)
            found = select(path)
        except ValueError as exc:
            return JSONResponse({"errorMessage": str(exc)}, status_code=400)
        lo, hi = window(cons)
        width = int(request.query_params.get("bin-width", "5000"))
        bins = []
        for b_lo in range(lo, hi, width):
            n = sum(1 for e in found if b_lo <= e["timestamp"] < b_lo + width)
            bins.append({"minTimestamp": b_lo, "maxTimestamp": b_lo + width, "value": n})
        return body_or_bad_json({"complete": not state["partial"], "bins": bins})

    async def version(request: Request) -> Response:
        if (r := await gate(request, auth=False)) is not None:
            return r
        return JSONResponse({"releaseName": "GA", "version": "8.18.3-24288990"})

    async def set_faults(request: Request) -> Response:
        if request.method == "DELETE":
            reset()
            sessions.clear()
        else:
            body = await request.json()
            if body.pop("expire_sessions", False):
                sessions.clear()
            state.update(body)
        return JSONResponse({k: v for k, v in state.items()})

    async def stats(_: Request) -> Response:
        return JSONResponse(
            {k: state[k] for k in ("login_count", "login_failures", "request_count")}
            | {"anchor_ms": anchor}
        )

    return Starlette(
        routes=[
            Route("/api/v2/sessions", login, methods=["POST"]),
            Route("/api/v2/events/{path:path}", events),
            Route("/api/v2/aggregated-events/{path:path}", aggregated),
            Route("/api/v1/version", version),
            Route("/_stub/faults", set_faults, methods=["POST", "DELETE"]),
            Route("/_stub/stats", stats),
        ]
    )


app = create_app()  # `uvicorn vrli_stub.app:app`
