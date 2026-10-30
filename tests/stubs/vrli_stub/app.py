"""Hermetic stand-in for the VRLI 8.18 API v2 (sessions, events, aggregated-events, version).

Mimics the documented behaviour that matters to clients (Log Insight query API docs):
* constraints live in the URL path, values percent-encoded; word operators are followed by a
  space (``CONTAINS%20x``), symbolic operators by the value directly (``%3E%3D123``);
* constraints sharing field AND operator are ORed, everything else is ANDed;
* CONTAINS matches a phrase of whole tokens, HAS every token in any order (case-insensitive);
* regex operators (``=~``/``!=~``) are disabled unless enabled on the appliance;
* a query WITHOUT a timestamp constraint only covers the last minute;
* 100 events/bins unless ``limit`` is given (max 20,000 events / 2,000 bins);
* fields found in the text are returned as ``startPosition``/``length``, not ``content``;
* bearer sessions with a TTL: unknown session -> 401, expired session -> 440;
* /api/v2/version requires a session.
Where the docs are silent, the stub takes the least convenient reading: aggregated bins are
epoch-aligned, sparse (empty bins omitted) and returned newest first.
* bearer sessions with a TTL, one per user (STUB_USERS={"user": "pass", ...} adds users
  next to STUB_USER/STUB_PASS; /_stub/stats counts requests per VRLI user).

Fault injection (POST /_stub/faults, DELETE to reset) lets tests exercise failure paths.
The payload shapes follow the public API docs; they are NOT verified against a real 8.18
appliance — see ARCHITECTURE.md open items.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

HOSTS = ["esx-01", "esx-02", "esx-03"]
MIN = 60_000
MAX_EVENTS = 20_000
MAX_BINS = 2_000

Constraint = tuple[str, str, str | None]


def make_dataset(anchor_ms: int) -> list[dict[str, Any]]:
    """~2h of synthetic ESXi syslog ending at ``anchor_ms``.

    Baseline noise on three hosts, plus a SCSI-error burst on esx-02 from T-30m to T-25m and a
    few 'Lost access to volume' lines inside it (a classic APD pattern). ``fields`` holds the
    canonical values used for matching; ``wire`` renders the documented response shape.
    """
    events: list[dict[str, Any]] = []

    def add(ts: int, host: str, app: str, msg: str) -> None:
        events.append(
            {
                "text": f"{host} {app}: {msg}",
                "timestamp": ts,
                "fields": {
                    "hostname": host,
                    "appname": app,
                    "source": f"10.0.0.{HOSTS.index(host) + 11}",
                },
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


def wire(ev: dict[str, Any]) -> dict[str, Any]:
    """Documented event shape: in-text fields as offsets, metadata fields with content."""
    out: list[dict[str, Any]] = [{"name": "source", "content": ev["fields"]["source"]}]
    for name in ("hostname", "appname"):
        value = ev["fields"][name]
        pos = ev["text"].find(value)
        out.append({"name": name, "startPosition": pos, "length": len(value)})
    return {"text": ev["text"], "timestamp": ev["timestamp"], "fields": out}


_WORD_OP = re.compile(r"^(CONTAINS|NOT_CONTAINS|HAS|NOT_HAS|LAST)( (.+))?$|^(EXISTS)$", re.S)
_SYM_OP = re.compile(r"^(!=~|=~|>=|<=|!=|>|<|=)(\S.*)$", re.S)
_TOKEN = re.compile(r"\w+")


def parse_constraints(path: str) -> list[Constraint]:
    parts = path.split("/") if path else []
    if len(parts) % 2:
        raise ValueError("constraints must be field/expression pairs")
    out: list[Constraint] = []
    for field, raw in zip(parts[::2], parts[1::2], strict=True):
        expr = unquote(raw)
        if m := _WORD_OP.match(expr):
            if m.group(4):
                out.append((unquote(field), "EXISTS", None))
                continue
            if m.group(3) is None:
                raise ValueError(f"{m.group(1)} needs a value")
            out.append((unquote(field), m.group(1), m.group(3)))
        elif m := _SYM_OP.match(expr):
            out.append((unquote(field), m.group(1), m.group(2)))
        else:
            raise ValueError(f"bad constraint expression: {expr!r}")
    return out


def _tokens(s: str) -> list[str]:
    return _TOKEN.findall(s.lower())


def _phrase_in(phrase: str, target: str) -> bool:
    p, t = _tokens(phrase), _tokens(target)
    return bool(p) and any(t[i : i + len(p)] == p for i in range(len(t) - len(p) + 1))


def _has_all(value: str, target: str) -> bool:
    p = set(_tokens(value))
    return bool(p) and p <= set(_tokens(target))


def _test(target: str | None, op: str, val: str | None) -> bool:
    if op == "EXISTS":
        return target is not None
    if target is None:
        return op in ("!=", "NOT_CONTAINS", "NOT_HAS", "!=~")
    v = val or ""
    return {
        "CONTAINS": lambda: _phrase_in(v, target),
        "NOT_CONTAINS": lambda: not _phrase_in(v, target),
        "HAS": lambda: _has_all(v, target),
        "NOT_HAS": lambda: not _has_all(v, target),
        "=": lambda: target.lower() == v.lower(),
        "!=": lambda: target.lower() != v.lower(),
        "=~": lambda: re.search(v, target) is not None,
        "!=~": lambda: re.search(v, target) is None,
    }.get(op, lambda: False)()


def create_app(
    *,
    anchor_ms: int | None = None,
    now_fn: Callable[[], int] | None = None,
    username: str | None = None,
    password: str | None = None,
    users: dict[str, str] | None = None,
) -> Starlette:
    anchor = anchor_ms if anchor_ms is not None else int(time.time() * 1000)
    now = now_fn or (lambda: anchor)
    user = username or os.environ.get("STUB_USER", "svc-test")
    pwd = password or os.environ.get("STUB_PASS", "placeholder")
    accounts = {user: pwd, **json.loads(os.environ.get("STUB_USERS", "{}")), **(users or {})}
    dataset = make_dataset(anchor)
    sessions: dict[str, tuple[float, str]] = {}
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
            regex_enabled=False,
            last_query={},
            requests_by_user={},
            logins_by_user={},
        )

    reset()

    def window(cons: list[Constraint]) -> tuple[int, int]:
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

    def match(ev: dict[str, Any], cons: list[Constraint]) -> bool:
        groups: dict[tuple[str, str], list[str | None]] = {}
        for field, op, val in cons:
            if field != "timestamp":
                groups.setdefault((field, op), []).append(val)  # same field+op -> OR
        fields = ev["fields"]
        return all(
            any(_test(ev["text"] if f == "text" else fields.get(f), op, v) for v in vals)
            for (f, op), vals in groups.items()
        )

    def select(path: str) -> tuple[list[Constraint], list[dict[str, Any]]]:
        cons = parse_constraints(path)
        if not state["regex_enabled"] and any(op in ("=~", "!=~") for _, op, _ in cons):
            raise ValueError("Regular expression queries are disabled")
        lo, hi = window(cons)
        return cons, [e for e in dataset if lo <= e["timestamp"] < hi and match(e, cons)]

    def limit_param(request: Request, maximum: int) -> int:
        limit = int(request.query_params.get("limit", "100"))
        if not 1 <= limit <= maximum:
            raise ValueError(f"limit must be 1-{maximum}")
        return limit

    async def gate(request: Request, *, auth: bool = True) -> Response | None:
        state["request_count"] += 1
        if state["latency_s"]:
            await asyncio.sleep(state["latency_s"])
        if state["unavailable_next"] > 0:
            state["unavailable_next"] -= 1
            return JSONResponse({"errorMessage": "Service starting"}, status_code=503)
        if auth:
            token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            expiry, who = sessions.get(token, (0.0, ""))
            if token not in sessions:
                return PlainTextResponse("Invalid session ID", status_code=401)
            if expiry < time.monotonic():
                return PlainTextResponse("Login Timeout", status_code=440)
            by_user = state["requests_by_user"]
            by_user[who] = by_user.get(who, 0) + 1
        return None

    async def login(request: Request) -> Response:
        if state["unavailable_next"] > 0:
            state["unavailable_next"] -= 1
            return JSONResponse({"errorMessage": "Service starting"}, status_code=503)
        body = await request.json()
        state["login_count"] += 1
        who = str(body.get("username"))
        if (
            who not in accounts
            or body.get("password") != accounts[who]
            or body.get("provider") not in ("Local", "ActiveDirectory", "vIDM")
        ):
            state["login_failures"] += 1
            return JSONResponse(
                {
                    "errorMessage": "Invalid credentials or account is locked.",
                    "errorCode": "FIELD_ERROR",
                },
                status_code=401,
            )
        state["logins_by_user"][who] = state["logins_by_user"].get(who, 0) + 1
        token = secrets.token_hex(16)
        sessions[token] = (time.monotonic() + state["ttl"], who)
        return JSONResponse({"userId": "u-1", "sessionId": token, "ttl": state["ttl"]})

    def body_or_bad_json(payload: dict[str, Any]) -> Response:
        if state["bad_json"]:
            return Response("<html>oops</html>", media_type="text/html")
        return JSONResponse(payload)

    async def events(request: Request) -> Response:
        if (r := await gate(request)) is not None:
            return r
        state["last_query"] = dict(request.query_params)
        try:
            limit = limit_param(request, MAX_EVENTS)
            _, found = select(request.path_params.get("path", ""))
        except ValueError as exc:
            return JSONResponse({"errorMessage": str(exc)}, status_code=400)
        found.sort(
            key=lambda e: e["timestamp"],
            reverse=request.query_params.get("order-by-direction", "DESC") == "DESC",
        )
        complete = True
        if state["partial"]:
            found, complete = found[: max(1, len(found) // 2)], False
        return body_or_bad_json(
            {"complete": complete, "events": [wire(e) for e in found[:limit]], "duration": 3}
        )

    async def aggregated(request: Request) -> Response:
        if (r := await gate(request)) is not None:
            return r
        state["last_query"] = dict(request.query_params)
        try:
            limit = limit_param(request, MAX_BINS)
            cons, found = select(request.path_params.get("path", ""))
        except ValueError as exc:
            return JSONResponse({"errorMessage": str(exc)}, status_code=400)
        lo, hi = window(cons)
        width = int(request.query_params.get("bin-width", "5000"))
        counts: dict[int, int] = {}
        for e in found:
            b_lo = e["timestamp"] - e["timestamp"] % width  # epoch-aligned
            counts[b_lo] = counts.get(b_lo, 0) + 1
        bins = [
            {"minTimestamp": b, "maxTimestamp": b + width - 1, "value": n}
            for b, n in sorted(counts.items(), reverse=True)  # sparse, newest first
        ]
        return body_or_bad_json({"complete": not state["partial"], "bins": bins[:limit]})

    async def version(request: Request) -> Response:
        if (r := await gate(request)) is not None:
            return r
        return JSONResponse({"releaseName": "GA", "version": "8.18.3-24288990"})

    async def set_faults(request: Request) -> Response:
        if request.method == "DELETE":
            reset()
            sessions.clear()
        else:
            body = await request.json()
            if body.pop("expire_sessions", False):  # appliance forgot them -> 401
                sessions.clear()
            if body.pop("timeout_sessions", False):  # sessions timed out -> 440
                for token, (_, who) in sessions.items():
                    sessions[token] = (0.0, who)
            state.update(body)
        return JSONResponse({k: v for k, v in state.items()})

    async def stats(_: Request) -> Response:
        return JSONResponse(
            {
                k: state[k]
                for k in (
                    "login_count",
                    "login_failures",
                    "request_count",
                    "last_query",
                    "requests_by_user",
                    "logins_by_user",
                )
            }
            | {"anchor_ms": anchor}
        )

    return Starlette(
        routes=[
            Route("/api/v2/sessions", login, methods=["POST"]),
            Route("/api/v2/events/{path:path}", events),
            Route("/api/v2/aggregated-events/{path:path}", aggregated),
            Route("/api/v2/version", version),
            Route("/_stub/faults", set_faults, methods=["POST", "DELETE"]),
            Route("/_stub/stats", stats),
        ]
    )


app = create_app()  # `uvicorn vrli_stub.app:app`
