from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from arialog_mcp.client import VRLIClient
from arialog_mcp.config import Settings
from vrli_stub.app import create_app

ANCHOR_DT = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
ANCHOR = int(ANCHOR_DT.timestamp() * 1000)
START = "2026-10-07T10:00:00Z"
END = "2026-10-07T12:00:00Z"


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


async def no_sleep(_: float) -> None:
    return None


def make_settings(**over: Any) -> Settings:
    base: dict[str, Any] = dict(
        host="stub",
        port=9543,
        use_tls=False,
        username="svc-test",
        password="placeholder",
        provider="ActiveDirectory",
        retries=2,
        backoff_base_s=0.0,
        breaker_failures=2,
        breaker_cooldown_s=30.0,
        login_cooldown_s=60.0,
    )
    base.update(over)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


class Stub:
    def __init__(self, app: Any) -> None:
        self.app = app
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://stub"
        )

    async def faults(self, **kw: Any) -> None:
        (await self.http.post("/_stub/faults", json=kw)).raise_for_status()

    async def stats(self) -> dict[str, Any]:
        return (await self.http.get("/_stub/stats")).json()


@pytest.fixture
async def stub() -> AsyncIterator[Stub]:
    s = Stub(create_app(anchor_ms=ANCHOR))
    yield s
    await s.http.aclose()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
async def client(stub: Stub, clock: FakeClock) -> AsyncIterator[VRLIClient]:
    c = VRLIClient(
        make_settings(),
        transport=httpx.ASGITransport(app=stub.app),
        sleep=no_sleep,
        clock=clock,
    )
    yield c
    await c.aclose()
