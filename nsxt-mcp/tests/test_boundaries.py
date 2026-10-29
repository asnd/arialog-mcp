import json

import httpx
import pytest
from fastmcp import Client
from jsonschema import Draft202012Validator
from stub_nsx import NSXStub

from nsxt_mcp.client import TargetRegistry
from nsxt_mcp.config import CredentialProfile
from nsxt_mcp.credentials import CredentialProvider
from nsxt_mcp.errors import AuthenticationFailed, ContractError, LimitExceeded, Unavailable
from nsxt_mcp.server import create_server


async def test_short_and_empty_pages_continue_and_opaque_cursor_is_encoded_once(settings, caller):
    opaque = "opaque+/=&% ?cursor"
    calls = []

    def stub(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json={"results": [], "cursor": opaque})
        assert request.url.params["cursor"] == opaque
        return httpx.Response(200, json={"results": [{"id": "one"}]})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    result = await registry.list_pages("a", "tier0s", caller, page_size=100)
    assert result.complete and result.pages == 2 and result.items == [{"id": "one"}]
    assert len(calls) == 2  # Empty/short pages are not an end-of-list signal.
    await registry.aclose()


async def test_empty_last_page_is_success(settings, caller):
    registry = TargetRegistry(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"results": []}))
    )
    page = await registry.list_pages("a", "tier0s", caller)
    assert page.complete and page.next_cursor is None and page.items == []
    await registry.aclose()


async def test_page_retry_does_not_duplicate_or_skip_results(settings, caller):
    cursors = []

    async def no_sleep(_):
        pass

    def stub(request):
        cursor = request.url.params.get("cursor")
        cursors.append(cursor)
        if cursor is None:
            return httpx.Response(200, json={"results": [{"id": "first"}], "cursor": "second"})
        if len(cursors) == 2:
            return httpx.Response(503, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"results": [{"id": "last"}]})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub), sleep=no_sleep)
    page = await registry.list_pages("a", "tier0s", caller)
    assert cursors == [None, "second", "second"]
    assert page.items == [{"id": "first"}, {"id": "last"}]
    assert page.pages == 2 and page.complete
    await registry.aclose()


async def test_later_page_failure_is_not_successful_partial_output(settings, caller):
    settings.attempts = 1

    def stub(request):
        if "cursor" not in request.url.params:
            return httpx.Response(200, json={"results": [{"id": "first"}], "cursor": "second"})
        return httpx.Response(503)

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    with pytest.raises(Unavailable):
        await registry.list_pages("a", "tier0s", caller)
    await registry.aclose()


async def test_non_adjacent_cursor_cycle_is_rejected(settings, caller):
    replies = iter(["one", "two", "one"])
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"results": [], "cursor": next(replies)})
        ),
    )
    with pytest.raises(ContractError, match="Repeated"):
        await registry.list_pages("a", "tier0s", caller)
    await registry.aclose()


@pytest.mark.parametrize("cursor", ["", 1, True, [], {}, "x" * 8193])
async def test_invalid_input_and_output_cursors_fail_without_restarting(settings, caller, cursor):
    calls = []

    def stub(request):
        calls.append(request)
        return httpx.Response(200, json={"results": [], "cursor": cursor})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    with pytest.raises(ContractError):
        await registry.list_pages("a", "tier0s", caller, cursor=cursor)
    assert not calls
    settings.max_pages = 1
    with pytest.raises(ContractError):
        await registry.list_pages("a", "tier0s", caller)
    assert len(calls) == 1  # Even a page-count stop cannot return a malformed next_cursor.
    await registry.aclose()


async def test_exact_item_cap_returns_page_boundary_cursor(settings, caller):
    settings.max_items = 2
    requests = []

    def stub(request):
        requests.append(request)
        return httpx.Response(200, json={"results": [{"id": 1}, {"id": 2}], "cursor": "next"})

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    page = await registry.list_pages("a", "tier0s", caller)
    assert len(requests) == 1 and len(page.items) == 2
    assert not page.complete and page.next_cursor == "next"
    await registry.aclose()


async def test_aggregate_byte_cap_applies_across_individually_small_pages(settings, caller):
    payload = {"results": [{"id": "x" * 50}], "cursor": "next"}
    settings.max_response_bytes = len(json.dumps(payload).encode()) + 10
    calls = []

    def stub(request):
        calls.append(request)
        return httpx.Response(
            200, json=payload if len(calls) == 1 else {"results": [{"id": "y" * 50}]}
        )

    registry = TargetRegistry(settings, transport=httpx.MockTransport(stub))
    with pytest.raises(LimitExceeded, match="Pagination budget"):
        await registry.list_pages("a", "tier0s", caller)
    assert len(calls) == 2
    await registry.aclose()


@pytest.mark.parametrize(
    "body",
    [
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":1e9999}',
        b'{"results":[{"nested":[NaN]}]}',
        b'{"value":"\xff"}',
    ],
)
async def test_non_finite_and_invalid_encoded_json_rejected(settings, caller, body):
    registry = TargetRegistry(
        settings, transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body))
    )
    with pytest.raises(ContractError, match="JSON"):
        await registry.get("a", "node_version", caller)
    await registry.aclose()


@pytest.mark.parametrize(
    "item",
    [
        {"id": "rule", "disabled": "false"},
        {"id": "rule", "logged": 1},
        {"id": "rule", "sequence_number": True},
        {"id": "rule", "sequence_number": -1},
        {"id": "rule", "scope": "ANY"},
        {"id": "rule", "services": [4]},
        {"action": "ALLOW"},
    ],
)
async def test_invalid_upstream_rule_fields_become_mcp_errors(settings, caller, item):
    registry = TargetRegistry(
        settings,
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"results": [item]})),
    )
    async with Client(create_server(registry, caller)) as client:
        result = await client.call_tool(
            "nsx_list_gateway_firewall_rules",
            {
                "target": "a",
                "policy_id": "p",
            },
            raise_on_error=False,
        )
        assert result.is_error
        assert "Invalid NSX policy object response" in str(result.content)
        assert result.structured_content is None


async def test_structured_results_validate_against_advertised_schemas(settings, caller):
    registry = TargetRegistry(settings, transport=httpx.MockTransport(NSXStub()))
    cases = [
        ("nsx_list_gateway_firewall_rules", {"target": "a", "policy_id": "policy-1"}),
        (
            "nsx_get_group_members",
            {"target": "a", "group_id": "web", "member_type": "ip-addresses"},
        ),
        ("nsx_get_bgp_config", {"target": "a", "tier0_id": "t0", "locale_service_id": "ls"}),
        ("nsx_get_cluster_health", {"target": "a"}),
        ("nsx_get_fleet_health", {"targets": ["a", "b"]}),
    ]
    async with Client(create_server(registry, caller)) as client:
        schemas = {tool.name: tool.output_schema for tool in await client.list_tools()}
        for tool, arguments in cases:
            result = await client.call_tool(tool, arguments)
            Draft202012Validator(schemas[tool]).validate(result.structured_content)


def test_password_file_preserves_spaces_unicode_and_colons(settings, caller, tmp_path):
    password = tmp_path / "nsx.password"
    password.write_bytes("  pāss:word=#$  \r\n".encode())
    password.chmod(0o600)
    settings.credential_profiles["service"] = CredentialProfile(
        username_env="TEST_NSX_USER", password_file=password
    )
    credentials = CredentialProvider(settings).resolve("a", caller)
    assert credentials.password.get_secret_value() == "  pāss:word=#$  "


def test_password_file_requires_private_mode_and_bounded_size(settings, caller, tmp_path):
    password = tmp_path / "password"
    password.write_text("secret")
    settings.credential_profiles["service"] = CredentialProfile(
        username_env="TEST_NSX_USER", password_file=password
    )
    with pytest.raises(AuthenticationFailed, match="private regular file"):
        CredentialProvider(settings).resolve("a", caller)
    password.chmod(0o600)
    password.write_text("x" * 4097)
    with pytest.raises(AuthenticationFailed, match="size limit"):
        CredentialProvider(settings).resolve("a", caller)


@pytest.mark.parametrize("content", [None, b"", b"\xff"])
def test_missing_empty_or_invalid_password_file_is_sanitized(settings, caller, tmp_path, content):
    password = tmp_path / "private-secret-path"
    if content is not None:
        password.write_bytes(content)
        password.chmod(0o600)
    settings.credential_profiles["service"] = CredentialProfile(
        username_env="TEST_NSX_USER", password_file=password
    )
    with pytest.raises(AuthenticationFailed) as exc:
        CredentialProvider(settings).resolve("a", caller)
    assert "private-secret-path" not in str(exc.value)
