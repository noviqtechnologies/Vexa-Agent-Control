"""Unit tests for AgentWall client and transport."""

import pytest
import respx
import httpx
from agentwall.client import AgentWallClient, AsyncAgentWallClient
from agentwall.errors import (
    AgentWallDenied,
    AgentWallApprovalPending,
    AgentWallPivotError,
    AgentWallConnectionError,
)
from agentwall.types import Verdict


@respx.mock
def test_call_tool_allow():
    respx.post("http://127.0.0.1:8080/").respond(
        status_code=200,
        json={
            "jsonrpc": "2.0",
            "id": "1",
            "result": {"content": [{"type": "text", "text": "file contents"}]},
        },
    )

    client = AgentWallClient("http://127.0.0.1:8080")
    result = client.call_tool("read_file", {"path": "/workspace/doc.md"})

    assert result.success is True
    assert result.verdict == Verdict.ALLOW
    assert result.tool_name == "read_file"
    assert result.data["content"][0]["text"] == "file contents"
    client.close()


@respx.mock
def test_call_tool_denied_policy_violation():
    respx.post("http://127.0.0.1:8080/").respond(
        status_code=200,
        json={
            "jsonrpc": "2.0",
            "id": "1",
            "error": {
                "code": -32001,
                "message": "Access to path /.ssh/id_rsa is denied by rule 'no_sensitive_paths'",
                "data": {
                    "rule_name": "no_sensitive_paths",
                    "reason": "sensitive path access",
                },
            },
        },
    )

    client = AgentWallClient("http://127.0.0.1:8080")
    with pytest.raises(AgentWallDenied) as exc_info:
        client.call_tool("read_file", {"path": "/.ssh/id_rsa"})

    assert exc_info.value.code == -32001
    assert exc_info.value.rule_name == "no_sensitive_paths"
    assert "no_sensitive_paths" in str(exc_info.value)
    client.close()


@respx.mock
def test_call_tool_hitl_approval_required():
    respx.post("http://127.0.0.1:8080/").respond(
        status_code=200,
        json={
            "jsonrpc": "2.0",
            "id": "req-99",
            "error": {
                "code": -32005,
                "message": "Dangerous command requires human approval",
                "data": {
                    "approval_id": "app-abc-123",
                    "approval_url": "http://127.0.0.1:8080/ui/approve/app-abc-123",
                    "timeout_seconds": 60,
                },
            },
        },
    )

    client = AgentWallClient("http://127.0.0.1:8080")
    with pytest.raises(AgentWallApprovalPending) as exc_info:
        client.call_tool("execute_command", {"command": "drop database"})

    assert exc_info.value.approval_id == "app-abc-123"
    assert exc_info.value.approval_url == "http://127.0.0.1:8080/ui/approve/app-abc-123"
    client.close()


@respx.mock
def test_call_tool_loop_pivot_error():
    respx.post("http://127.0.0.1:8080/").respond(
        status_code=200,
        json={
            "jsonrpc": "2.0",
            "id": "req-100",
            "error": {
                "code": -32010,
                "message": "Cycle detected: repeated identical tool failures. Try alternative strategy.",
                "data": {
                    "action": "PivotError",
                    "attempts": 3,
                },
            },
        },
    )

    client = AgentWallClient("http://127.0.0.1:8080")
    with pytest.raises(AgentWallPivotError) as exc_info:
        client.call_tool("query_db", {"q": "syntax error query"})

    assert exc_info.value.attempts == 3
    client.close()


@respx.mock
def test_gateway_connection_failure():
    respx.post("http://127.0.0.1:8080/").mock(side_effect=httpx.ConnectError("Connection refused"))

    client = AgentWallClient("http://127.0.0.1:8080")
    with pytest.raises(AgentWallConnectionError):
        client.call_tool("read_file", {"path": "test.txt"})
    client.close()
