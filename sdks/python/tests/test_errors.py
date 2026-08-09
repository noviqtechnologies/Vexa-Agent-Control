"""Tests for AgentWall SDK exception types."""

from agentwall.errors import (
    AgentWallDenied,
    AgentWallApprovalPending,
    AgentWallPivotError,
    AgentWallConnectionError,
)


def test_denied_exception_properties():
    err = AgentWallDenied(
        message="Sensitive path blocked",
        code=-32001,
        tool_name="read_file",
        rule_name="no-sensitive-paths",
        reason="Pattern .ssh/ is forbidden",
        details={"path": "/home/user/.ssh/id_rsa"},
    )
    assert err.code == -32001
    assert err.tool_name == "read_file"
    assert err.rule_name == "no-sensitive-paths"
    assert err.reason == "Pattern .ssh/ is forbidden"
    assert err.details["path"] == "/home/user/.ssh/id_rsa"
    assert "Sensitive path blocked" in str(err)


def test_approval_pending_exception():
    err = AgentWallApprovalPending(
        message="High-risk command requires human approval",
        approval_id="app-12345",
        approval_url="http://127.0.0.1:8080/approve/app-12345",
        timeout_seconds=90,
    )
    assert err.approval_id == "app-12345"
    assert err.approval_url == "http://127.0.0.1:8080/approve/app-12345"
    assert err.timeout_seconds == 90


def test_pivot_error_exception():
    err = AgentWallPivotError("Cycle detected on repeated failure", attempts=3)
    assert err.attempts == 3
    assert "Cycle detected" in str(err)


def test_connection_error_exception():
    err = AgentWallConnectionError("Connection refused", "http://127.0.0.1:8080")
    assert err.proxy_url == "http://127.0.0.1:8080"
    assert "Connection refused" in str(err)
