"""Unit tests for @client.governed decorator."""

import pytest
import respx
from agentwall.client import AgentWallClient, AsyncAgentWallClient
from agentwall.errors import AgentWallDenied


@respx.mock
def test_sync_governed_decorator_allow():
    respx.post("http://127.0.0.1:8080/").respond(
        status_code=200,
        json={"jsonrpc": "2.0", "id": "1", "result": {"status": "ok"}},
    )

    client = AgentWallClient("http://127.0.0.1:8080")

    @client.governed
    def compute_sum(a: int, b: int) -> int:
        return a + b

    res = compute_sum(10, 20)
    assert res == 30
    client.close()


@respx.mock
def test_sync_governed_decorator_denied():
    respx.post("http://127.0.0.1:8080/").respond(
        status_code=200,
        json={
            "jsonrpc": "2.0",
            "id": "1",
            "error": {
                "code": -32001,
                "message": "Blocked by policy",
                "data": {"rule_name": "block_all"},
            },
        },
    )

    client = AgentWallClient("http://127.0.0.1:8080")

    @client.governed
    def delete_records(table: str) -> bool:
        return True

    with pytest.raises(AgentWallDenied):
        delete_records("users")
    client.close()


@pytest.mark.asyncio
@respx.mock
async def test_async_governed_decorator_allow():
    respx.post("http://127.0.0.1:8080/").respond(
        status_code=200,
        json={"jsonrpc": "2.0", "id": "1", "result": {"status": "ok"}},
    )

    client = AsyncAgentWallClient("http://127.0.0.1:8080")

    @client.governed
    async def async_fetch_data(endpoint: str) -> str:
        return f"data from {endpoint}"

    res = await async_fetch_data("https://api.internal/stats")
    assert res == "data from https://api.internal/stats"
    await client.aclose()
