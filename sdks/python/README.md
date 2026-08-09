# AgentWall Python Client SDK

Python client for the [Vexa AgentWall](https://github.com/noviqtechnologies/agentwall) AI Security Gateway & Firewall.

Routes AI agent tool calls and LLM egress through the out-of-process AgentWall proxy, enforcing default-deny policies, DLP secret redaction, prompt injection scanning, spend caps, and Human-in-the-Loop approvals without running governance logic in-process.

## Installation

```bash
pip install agentwall
```

## Quick Start

Make sure `agentwall` is running locally (`agentwall dev` or via Docker / Kubernetes):

```python
from agentwall import AgentWallClient, AgentWallDenied, AgentWallApprovalPending

# Auto-discovers local proxy at http://127.0.0.1:8080 or AGENTWALL_PROXY_URL env var
client = AgentWallClient()

# Method 1: Decorator for transparent governance
@client.governed
def read_project_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read()

# Safe call
try:
    content = read_project_file("/home/user/project/src/main.rs")
    print(content)
except AgentWallDenied as e:
    print(f"Blocked by policy: {e.rule_name} — {e.reason}")
except AgentWallApprovalPending as e:
    print(f"Action requires human approval: {e.approval_url}")

# Method 2: Direct tool call routing
result = client.call_tool("read_file", {"path": "/home/user/project/README.md"})
print(result.data)
```

## Async Support

```python
import asyncio
from agentwall import AsyncAgentWallClient

async def main():
    client = AsyncAgentWallClient()
    
    @client.governed
    async def async_fetch(url: str):
        # Your tool logic
        return "data"

    res = await async_fetch("https://api.internal.corp/data")
    print(res)

asyncio.run(main())
```

## LangChain Integration

```python
from langchain.tools import tool
from agentwall import AgentWallClient

client = AgentWallClient()

@tool
@client.governed
def query_customer_db(query: str) -> str:
    """Run read-only database query."""
    return db.execute(query)
```

## License

MIT License.
