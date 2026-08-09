# @vexa/agentwall

Zero-dependency TypeScript/JavaScript client for [Vexa AgentWall](https://github.com/noviqtechnologies/agentwall) AI Security Gateway & Firewall.

Routes AI agent tool calls and LLM egress through the out-of-process AgentWall proxy, enforcing default-deny policies, DLP secret redaction, prompt injection scanning, spend caps, and Human-in-the-Loop approvals.

## Installation

```bash
npm install @vexa/agentwall
```

## Quick Start

```typescript
import { AgentWallClient, AgentWallDenied, AgentWallApprovalPending } from "@vexa/agentwall";

// Auto-discovers local proxy at http://127.0.0.1:8080 or AGENTWALL_PROXY_URL env var
const client = new AgentWallClient();

// Method 1: Direct tool call routing
try {
  const result = await client.callTool("read_file", { path: "/workspace/doc.md" });
  console.log("Tool output:", result.data);
} catch (err) {
  if (err instanceof AgentWallDenied) {
    console.error(`Blocked by policy [${err.ruleName}]: ${err.message}`);
  } else if (err instanceof AgentWallApprovalPending) {
    console.warn(`Approval required: ${err.approvalUrl}`);
  }
}

// Method 2: Wrapper function for existing tools
const governedReadFile = client.governed("read_file", async (args: { path: string }) => {
  // Underlying implementation only runs if AgentWall policy permits
  const fs = await import("fs/promises");
  return fs.readFile(args.path, "utf-8");
});
```

## License

MIT License.
