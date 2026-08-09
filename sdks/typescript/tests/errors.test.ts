import { describe, it, expect } from "vitest";
import {
  AgentWallDenied,
  AgentWallApprovalPending,
  AgentWallPivotError,
  AgentWallConnectionError,
} from "../src/errors.js";

describe("AgentWall TypeScript SDK Errors", () => {
  it("constructs AgentWallDenied with full metadata", () => {
    const err = new AgentWallDenied({
      message: "Access to /etc/shadow blocked",
      code: -32001,
      toolName: "read_file",
      ruleName: "block_system_files",
      reason: "Access to system directory is restricted",
      details: { path: "/etc/shadow" },
    });

    expect(err.name).toBe("AgentWallDenied");
    expect(err.code).toBe(-32001);
    expect(err.toolName).toBe("read_file");
    expect(err.ruleName).toBe("block_system_files");
    expect(err.reason).toBe("Access to system directory is restricted");
    expect(err.details).toEqual({ path: "/etc/shadow" });
    expect(err.message).toBe("Access to /etc/shadow blocked");
  });

  it("constructs AgentWallApprovalPending with approval URL", () => {
    const err = new AgentWallApprovalPending({
      message: "Human approval needed",
      approvalId: "hitl-999",
      approvalUrl: "http://127.0.0.1:8080/ui/approve/hitl-999",
      timeoutSeconds: 45,
    });

    expect(err.name).toBe("AgentWallApprovalPending");
    expect(err.approvalId).toBe("hitl-999");
    expect(err.approvalUrl).toBe("http://127.0.0.1:8080/ui/approve/hitl-999");
    expect(err.timeoutSeconds).toBe(45);
  });

  it("constructs AgentWallPivotError with attempts", () => {
    const err = new AgentWallPivotError("Cycle detected", 3);
    expect(err.name).toBe("AgentWallPivotError");
    expect(err.attempts).toBe(3);
    expect(err.message).toBe("Cycle detected");
  });

  it("constructs AgentWallConnectionError with proxy URL", () => {
    const err = new AgentWallConnectionError("ECONNREFUSED", "http://127.0.0.1:8080");
    expect(err.name).toBe("AgentWallConnectionError");
    expect(err.proxyUrl).toBe("http://127.0.0.1:8080");
    expect(err.message).toContain("http://127.0.0.1:8080");
  });
});
