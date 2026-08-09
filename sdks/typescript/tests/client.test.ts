import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AgentWallClient } from "../src/client.js";
import { AgentWallDenied, AgentWallApprovalPending, AgentWallPivotError } from "../src/errors.js";

describe("AgentWallClient", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("calls tool successfully when allowed", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: "1",
        result: { data: "success content" },
      }),
    });

    const client = new AgentWallClient("http://127.0.0.1:8080");
    const res = await client.callTool("read_file", { path: "test.txt" });

    expect(res.success).toBe(true);
    expect(res.verdict).toBe("allow");
    expect(res.data).toEqual({ data: "success content" });
  });

  it("throws AgentWallDenied on policy violation", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: "1",
        error: {
          code: -32001,
          message: "Path /etc/shadow is forbidden",
          data: { rule_name: "no_system_paths" },
        },
      }),
    });

    const client = new AgentWallClient("http://127.0.0.1:8080");

    await expect(
      client.callTool("read_file", { path: "/etc/shadow" })
    ).rejects.toThrow(AgentWallDenied);
  });

  it("throws AgentWallApprovalPending on HITL requirement", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: "req-1",
        error: {
          code: -32005,
          message: "Action requires human approval",
          data: {
            approval_id: "app-456",
            approval_url: "http://127.0.0.1:8080/ui/approve/app-456",
            timeout_seconds: 60,
          },
        },
      }),
    });

    const client = new AgentWallClient("http://127.0.0.1:8080");

    await expect(
      client.callTool("drop_table", { table: "users" })
    ).rejects.toThrow(AgentWallApprovalPending);
  });

  it("wraps functions transparently using client.governed()", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: "1",
        result: { status: "allowed" },
      }),
    });

    const client = new AgentWallClient("http://127.0.0.1:8080");

    const addNumbers = client.governed("add_numbers", async (args: { a: number; b: number }) => {
      return args.a + args.b;
    });

    const sum = await addNumbers({ a: 5, b: 7 });
    expect(sum).toBe(12);
  });
});
