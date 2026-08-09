/**
 * AgentWall client implementation for TypeScript / JavaScript runtimes.
 */

import { HttpTransport } from "./transport.js";
import { ClientOptions, GatewayStatus, ToolCallResult } from "./types.js";

export class AgentWallClient {
  private readonly transport: HttpTransport;

  constructor(options?: ClientOptions | string) {
    const opts = typeof options === "string" ? { proxyUrl: options } : options;
    this.transport = new HttpTransport(opts);
  }

  /**
   * Gateway URL currently targeted.
   */
  public get proxyUrl(): string {
    return this.transport.proxyUrl;
  }

  /**
   * Check gateway readiness and status.
   */
  async getStatus(): Promise<GatewayStatus> {
    return this.transport.getStatus();
  }

  /**
   * Routes a tool call through AgentWall out-of-process gateway for policy evaluation.
   *
   * @param toolName Target tool name (e.g., 'read_file')
   * @param args Tool parameters dictionary
   * @param sessionId Optional explicit session UUID
   */
  async callTool<T = unknown>(
    toolName: string,
    args: Record<string, unknown>,
    sessionId?: string
  ): Promise<ToolCallResult<T>> {
    return this.transport.evaluateAndCall<T>(toolName, args, sessionId);
  }

  /**
   * Wraps an existing tool execution function so that every execution is first
   * authorized by the AgentWall security gateway before the underlying handler executes.
   *
   * @param toolName The name of the tool as configured in the policy
   * @param fn The implementation function
   */
  governed<TArgs extends Record<string, unknown>, TResult>(
    toolName: string,
    fn: (args: TArgs) => Promise<TResult> | TResult
  ): (args: TArgs, sessionId?: string) => Promise<TResult> {
    return async (args: TArgs, sessionId?: string): Promise<TResult> => {
      // 1. Authorize on the proxy wire
      await this.callTool(toolName, args, sessionId);
      // 2. Execute underlying handler if allowed
      return await fn(args);
    };
  }
}
