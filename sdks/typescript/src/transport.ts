/**
 * Zero-dependency native fetch transport for AgentWall gateway.
 */

import {
  AgentWallConnectionError,
  AgentWallDenied,
  AgentWallApprovalPending,
  AgentWallPivotError,
  AgentWallError,
} from "./errors.js";
import { ToolCallResult, GatewayStatus, ClientOptions } from "./types.js";

const DEFAULT_GATEWAY_URL = "http://127.0.0.1:8080";

function resolveProxyUrl(options?: ClientOptions): string {
  if (options?.proxyUrl) {
    return options.proxyUrl.replace(/\/+$/, "");
  }
  if (typeof process !== "undefined" && process.env) {
    if (process.env.AGENTWALL_PROXY_URL) {
      return process.env.AGENTWALL_PROXY_URL.replace(/\/+$/, "");
    }
    if (process.env.HTTP_PROXY) {
      return process.env.HTTP_PROXY.replace(/\/+$/, "");
    }
  }
  return DEFAULT_GATEWAY_URL;
}

export class HttpTransport {
  public readonly proxyUrl: string;
  private readonly authToken?: string;
  private readonly timeoutMs: number;

  constructor(options?: ClientOptions) {
    this.proxyUrl = resolveProxyUrl(options);
    this.authToken =
      options?.authToken ||
      (typeof process !== "undefined" ? process.env?.AGENTWALL_AUTH_TOKEN : undefined);
    this.timeoutMs = options?.timeoutMs ?? 30000;
  }

  async getStatus(): Promise<GatewayStatus> {
    const url = `${this.proxyUrl}/ready`;
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(this.timeoutMs) });
      const ready = resp.status === 200;
      return {
        ready,
        version: "1.0",
        listenAddress: this.proxyUrl,
        policyLoaded: ready,
      };
    } catch (err: unknown) {
      throw new AgentWallConnectionError(
        `Failed to connect to gateway: ${err instanceof Error ? err.message : String(err)}`,
        this.proxyUrl
      );
    }
  }

  async evaluateAndCall<T = unknown>(
    toolName: string,
    argumentsObj: Record<string, unknown>,
    sessionId?: string
  ): Promise<ToolCallResult<T>> {
    const sid = sessionId || (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));
    const reqId = typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);

    const payload = {
      jsonrpc: "2.0",
      id: reqId,
      method: "tools/call",
      params: {
        name: toolName,
        arguments: argumentsObj,
      },
    };

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-AgentWall-Session-ID": sid,
    };
    if (this.authToken) {
      headers["Authorization"] = `Bearer ${this.authToken}`;
    }

    let resp: Response;
    try {
      resp = await fetch(`${this.proxyUrl}/`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err: unknown) {
      throw new AgentWallConnectionError(
        `Gateway request failed: ${err instanceof Error ? err.message : String(err)}`,
        this.proxyUrl
      );
    }

    if (resp.status === 401) {
      throw new AgentWallDenied({
        message: "Unauthorized: Invalid OIDC or API token",
        code: 401,
        toolName,
      });
    }

    let data: any;
    try {
      data = await resp.json();
    } catch {
      if (!resp.ok) {
        throw new AgentWallDenied({
          message: `Gateway returned HTTP ${resp.status}`,
          toolName,
        });
      }
      throw new AgentWallError("Invalid JSON response from gateway");
    }

    if (data.error) {
      const err = data.error;
      const code = err.code ?? -32001;
      const msg = err.message ?? "Action denied by security gateway";
      const errData = err.data ?? {};

      if (code === -32010) {
        throw new AgentWallPivotError(msg, errData.attempts ?? 3);
      } else if (code === -32005 || msg.toLowerCase().includes("approval")) {
        throw new AgentWallApprovalPending({
          message: msg,
          approvalId: errData.approval_id ?? reqId,
          approvalUrl: errData.approval_url,
          timeoutSeconds: errData.timeout_seconds ?? 60,
        });
      } else {
        throw new AgentWallDenied({
          message: msg,
          code,
          toolName,
          ruleName: errData.rule_name || errData.pattern,
          reason: msg,
          details: errData,
        });
      }
    }

    return {
      success: true,
      data: (data.result ?? {}) as T,
      verdict: "allow",
      toolName,
      sessionId: sid,
      rawResponse: data,
    };
  }
}
