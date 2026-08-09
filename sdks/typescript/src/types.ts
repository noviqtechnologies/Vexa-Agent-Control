/**
 * Core type definitions for AgentWall TypeScript client SDK.
 */

export type Verdict = "allow" | "deny" | "warn" | "escalate";

export interface ToolCallResult<T = unknown> {
  success: boolean;
  data: T;
  verdict: Verdict;
  toolName?: string;
  sessionId?: string;
  latencyMs?: number;
  rawResponse?: Record<string, unknown>;
}

export interface GatewayStatus {
  ready: boolean;
  version: string;
  listenAddress: string;
  policyLoaded: boolean;
  uptimeSeconds?: number;
  activeSessions?: number;
}

export interface ClientOptions {
  /**
   * Gateway URL (defaults to process.env.AGENTWALL_PROXY_URL or http://127.0.0.1:8080)
   */
  proxyUrl?: string;
  /**
   * Optional corporate OIDC JWT or bearer token
   */
  authToken?: string;
  /**
   * Request timeout in milliseconds (default: 30000)
   */
  timeoutMs?: number;
}
