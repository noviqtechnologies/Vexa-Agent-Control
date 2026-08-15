/**
 * @vexa/agentwall — TypeScript client SDK for Vexa Agent Control AI Security Gateway & Firewall.
 */

export { AgentWallClient, AgentWallClient as AgentControlClient } from "./client.js";
export {
  AgentWallError,
  AgentWallDenied,
  AgentWallApprovalPending,
  AgentWallPivotError,
  AgentWallConnectionError,
} from "./errors.js";
export type {
  Verdict,
  ToolCallResult,
  GatewayStatus,
  ClientOptions,
} from "./types.js";
