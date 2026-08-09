/**
 * @vexa/agentwall — TypeScript client SDK for Vexa AgentWall AI Security Gateway & Firewall.
 */

export { AgentWallClient } from "./client.js";
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
