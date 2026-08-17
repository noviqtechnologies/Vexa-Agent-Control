/**
 * @vexa/agentcontrol — TypeScript client SDK for Vexa Agent Control AI Security Gateway & Firewall.
 */

export { AgentControlClient, AgentControlClient as AgentControlClient } from "./client.js";
export {
  AgentControlError,
  AgentControlDenied,
  AgentControlApprovalPending,
  AgentControlPivotError,
  AgentControlConnectionError,
} from "./errors.js";
export type {
  Verdict,
  ToolCallResult,
  GatewayStatus,
  ClientOptions,
} from "./types.js";
