/**
 * Exception types for AgentWall TypeScript client SDK.
 */

export class AgentWallError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentWallError";
  }
}

export class AgentWallConnectionError extends AgentWallError {
  public readonly proxyUrl: string;

  constructor(message: string, proxyUrl: string) {
    super(`${message} (Proxy URL: ${proxyUrl})`);
    this.name = "AgentWallConnectionError";
    this.proxyUrl = proxyUrl;
  }
}

export class AgentWallDenied extends AgentWallError {
  public readonly code: number;
  public readonly toolName?: string;
  public readonly ruleName: string;
  public readonly reason: string;
  public readonly details: Record<string, unknown>;

  constructor(options: {
    message: string;
    code?: number;
    toolName?: string;
    ruleName?: string;
    reason?: string;
    details?: Record<string, unknown>;
  }) {
    super(options.message);
    this.name = "AgentWallDenied";
    this.code = options.code ?? -32001;
    this.toolName = options.toolName;
    this.ruleName = options.ruleName ?? "default-deny";
    this.reason = options.reason ?? options.message;
    this.details = options.details ?? {};
  }
}

export class AgentWallApprovalPending extends AgentWallError {
  public readonly approvalId: string;
  public readonly approvalUrl?: string;
  public readonly timeoutSeconds: number;

  constructor(options: {
    message: string;
    approvalId: string;
    approvalUrl?: string;
    timeoutSeconds?: number;
  }) {
    super(options.message);
    this.name = "AgentWallApprovalPending";
    this.approvalId = options.approvalId;
    this.approvalUrl = options.approvalUrl;
    this.timeoutSeconds = options.timeoutSeconds ?? 60;
  }
}

export class AgentWallPivotError extends AgentWallError {
  public readonly attempts: number;

  constructor(message: string, attempts: number = 3) {
    super(message);
    this.name = "AgentWallPivotError";
    this.attempts = attempts;
  }
}
