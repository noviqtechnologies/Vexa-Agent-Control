-- Migration: 000003_seed_default_policy
-- Seeds a default AgentWall policy into the policies table IF none exists.
-- This ensures the system works out of the box on first boot without requiring
-- an admin to manually create a policy before agents can connect.
--
-- The default policy:
--   - version: "2" (Schema v2, required by the gateway v6.1+)
--   - default_action: deny (secure by default — unknown tools are blocked)
--   - Allows the most common safe MCP tools with no parameter restrictions
--   - Enables the agent firewall for cycle/loop detection
--   - Rate-limited to 10 calls/second per session
--
-- Admins can refine this policy at any time via the Policy Editor page in the
-- dashboard. Every save creates a new version in this table and the gateway
-- hot-swaps it within POLICY_POLL_INTERVAL_SECS seconds (default: 30).

BEGIN;

INSERT INTO policies (version, content, is_active, created_at, updated_at)
SELECT
    'v1.0.0',
    $POLICY$version: "2"
default_action: deny

# Rate limiting: maximum tool calls per agent session per second
session:
  max_calls_per_second: 10

# LLM Governance & Prompt DLP
llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-3.5-turbo"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"

# Tool allowlist — add or restrict tools as needed.
# All unlisted tools are blocked by default_action: deny.
tools:
  # File system — read access only (write_file is intentionally omitted)
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        required: true

  - name: "list_directory"
    action: allow
    parameters:
      - name: "directory"
        type: string
        required: true

  # MCP introspection — always safe
  - name: "tools/list"
    action: allow

  - name: "get_schema"
    action: allow

  - name: "ping"
    action: allow

  # Shell execution — allowed but review carefully before enabling in production.
  # Consider adding a pattern constraint (e.g. pattern: "^(ls|pwd|echo .*)$").
  - name: "exec_shell"
    action: allow
    parameters:
      - name: "command"
        type: string
        required: true

  # File write — disabled by default. Remove the comment below to enable.
  # - name: "write_file"
  #   action: allow
  #   parameters:
  #     - name: "path"
  #       type: string
  #       required: true
  #     - name: "content"
  #       type: string
  #       required: true

# Agent firewall: detects and breaks tool-call loops / cycles
firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error  # Options: pivot_error, block, pause_interactive
$POLICY$,
    true,
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM policies WHERE is_active = true
);

COMMIT;
