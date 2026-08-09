"""Basic usage example for AgentWall Python client SDK."""

import os
from agentwall import AgentWallClient, AgentWallDenied, AgentWallApprovalPending

def main():
    # Initialize client (connects to local agentwall proxy at 127.0.0.1:8080)
    client = AgentWallClient()

    print("Checking AgentWall gateway status...")
    try:
        status = client.status
        print(f"Gateway is ready: {status.ready} on {status.listen_address}")
    except Exception as e:
        print(f"Warning: Gateway not reachable locally: {e}")
        print("Continuing with demonstration...\n")

    # Example 1: Function decorated with @client.governed
    @client.governed
    def read_config_file(path: str) -> str:
        """Reads a configuration file from the filesystem."""
        print(f"[Executing] Reading file: {path}")
        return "DATABASE_URL=postgres://localhost:5432"

    print("--- Test 1: Allowed Tool Call ---")
    try:
        content = read_config_file("/workspace/app/config.json")
        print(f"Result: {content}\n")
    except AgentWallDenied as e:
        print(f"Denied: {e.reason}\n")

    print("--- Test 2: Denied Tool Call (Access to Sensitive Key) ---")
    try:
        content = read_config_file("/home/user/.ssh/id_rsa")
        print(f"Result: {content}\n")
    except AgentWallDenied as e:
        print(f"Successfully caught policy violation: {e.reason}")
        print(f"Violated rule: {e.rule_name}\n")
    except AgentWallApprovalPending as e:
        print(f"Requires human approval: {e.approval_url}\n")

if __name__ == "__main__":
    main()
