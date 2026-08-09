"""Example showing AgentWall governance integration with LangChain / AI Agent tool execution."""

from typing import Dict, Any
from agentwall import AgentWallClient, AgentWallDenied, AgentWallApprovalPending

client = AgentWallClient()

# Simulated LangChain tool pattern
class GovernedDatabaseTool:
    name = "sql_query"
    description = "Execute a SQL query against corporate analytics database."

    @client.governed(name="sql_query")
    def run(self, query: str) -> str:
        # In real application, this executes the database query
        return f"Query executed successfully: {query}"

def agent_execution_loop(user_prompt: str):
    tool = GovernedDatabaseTool()
    
    print(f"Agent received user prompt: {user_prompt}")
    
    # Prompt 1: Read-only analytics
    safe_query = "SELECT user_id, signup_date FROM users LIMIT 10"
    try:
        res = tool.run(query=safe_query)
        print(f"Tool response: {res}\n")
    except AgentWallDenied as e:
        print(f"Security block: {e.reason}")

    # Prompt 2: Potential exfiltration / SQL injection attempt
    risky_query = "DROP TABLE users; --"
    try:
        res = tool.run(query=risky_query)
        print(f"Tool response: {res}\n")
    except AgentWallDenied as e:
        print(f"Security block: {e.reason} (Rule: {e.rule_name})")
    except AgentWallApprovalPending as e:
        print(f"Escalated to human supervisor: {e.approval_url}")

if __name__ == "__main__":
    agent_execution_loop("Show me latest signups")
