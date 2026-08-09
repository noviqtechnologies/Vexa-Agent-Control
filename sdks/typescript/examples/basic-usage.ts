import { AgentWallClient, AgentWallDenied, AgentWallApprovalPending } from "../src/index.js";

async function main() {
  const client = new AgentWallClient("http://127.0.0.1:8080");

  console.log("Checking gateway health...");
  try {
    const status = await client.getStatus();
    console.log(`Gateway is ready: ${status.ready} on ${status.listenAddress}`);
  } catch (e) {
    console.warn(`Gateway not reachable locally: ${e}`);
    console.log("Continuing demonstration...\n");
  }

  // Define a governed file reader tool
  const governedReadFile = client.governed(
    "read_file",
    async (args: { path: string }) => {
      console.log(`[Executing] Reading file: ${args.path}`);
      return "DB_HOST=127.0.0.1\nDB_PORT=5432";
    }
  );

  console.log("--- Test 1: Allowed Tool Call ---");
  try {
    const content = await governedReadFile({ path: "/workspace/config.env" });
    console.log(`Content:\n${content}\n`);
  } catch (err) {
    console.error("Denied:", err);
  }

  console.log("--- Test 2: Denied Tool Call ---");
  try {
    await governedReadFile({ path: "/etc/shadow" });
  } catch (err) {
    if (err instanceof AgentWallDenied) {
      console.log(`Successfully intercepted violation: ${err.message}`);
      console.log(`Violated Rule: ${err.ruleName}`);
    } else if (err instanceof AgentWallApprovalPending) {
      console.log(`Action requires human supervisor: ${err.approvalUrl}`);
    }
  }
}

main().catch(console.error);
