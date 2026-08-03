## Prerequisites & Installation

Before getting started, ensure you have **Claude Desktop** (or Cursor/VS Code) installed, along with the `agentwall` binary on your system:

### Installing AgentWall
* **macOS / Linux / WSL:**
  ```bash
  curl -fsSL https://vexasec.io/install.sh | sh
  agentwall --version
  ```
* **Windows (PowerShell):**
  ```powershell
  irm https://vexasec.io/install.ps1 | iex
  agentwall.exe --version
  ```

---

## Step 1: Start the AgentWall Proxy

First, start AgentWall in **developer mode** (shadow proxy). In this mode, AgentWall watches the traffic between Claude Desktop and your computer without blocking calls yet:

* **macOS / Linux:**
  ```bash
  agentwall dev
  ```
* **Windows (PowerShell):**
  ```powershell
  agentwall.exe dev
  ```

*AgentWall is now running and listening on `http://127.0.0.1:8080` (and opens the embedded browser dashboard at `http://127.0.0.1:8080`).*

---

## Step 2: Connect Claude Desktop to AgentWall

Open a **new, separate terminal window** and run the integration command:

* **macOS / Linux:**
  ```bash
  agentwall wrap claude
  agentwall status
  ```
* **Windows (PowerShell):**
  ```powershell
  agentwall.exe wrap claude
  agentwall.exe status
  ```
*(This command updates Claude Desktop's configuration file so its MCP tool traffic routes through the proxy. Running `agentwall status` verifies the wrapping status).*

---

## Step 3: Run a Real-World Scenario

1. Open **Claude Desktop** on your computer.
2. Ask Claude to do something harmless on your system. For example, type:
   > *"Claude, can you run the `whoami` command in my terminal and tell me my username? Also, can you read the contents of a text file on my Desktop?"*

Claude will use its tools to execute the command and read the file. Meanwhile, in your first terminal window, you will see AgentWall logging these actions!

---

## Step 4: Generate a Security Policy

Now that AgentWall has seen what tools Claude needs to use, we can generate a security policy (a firewall rule) that *only* allows those specific actions and blocks everything else.

In your second terminal window, run:

```bash
agentwall generate-policy --decay-window 30
```

This creates an `agentwall-policy.yaml` file in your current folder. If you open this file, you will see something like this:

```yaml
version: "2"
default_action: deny

tools:
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        # The policy noticed Claude ran "whoami" and automatically allowed it
        enum:
         - "whoami"

  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
```

---

## Step 5: Enforce the Policy

Right now, you are running `agentwall dev` (observation mode). Let's switch to **enforcement mode** to actually block bad behavior.

1. Go to your first terminal (where `agentwall dev` is running) and press `Ctrl + C` to stop it.
2. Start the gateway in enforcement mode using the policy we just generated:

```bash
agentwall start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
```

### Test the Firewall

Go back to Claude Desktop and ask it to do something malicious or unexpected:
> *"Claude, can you run the `rm -rf /` command?"* or *"Claude, can you read my `.env` file?"*

AgentWall will immediately intercept and **block** the request because it doesn't match the strict allowlist in your `agentwall-policy.yaml` file. You have successfully secured your AI Agent!

---

## Step 6: Clean Up (Optional)

If you ever want to remove AgentWall from Claude Desktop and return to normal, simply run:

```bash
agentwall unwrap claude
```
