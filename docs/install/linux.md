# Linux Installation Guide

This guide covers installing Vexa Agent Control on Linux distributions (Ubuntu, Debian, Fedora, Arch, Alpine, Rocky Linux) for both `x86_64` and `aarch64` (ARM64) architectures.

---

## Prerequisites

- Linux kernel 5.4+ (glibc 2.31+ or musl via static binary)
- Standard utilities: `curl`, `unzip`, `sha256sum` (or `shasum`)

To install prerequisites on common distributions:
- **Ubuntu / Debian:** `sudo apt-get update && sudo apt-get install -y curl unzip coreutils`
- **Fedora / RHEL:** `sudo dnf install -y curl unzip coreutils`
- **Arch Linux:** `sudo pacman -S --needed curl unzip coreutils`

---

## Architecture Matrix

| Architecture | Release Asset Name | Supported |
|---|---|---|
| **Linux x86_64 (AMD64)** | `agentcontrol-v1.0.83-linux-x86_64.zip` | **Yes (Verified)** |
| **Linux aarch64 (ARM64)** | `agentcontrol-v1.0.83-linux-aarch64.zip` | **Yes (Verified)** |

---

## Installation via Script (Recommended)

1. Run the installer script:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
   ```

2. Add `~/.local/bin` to your current shell session:
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

3. Make PATH persistent in your shell config (e.g. `~/.bashrc` or `~/.zshrc`):
   ```bash
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
   source ~/.bashrc
   ```

4. Confirm installation:
   ```bash
   agentcontrol --version
   ```

---

## Alternative: Docker Deployment on Linux

If you have Docker Engine or Docker Desktop installed on Linux:

### Standalone Gateway Container
```bash
docker run -d \
  --name agentcontrol \
  -p 8080:8080 \
  -v agentcontrol-data:/app/data \
  -v agentcontrol-logs:/var/log/agentcontrol \
  -e AGENTCONTROL_ADMIN_TOKEN="admin123456" \
  ghcr.io/noviqtechnologies/agentcontrol:latest \
  start --listen 0.0.0.0:8080
```

### Full-Stack Control Hub (Compose)
```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
cp .env.team.example .env
docker compose -f docker-compose.team.yml up -d
```
Access the Web Management Console at `http://localhost:3000`. See the complete [Docker Deployment Guide](../guides/docker-deployment.md).

---

## Starting Protection

Launch the local security gateway and dashboard on `127.0.0.1:18080`:

```bash
agentcontrol start
```

*(To run as a persistent background systemd user service across reboots, run `agentcontrol service install`).*

---

## Connecting Coding Assistants

In a second terminal window:

```bash
agentcontrol connect codex
agentcontrol connect claude
agentcontrol connect vscode-continue
agentcontrol connect cursor
```

---

## Verification & Status

```bash
agentcontrol doctor
agentcontrol status
```

Open the Local Developer Dashboard in your browser:
```text
http://127.0.0.1:18080
```

---

## Clean Disconnect & Uninstallation

To cleanly disconnect an assistant:
```bash
agentcontrol disconnect codex
agentcontrol disconnect claude
```

To cleanly uninstall:
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall/uninstall.sh | bash
```
