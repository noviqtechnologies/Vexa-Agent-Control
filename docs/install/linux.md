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
| **Linux x86_64 (AMD64)** | `agentcontrol-v1.0.65-linux-x86_64.zip` | **Yes (Verified)** |
| **Linux aarch64 (ARM64)** | `agentcontrol-v1.0.65-linux-aarch64.zip` | **Yes (Verified)** |

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

## Headless / Server Environments

When running in a headless Linux environment (e.g., remote SSH server, CI runner, or container) where no desktop browser is available:

```bash
# Start in background with browser launch disabled:
agentcontrol protect --no-browser &
```

Or run via `agentcontrol dev`:
```bash
agentcontrol dev --listen 0.0.0.0:8080 --no-browser
```

---

## Service Installation (systemd user daemon)

To keep Vexa running as a persistent background daemon:

```bash
agentcontrol service install
agentcontrol service status
```

To stop and remove the user service:
```bash
agentcontrol service uninstall
```

---

## Uninstallation

To cleanly restore all wrapped client configs and remove the binary:

```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.sh | bash
```
