# macOS Installation Guide

This guide covers installing Vexa Agent Control on macOS for both Apple Silicon (`aarch64` / M1/M2/M3/M4) and Intel (`x86_64`) hardware.

---

## Prerequisites

- macOS 12.0 (Monterey) or later
- Terminal with `zsh` (default on macOS) or `bash`
- `curl`, `unzip`, and `shasum` (installed by default on macOS)

---

## Architecture Matrix

| Apple Architecture | Release Asset Name | Supported |
|---|---|---|
| **Apple Silicon (M1/M2/M3/M4)** | `agentcontrol-v1.0.70-macos-aarch64.zip` | **Yes (Verified)** |
| **Intel Core (x86_64)** | `agentcontrol-v1.0.70-macos-x86_64.zip` | **Yes (Verified)** |

---

## Installation via Script (Recommended)

1. Open your Terminal and execute:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
   ```

2. Add `~/.local/bin` to your current shell session:
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

3. To make the PATH change permanent in `zsh` (macOS default):
   ```bash
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc
   ```

4. Verify installation:
   ```bash
   agentcontrol --version
   ```

---

## Alternative: Docker Deployment on macOS

If you have **Docker Desktop for Mac** installed and prefer not to install binaries on your host system:

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
docker compose -f docker-compose.team.yml up -d
```
Access the Web Management Console at `http://localhost:3000`. See the complete [Docker Deployment Guide](../guides/docker-deployment.md).

---

## Manual Installation & Checksum Verification

If you prefer to inspect and verify the binary manually before running:

1. Download the release asset and checksum manifest for your architecture:
   ```bash
   ARCH=$(uname -m)
   if [[ "$ARCH" == "arm64" ]]; then ARCH="aarch64"; fi
   VERSION="v1.0.70"

   curl -LO "https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/download/${VERSION}/agentcontrol-${VERSION}-macos-${ARCH}.zip"
   curl -LO "https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/download/${VERSION}/checksums.txt"
   ```

2. Verify the SHA-256 checksum:
   ```bash
   shasum -a 256 "agentcontrol-${VERSION}-macos-${ARCH}.zip"
   grep "agentcontrol-${VERSION}-macos-${ARCH}.zip" checksums.txt
   ```

3. Extract and move the binary to `~/.local/bin`:
   ```bash
   mkdir -p ~/.local/bin
   unzip -o "agentcontrol-${VERSION}-macos-${ARCH}.zip" -d ~/.local/bin/
   chmod +x ~/.local/bin/agentcontrol
   ```

---

## macOS Gatekeeper / Security Considerations

If macOS displays a warning stating *"agentcontrol cannot be opened because developer cannot be verified"*:

1. Run the following command in Terminal to clear the quarantine flag:
   ```bash
   xattr -d com.apple.quarantine ~/.local/bin/agentcontrol
   ```
2. Re-run `agentcontrol --version`.

---

## Starting Protection

After installation, run:

```bash
agentcontrol protect
```

To verify live enforcement:
```bash
agentcontrol verify
```

To cleanly uninstall:
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.sh | bash
```
