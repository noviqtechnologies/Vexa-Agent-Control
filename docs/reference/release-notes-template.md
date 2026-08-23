# Release Notes Specification & Template

This template defines the mandatory structure for every public release of Vexa Agent Control.

---

```markdown
# Vexa Agent Control vX.Y.Z

## Who Should Update
[One paragraph describing affected operating systems, clients, bug severity, and whether this update is recommended or mandatory.]

## Highlights
- **New Feature:** [Plain English description of what changed and the exact developer outcome].
- **Fix:** [Plain English description of the prior symptom, root cause, and confirmed fix].

## Compatibility Matrix
| Platform / Architecture | Release Asset Name | Status | Notes |
|---|---|---|---|
| macOS Apple Silicon (aarch64) | `agentcontrol-vX.Y.Z-macos-aarch64.zip` | Supported | SHA-256 Verified |
| macOS Intel (x86_64) | `agentcontrol-vX.Y.Z-macos-x86_64.zip` | Supported | SHA-256 Verified |
| Linux x86_64 | `agentcontrol-vX.Y.Z-linux-x86_64.zip` | Supported | SHA-256 Verified |
| Linux aarch64 | `agentcontrol-vX.Y.Z-linux-aarch64.zip` | Supported | SHA-256 Verified |
| Windows x86_64 | `agentcontrol-vX.Y.Z-windows-x86_64.zip` | Supported | SHA-256 Verified |
| Windows ARM64 (aarch64) | `agentcontrol-vX.Y.Z-windows-aarch64.zip` | [Status] | [Notes] |

## Upgrade Instructions
1. Stop any currently running local gateway or background service:
   ```bash
   agentcontrol service stop
   ```
2. Run the platform installer to fetch the new release:
   - macOS / Linux: `curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash`
   - Windows: `irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex`
3. Verify installed version:
   ```bash
   agentcontrol --version
   ```
4. Run live smoke test:
   ```bash
   agentcontrol verify
   ```

## Known Limitations & Experimental Features
- **Verified Integrations:** Claude Desktop, Cursor, Codex, Antigravity.
- **Experimental Integrations:** VS Code, JetBrains, Zed, Cline, OpenCode.

## Rollback Procedure
If issues arise, revert immediately to the prior release `vA.B.C`:
- macOS / Linux: `curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash -s -- -v vA.B.C`
- Windows: `.\install.ps1 -Version vA.B.C`

## Cryptographic Integrity
Download `checksums.txt` from the release assets and verify:
- macOS / Linux: `sha256sum -c checksums.txt --ignore-missing`
- Windows: `(Get-FileHash .\agentcontrol-*.zip -Algorithm SHA256).Hash`
```
