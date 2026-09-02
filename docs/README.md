# Vexa Agent Control Documentation Hub

Welcome to the technical documentation for **Vexa Agent Control**. This directory is the single source of truth for installation, developer workflows, IDE integrations, runtime reference, and enterprise deployment.

---

## 🚀 Start Here

- **First time with Vexa?** Read the [10-Minute Developer Quickstart](quickstart.md).
- **Evaluating with Docker?** Read the [Docker Deployment Guide](guides/docker-deployment.md).
- **Evaluating in a team?** Read the [Small Team Hub Guide](guides/small-team-hub.md).

---

## 📚 Documentation Tree

```text
docs/
├── README.md                         # Documentation Hub entry point (this page)
├── quickstart.md                     # 10-minute local developer journey
├── install/                          # Platform-specific installation guides
│   ├── macos.md                      # macOS Apple Silicon & Intel
│   ├── linux.md                      # Generic Linux & headless servers
│   ├── wsl.md                        # WSL2 boundary & Windows host integration
│   ├── windows-powershell.md         # Windows 10/11 (PowerShell)
│   └── windows-cmd.md                # Windows Command Prompt
├── guides/                           # Workflow guides
│   ├── docker-deployment.md          # Docker deployment (standalone & full-stack compose)
│   ├── workstation.md                # Local developer workflow (Observe → Enforce → Restore)
│   ├── custom-agent-http.md          # Proxying Python/TS agents (LangChain, LlamaIndex, CrewAI)
│   ├── small-team-hub.md             # Shared team hub with Docker Compose
│   ├── run-explorer.md               # Run Explorer & forensic dossier workflows
│   └── effective-policy.md           # 5-level deterministic effective policy resolution
├── integrations/                     # IDE & client integration matrices and guides
│   ├── README.md                     # Verified vs. Experimental support matrix
│   ├── claude-desktop.md             # Claude Desktop MCP configuration
│   ├── cursor.md                     # Cursor IDE integration
│   ├── codex.md                      # ChatGPT Codex integration
│   └── antigravity.md                # Antigravity IDE integration
├── reference/                        # Authoritative technical references
│   ├── cli.md                        # Complete CLI commands and flags reference
│   ├── configuration.md              # Policy Schema v2, detectors, and canonical env vars
│   ├── paths-and-state.md            # Filesystem paths, state files, and logs
│   ├── troubleshooting.md            # Common first-run issues and diagnostics
│   ├── removal-and-recovery.md       # Safe manual and automated uninstallation
│   ├── legacy-migration.md           # Migration guide for AGENTWALL_* to AGENTCONTROL_*
│   └── release-notes-template.md     # Standardized release notes specification
└── advanced/                         # Platform, security, and enterprise infrastructure
    ├── team-operations.md            # OTET device enrollment, telemetry, spend caps
    ├── oidc.md                       # OIDC identity provider binding (Okta, Entra ID, Auth0)
    ├── kubernetes.md                 # Kubernetes Helm charts & HAR container sidecar
    ├── siem.md                       # Splunk, Datadog, and OpenSearch log export
    └── enterprise.md                 # CMK encryption, hardware PKI, compliance mappings
```

---

## 🎯 Quick Navigation by Topic

| Goal | Recommended Guide |
|---|---|
| Deploy with Docker / Compose | [Docker Deployment Guide](guides/docker-deployment.md) |
| Install binary on macOS | [macOS Installation Guide](install/macos.md) |
| Install binary on Linux | [Linux Installation Guide](install/linux.md) |
| Install binary on Windows | [Windows PowerShell Guide](install/windows-powershell.md) |
| Protect Claude Desktop | [Claude Desktop Integration](integrations/claude-desktop.md) |
| Protect Cursor IDE | [Cursor Integration](integrations/cursor.md) |
| Route LangChain / Custom Agent | [Custom Agent HTTP Guide](guides/custom-agent-http.md) |
| View All CLI Options | [CLI Reference](reference/cli.md) |
| Environment Variable Reference | [Configuration Reference](reference/configuration.md) |
| Clean Uninstall / Rollback | [Removal & Recovery Guide](reference/removal-and-recovery.md) |
| Organization & License Setup | [Organization Admin Guide](organization_admin_guide.md) |
| Migrating from `AGENTWALL_*` | [Legacy Migration Guide](reference/legacy-migration.md) |

---

## 🛡️ The Rule for Updating Documentation

1. Any code change that alters CLI flags, configuration schema, environment variables, or default paths **must** update the corresponding reference in `docs/` within the same pull request.
2. New primary examples must always use `AGENTCONTROL_*` environment variables.
3. Integrations must strictly reflect their verification status in `src/wrap/status.rs`.
