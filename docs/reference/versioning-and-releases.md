# Versioning & Release Governance Specification

This document specifies the official versioning, release tagging, and backwards-compatibility policy for **Vexa Agent Control**.

---

## 1. Semantic Versioning (SemVer 2.0.0) Policy

Vexa Agent Control adheres strictly to the [Semantic Versioning 2.0.0](https://semver.org/) standard:

```text
vMAJOR.MINOR.PATCH
  │     │     │
  │     │     └─ Patch: Backward-compatible bug fixes, security patches & doc updates ONLY.
  │     └─────── Minor: New backward-compatible features, engines, integrations & config options.
  └───────────── Major: Breaking config schema changes, removed flags, or incompatible wire protocols.
```

### Major Releases (`vX.0.0`)
Incremented when changes break backward compatibility for existing deployments:
- **Configuration Breaking Changes:** Renaming, removing, or changing the default behavior of keys in `agentcontrol.yaml` or `policy.yaml` without automatic fallback.
- **CLI Incompatibilities:** Removing or altering the syntax of existing subcommands or mandatory CLI arguments.
- **Wire Protocol & Schema Breaks:** Breaking alterations to the MCP proxy stream format, control-plane gRPC/HTTP payloads, or database schemas that require manual database intervention or migration scripts.
- **Platform Deprecations:** Dropping support for previously supported major operating systems or runtime architectures.

### Minor Releases (`v1.Y.0`)
Incremented whenever new capabilities, engines, or additive options are released in a backward-compatible manner:
- **New Feature Engines:** Adding major sub-systems such as the semantic vector caching engine, virtual keys manager, or spend queue backpressure.
- **New Provider / Client Integrations:** Adding support for new LLM providers, new IDE wrappers (e.g. Codex, Windsurf, Zed), or new telemetry sinks (e.g. OpenSearch, Datadog).
- **Additive Configuration Keys:** Introducing new configuration options with safe, non-breaking defaults that preserve existing system behavior if omitted.
- **New CLI Subcommands:** Introducing new non-destructive CLI inspection or management tools (e.g. `agentcontrol cache status`, `agentcontrol keys list`).

### Patch Releases (`v1.0.Z`)
Incremented **strictly** for defect remediation:
- **Defect & Bug Fixes:** Resolving unexpected runtime panics, edge-case memory leaks, regex evaluation flaws, or UI rendering bugs.
- **Security Patches:** Addressing vulnerability disclosures, updating compromised third-party dependencies, or patching boundary bypasses.
- **Performance Optimizations:** Sub-millisecond latency improvements and memory footprint reductions that do not alter public APIs or configuration schemas.
- **Documentation & Packaging Fixes:** Correcting typos, installation script fixes, or packaging manifest corrections.

> [!IMPORTANT]
> **Zero New Features in Patch Releases:**
> Additive features, new configuration schema fields, and experimental subcommands **must not** be shipped in patch releases. All additive functionality must wait for the next minor release (e.g., `v1.1.0`).

---

## 2. Transition from Early-Access Iterations

### Historical Context (v1.0.70 – v1.0.80)
During initial rapid early-access prototyping, substantial sub-systems (such as the semantic caching engine in v1.0.76 and virtual keys management in v1.0.78) were released in rapid patch increments. While this allowed fast turnaround for initial pilot feedback, it created the appearance of version churn.

### The SemVer Baseline Going Forward
Starting immediately:
- **Patch releases on the current branch (`v1.0.81+`)** are reserved exclusively for critical defect fixes, security patches, and documentation.
- **The next feature release** will be tagged as **`v1.1.0`**, clearly signaling to engineering leaders, DevOps, and security evaluators that the codebase follows standard enterprise release governance.

---

## 3. Pull Request Version Classification Checklist

Every Pull Request must be categorized with the appropriate SemVer impact before merging to `main`:

| PR Label | Target Bump | Required Review Criteria |
|---|---|---|
| `semver:patch` | Patch (`+0.0.1`) | - Zero changes to `policy.yaml` / `agentcontrol.yaml` schemas.<br/>- Zero changes to public CLI command flags.<br/>- Automated tests verify bug reproduction and resolution. |
| `semver:minor` | Minor (`+0.1.0`) | - Backward-compatible additions only.<br/>- Defaults preserve existing behavior when new config keys are absent.<br/>- New feature is covered by unit tests and documented in `docs/`. |
| `semver:major` | Major (`+1.0.0`) | - Requires explicit maintainer sign-off.<br/>- Must provide automated migration path or migration guide in `docs/reference/`. |

---

## 4. Release Process

1. **Update `Cargo.toml`:**
   Bump `version = "X.Y.Z"` in `Cargo.toml` according to the SemVer rules above.
2. **Update `CHANGELOG.md`:**
   Move items from `[Unreleased]` to `[vX.Y.Z] - YYYY-MM-DD` following [Keep a Changelog](https://keepachangelog.com/).
3. **Commit and Tag:**
   ```bash
   git commit -m "release: vX.Y.Z - <concise summary>"
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin main --tags
   ```
4. **Automated CI/CD Pipeline:**
   The `.github/workflows/release.yml` pipeline automatically builds multi-platform binaries (Linux x86_64, Linux ARM64, macOS Apple Silicon, macOS Intel, Windows x86_64), generates SHA-256 checksums, and publishes the official GitHub release.
