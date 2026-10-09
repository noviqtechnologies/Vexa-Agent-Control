# Enterprise Security Hardening & Assurance Implementation Plan

**Target Solution:** Vexa Agent Control (`agentcontrol`)  
**Status:** Approved Architectural Blueprint & Phased Execution Plan  
**Target Release Line:** `v1.1.0` – `v1.2.0`  
**Document Version:** 1.0.0  

---

## 1. Executive Summary & Context

Enterprise security teams, CISOs, and platform engineers evaluating AI agent governance solutions require verifiable security assurances rather than cooperative wrappers. This implementation plan directly operationalizes remediation for the 6 critical enterprise operator requirements:

1. **Third-Party Penetration Test & Published Remediation:** End-to-end evaluation covering gateway, local UI/API, OIDC, control plane, operator, and update/release paths.
2. **Non-Bypassable Enforcement Mode:** Strict containment under a stated threat model handling unmanaged shells, alternate credentials, IPv4/IPv6 dual-stack, DNS tunneling, and proxy failure (fail-closed).
3. **Verifiable Releases & Signed Provenance:** Pinned CI actions, mandatory signed provenance (SLSA), and installer-side signature verification that fails closed.
4. **Compliance Realism & Governance Commitments:** Separation between "evidence collection" and "regulatory compliance"; concrete data retention, tenancy, KMS key management, and incident response SLAs.
5. **Cleaned, Versioned Operator Documentation:** Complete scrubbing of machine-local URLs, alignment with the active release, and strict feature lifecycle labeling (`[GA]`, `[Preview]`, `[Experimental]`).
6. **Public Track Record & Reproducible Security Tests:** Reproducible test harness, vulnerability disclosure policy (VDP), and documented security advisories.

---

## 2. Threat Boundary & Enforcement Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              HOST SECURITY BOUNDARY                                    │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                    SANDBOXED AGENT RUNTIME (CONTAINED)                           │  │
│  │                                                                                  │  │
│  │   ┌─────────────────────┐          ┌───────────────────────┐                     │  │
│  │   │  LLM Agent Process  │ ──fork──▶│   Subshell Process    │                     │  │
│  │   │  (Python/Node/CLI)  │          │   (bash/cmd/pwsh)     │                     │  │
│  │   └──────────┬──────────┘          └───────────┬───────────┘                     │  │
│  │              │                                 │                                 │  │
│  │              │ (Attempts direct socket/DNS)    │ (Raw curl / socket egress)      │  │
│  │              ▼                                 ▼                                 │  │
│  │    [ Restricted Network Namespace / cgroup / Windows Filtering Platform (WFP) ]   │  │
│  │    * IPv4 & IPv6 outbound redirected to Gateway Ports (8080/8443)                │  │
│  │    * UDP/53 & DoH redirected to Gateway DNS Sinkhole                             │  │
│  │    * Environment credentials stripped; injected via AgentControl Vault only      │  │
│  └──────────────────────────────────────┬───────────────────────────────────────────┘  │
│                                         │ Intercepted Stream                           │
│                                         ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                      AGENTCONTROL LOCAL GATEWAY DAEMON                           │  │
│  │                                                                                  │  │
│  │   ┌────────────────────────────────┐       ┌─────────────────────────────────┐   │  │
│  │   │ Dual-Stack Listener (v4/v6)    │       │ Fail-Closed Watchdog Monitor    │   │  │
│  │   │ & DNS Resolver / Sinkhole      │       │ (Terminates agent if GW dies)   │   │  │
│  │   └───────────────┬────────────────┘       └─────────────────────────────────┘   │  │
│  │                   │                                                              │  │
│  │                   ▼                                                              │  │
│  │   ┌──────────────────────────────────────────────────────────────────────────┐   │  │
│  │   │ Policy Engine: RegexSet DLP | Injection Normalizer | Tool Guard | HITL   │   │  │
│  │   └──────────────────────────────────────┬───────────────────────────────────┘   │  │
│  │                                          │ Outbound Egress                       │  │
│  └──────────────────────────────────────────┼───────────────────────────────────────┘  │
│                                             ▼                                          │
│                                   Authorized Upstreams                                 │
│                        (OpenAI / Anthropic / Team Control Hub)                         │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Phased Implementation Roadmap

```
PHASE 0 (Weeks 1-2)  ──▶ PHASE 1 (Weeks 3-4)  ──▶ PHASE 2 (Weeks 5-8)
Doc Hygiene & Pinning     Release Integrity &       Non-Bypassable
Threat Boundary Def.      Installer Verification    Enforcement Engine

        │                         │                         │
        ▼                         ▼                         ▼
PHASE 3 (Weeks 9-10) ──▶ PHASE 4 (Weeks 11-12) ──▶ PHASE 5 (Weeks 13-16+)
Compliance Realism &      Versioned Runbook &       Third-Party Pentest,
Data Commitments          Maturity Matrix           Remediation & Public VDP
```

---

### Phase 0: Baseline Hygiene & Supply Chain Pinning (Weeks 1–2)

**Goal:** Eliminate machine-local paths in docs, freeze third-party CI dependencies to cryptographic SHAs, and document the baseline threat model.

#### Deliverables & Code Changes:
1. **Scrub Machine-Local References:**
   * Audit all files in `docs/`, `docs/adr/`, and `docs/security/`.
   * Replace all instances of `file:///C:/Users/...` or hardcoded local paths with repository-relative paths (e.g., `../security/threat_model.md`).
2. **Immutable CI GitHub Action Pinning:**
   * Modify `.github/workflows/ci.yml`, `.github/workflows/release.yml`, and `.github/workflows/agentcontrol-assess.yml`.
   * Pin all external GitHub Actions to full 40-character commit SHAs with inline version comments:
     * `actions/checkout@v4` $\rightarrow$ `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`
     * `dtolnay/rust-toolchain@master` $\rightarrow$ pin to immutable commit SHA.
     * `sigstore/cosign-installer`, `anchore/sbom-action`, `actions/attest-build-provenance`, `softprops/action-gh-release`.
3. **Formal Boundary Definition:**
   * Update `docs/security/threat_model.md` and `docs/security/direct-proxy-bypass-model.md` to clearly delineate **Cooperative Mode** (developer convenience) vs. **Strict Containment Mode** (production enterprise).

#### Acceptance Criteria:
* `grep -rn "file:///" docs/` returns 0 matches.
* All `.github/workflows/*.yml` files contain zero unpinned floating action tags (`@master`, `@v1`, `@v4`).
* CI build completes cleanly without warnings.

---

### Phase 1: Verifiable Releases & Installer Fail-Closed Verification (Weeks 3–4)

**Goal:** Ensure end users can mathematically verify that binaries originated from the authentic GitHub repository workflow without tampering.

#### Deliverables & Code Changes:
1. **Fail-Closed Cosign Signing in CI (`.github/workflows/release.yml`):**
   * Remove `continue-on-error: true` from the Cosign signature step (line 183).
   * Sign every artifact binary (`.zip`, `.tgz`) individually, generating `.sig` and `.pem` or Rekor bundle files.
   * Generate SLSA Level 2+ build provenance via `actions/attest-build-provenance@v1`.
2. **Installer Signature Verification (`install/install.sh` & `install/install.ps1`):**
   * **`install.sh` Updates:**
     * Download `checksums.txt`, `checksums.txt.bundle`, and individual archive signatures.
     * Run `cosign verify-blob` against the official Vexa Sigstore identity (`github.com/noviqtechnologies/Vexa-Agent-Control`).
     * If `cosign` is missing: download static standalone `cosign` binary or fallback to Vexa GPG/Ed25519 root key verification.
     * **Fail-Closed Rule:** If signature verification fails or cannot reach the transparency log, installation aborts immediately with non-zero exit code:
       ```bash
       echo "[!] FATAL: Cryptographic signature verification failed! Aborting."
       exit 1
       ```
   * **`install.ps1` Updates:**
     * Implement identical fail-closed verification using authentic Authenticode or Cosign Windows binary before extracting into `%LOCALAPPDATA%\AgentControl\bin`.

#### Acceptance Criteria:
* Tampered test binary injected into install step causes `install.sh` and `install.ps1` to immediately abort.
* Installation succeeds only when signature and checksum match the provenance record.

---

### Phase 2: Non-Bypassable Enforcement Engine (Weeks 5–8)

**Goal:** Prevent agent processes from bypassing gateway inspection via unmanaged subshells, raw sockets, IPv6 fallback, or DNS tunneling.

#### Deliverables & Code Changes:
1. **Strict Sandbox Containment (`src/enforcement/mod.rs`, `src/enforcement/sandbox.rs`):**
   * **Linux:** Launch agent processes within a dedicated network namespace (`ip netns`) or unshare network where the default gateway is redirected to `agentcontrol` loopback using `iptables` / `nftables` rules.
   * **Windows:** Utilize Windows Filtering Platform (WFP) temporary rules or AppContainer network isolation to restrict outbound TCP to the `agentcontrol` port.
2. **Subshell & Environment Sanitization:**
   * When `agentcontrol run` spawns agent processes, sanitize the environment:
     * Strip raw cloud credentials (`AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`).
     * Inject short-lived gateway tokens (`AGENTCONTROL_SESSION_TOKEN`).
     * Enforce child process containment so spawned child shells (`bash -c "curl ..."`) inherit the isolated network sandbox.
3. **Dual-Stack IPv4 / IPv6 & DNS Sinkhole (`src/proxy/connector.rs`, `src/proxy/egress.rs`):**
   * Bind the gateway proxy to dual-stack `[::1]:8080` and `127.0.0.1:8080`.
   * Explicitly sinkhole/drop unauthorized outbound IPv6 traffic to prevent AAAA bypasses.
   * Implement local DNS sinkholing (intercepting port 53 UDP/TCP) in the daemon to block DNS exfiltration and tunneling.
4. **Proxy Failure Semantics (Deterministic Fail-Closed Watchdog):**
   * In `src/kill.rs` and `src/proxy/server.rs`, implement a parent-child watchdog heartbeat:
     * If `agentcontrol` panics or is killed, the kernel-level mechanism (`PR_SET_PDEATHSIG` with `SIGKILL` on Linux, `JobObject` on Windows) automatically terminates all child agent processes within 50ms.
     * Configure `failure_mode` in `agentcontrol-policy.yaml`:
       ```yaml
       enforcement:
         mode: strict # strict (network isolated) | cooperative (dev)
         on_proxy_failure: fail-closed # fail-closed | fail-open
         watchdog_timeout_ms: 1000
       ```

#### Acceptance Criteria:
* Python test script attempting raw `socket.create_connection(("api.openai.com", 443))` without proxy fails with `ConnectionRefused`.
* Bash subshell spawned by agent attempting `curl -6 https://...` is blocked.
* Killing the `agentcontrol` daemon process terminates the agent immediately without data leak.

---

### Phase 3: Compliance Realism & Data Commitments (Weeks 9–10)

**Goal:** Replace marketing claims with defensible cryptographic and operational compliance boundaries.

#### Deliverables & Code Changes:
1. **Refactor `docs/compliance_mapping.md`:**
   * Disclaim "auto-compliance." Title changed to: **"Compliance Evidence Collection & Technical Controls Guide"**.
   * Add **Shared Responsibility Model** section explicitly detailing customer duties vs. AgentControl duties.
   * Separate audit evidence generation (HMAC audit trails, SIEM streaming) from regulatory compliance attestations.
2. **Publish Data Governance Standard (`docs/security/data_governance.md`):**
   * **Data Retention & Pruning:** Default local retention (SQLite 30/90 days), automated cryptographically verified purging routines.
   * **Tenant Isolation Architecture:** Separate schemas/tenants for SMB & Enterprise Hub deployments; zero co-mingling of tenant prompt logs.
   * **Key Hierarchy & KMS:** Document Master Key (HSM/KMS) $\rightarrow$ Tenant Encryption Key (DEK) $\rightarrow$ Session Key hierarchy.
3. **Update `SECURITY.md` Incident Response SLAs:**
   * Commit to:
     * Critical vulnerability initial triage: $\le 24$ hours.
     * High severity patch release: $\le 7$ business days.
     * Security breach customer notification: $\le 72$ hours.

#### Acceptance Criteria:
* Published `docs/security/data_governance.md` reviewed and approved by compliance stakeholders.
* `docs/compliance_mapping.md` passes enterprise audit scrutiny without unsubstantiated compliance certification claims.

---

### Phase 4: Versioned Operator Runbook & Feature Maturity (Weeks 11–12)

**Goal:** Deliver rock-solid, version-pinned operator documentation with clear feature lifecycle indicators.

#### Deliverables & Code Changes:
1. **Feature Lifecycle Matrix (`docs/reference/feature_lifecycle.md`):**
   * Classify every feature across CLI and configuration:
     * `[GA]`: MCP Stdio Proxy, Local Safe Mode, RegexSet DLP, HMAC Audit Chain.
     * `[Preview]`: OIDC Identity Binding, Team Hub Sync, Spend Budgets.
     * `[Experimental]`: Kernel-level Egress Sandboxing, Semantic Anomaly Scanner.
2. **Operator Runbook Standardization (`docs/OPERATOR_RUNBOOK.md`):**
   * Synchronize all CLI flags, health checks, and daemon configs with the active `v1.0.x` / `v1.1.x` release.
   * Provide explicit failure diagnostic guides:
     * `agentcontrol doctor` diagnostics.
     * Local API port conflict resolution.
     * Fail-closed unblock procedures for incident responders.

#### Acceptance Criteria:
* Every command and YAML setting in `docs/` is verified against current binary `--help` and schemas.
* No dead links, deprecated commands, or undocumented experimental features.

---

### Phase 5: Third-Party Penetration Test & Public Track Record (Weeks 13–16+)

**Goal:** Validate all components via independent third-party penetration testing, publish remediation results, and establish a public security track record.

#### Deliverables & Code Changes:
1. **Penetration Test Engagement & Scoping (`docs/security/pentest_scope.md`):**
   * Commission external accredited firm across 6 attack surfaces:
     1. Gateway Rust daemon & memory safety.
     2. Local UI & IPC sockets (Named pipes / loopback REST API).
     3. OIDC JWT validation & token exchange.
     4. Control Plane / Team Hub (Multi-tenancy isolation).
     5. Operator CLI & daemon management.
     6. Release & update pipeline (Cosign, CI/CD).
2. **Published Remediation Summary (`docs/security/pentest_remediation_summary.md`):**
   * Executive summary of all findings (CVSS Critical to Low).
   * Verifiable Git commit hashes for each remediated item.
   * Attestation letter from testing firm published in repository.
3. **Reproducible Security Verification Test Suite (`tests/security_harness/`):**
   * Public test suite executable by any external user:
     ```bash
     cargo test --test security_enforcement_bypass -- --nocapture
     ```
   * Automated scenarios:
     * `test_unmanaged_shell_subversion_fails()`
     * `test_ipv6_direct_socket_fails()`
     * `test_dns_tunneling_sinkholed()`
     * `test_proxy_crash_fail_closed_terminates_agent()`
4. **Vulnerability Handling Registry:**
   * Publish active GitHub Security Advisories for resolved CVEs.
   * Establish security research hall of fame in `SECURITY.md`.

#### Acceptance Criteria:
* Zero unresolved Critical or High findings from external penetration test.
* All test cases in `tests/security_harness/` pass in automated CI.
* Signed remediation summary published and linked in documentation.

---

## 4. Execution Schedule & Milestones

| Milestone | Phase | Target Timeline | Key Milestone Deliverable |
|---|---|---|---|
| **M0** | Phase 0 | Week 2 | Pinned CI actions, clean docs, formal threat boundaries |
| **M1** | Phase 1 | Week 4 | Fail-closed Cosign verification in CI and installers |
| **M2** | Phase 2 | Week 8 | Non-bypassable sandbox containment & fail-closed watchdog |
| **M3** | Phase 3 | Week 10 | Refactored compliance guide, data retention & KMS commitments |
| **M4** | Phase 4 | Week 12 | Versioned Operator Runbook & feature lifecycle classification |
| **M5** | Phase 5 | Week 16+ | Third-party pentest completed, remediation summary published |

---

## 5. Definition of Done (DoD) for Enterprise Readiness

A release is marked **Enterprise Certified** only when:
- [ ] Installers reject unsigned or untrusted binaries fail-closed.
- [ ] Agent runtime cannot establish direct outbound network connections outside the gateway under any condition (subshell, IPv6, raw socket).
- [ ] Watchdog kills contained agent if the gateway fails.
- [ ] All documentation matches binary CLI outputs with zero machine-local links.
- [ ] Third-party penetration audit attestation is public with documented remediation commits.
- [ ] End-to-end security test suite passes in public CI.
