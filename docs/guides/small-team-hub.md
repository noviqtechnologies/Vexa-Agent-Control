# Small Team Hub Guide (Docker Compose)

This guide covers deploying a shared Vexa Control Hub for engineering teams and small-to-medium businesses (SMBs) using Docker Compose.

---

## Why a Team Hub?

- **Centralized Security Policies:** Write policies once in Git; distribute them in real time to all developer workstations via Server-Sent Events (SSE).
- **Aggregated Audit Logs:** View all team AI tool calls, DLP blocks, and injection attempts in a single dashboard.
- **Team Spend Caps & Budgets:** Set daily/monthly spend limits per developer or project.
- **OTET Device Enrollment:** Onboard developer workstations securely with One-Time Enrollment Tokens.

---

## Prerequisites

- Docker 24.0+ and Docker Compose v2+
- Domain name pointed to your host (e.g. `hub.yourcompany.com`)
- Ports `80` and `443` available for HTTPS reverse proxy with automatic TLS

---

## Step 1: Clone and Configure

1. Clone the repository:
   ```bash
   git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
   cd Vexa-Agent-Control
   ```

2. Initialize your production environment configuration:
   ```bash
   cp .env.team.example .env
   ```

3. Generate secure secrets and populate `.env`:
   - `HUB_DOMAIN`: `hub.yourcompany.com` (or your reachable domain / host)
   - `INGRESS_AUTH_SECRET`: `openssl rand -hex 24` (Mandatory secret for VPC reverse proxy header verification)
   - `POSTGRES_PASSWORD`: `openssl rand -hex 24`
   - `GATEWAY_SECRET`: `openssl rand -hex 24`
   - `POLICY_READ_SECRET`: `openssl rand -hex 24`
   - `PROVIDER_KEY_ENCRYPTION_SECRET`: `openssl rand -hex 32` (Must be 64-hex chars)
   - `AGENTCONTROL_SESSION_SECRET`: `openssl rand -hex 32`
   - `SAAS_OPERATOR_PASSWORD`: Strong password for the platform admin

4. Start the secure team services with automatic TLS termination:
   ```bash
   docker compose -f docker-compose.team.secure.yml up -d
   ```

5. Verify health:
   ```bash
   docker compose -f docker-compose.team.secure.yml ps
   curl -s https://hub.yourcompany.com/healthz
   ```

---

## Step 2: Onboarding Developer Workstations

To connect a developer workstation to the shared team hub securely:

1. Generate a One-Time Enrollment Token (OTET) in the Hub UI at `https://<HUB_HOST>` (or via API).
2. On the developer's workstation, run:
   ```bash
   agentcontrol enroll --token <OTET_TOKEN> --hub-url https://<HUB_HOST>
   ```
3. Once enrolled, the workstation automatically pulls organization policies and streams telemetry to the team hub over encrypted mTLS / TLS.

---

## Step 3: Pushing Policy Updates

When you update `agentcontrol-policy.yaml` on the Hub:
1. The Hub publishes a policy revision event over SSE.
2. Connected developer workstations receive and hot-reload the policy without restarting their IDEs.

---

## Maintenance & Backups

- **Data Persistence:** Hub PostgreSQL database is persisted in the `vexa-postgres-data` Docker volume.
- **Backup Command:**
  ```bash
  docker compose -f docker-compose.team.secure.yml exec postgres pg_dump -U vexa vexa_control_plane > "backup-$(date +%F).sql"
  ```
- **Stop Hub:**
  ```bash
  docker compose -f docker-compose.team.secure.yml down
  ```
