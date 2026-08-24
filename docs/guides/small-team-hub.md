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
- Ports `3000` (Hub Web UI), `8080` (Gateway), and `8081` (Control Plane API) available

---

## Step 1: Clone and Configure

1. Clone the repository:
   ```bash
   git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
   cd Vexa-Agent-Control
   ```

2. Review `docker-compose.team.yml` environment settings:
   ```yaml
   services:
     postgres:
       image: postgres:16-alpine
       ports:
         - "5432:5432"

     control-plane-api:
       build:
         context: ./control-plane/api
       ports:
         - "8081:8081"

     control-plane-ui:
       build:
         context: ./control-plane/ui
       ports:
         - "3000:80"

     agentcontrol-gw:
       build:
         context: .
       ports:
         - "8080:8080"
   ```

3. Start the team services:
   ```bash
   docker compose -f docker-compose.team.yml up -d
   ```

4. Verify health:
   ```bash
   docker compose -f docker-compose.team.yml ps
   curl -s http://localhost:8081/healthz
   ```

---

## Step 2: Onboarding Developer Workstations

To connect a developer workstation to the shared team hub:

1. Generate a One-Time Enrollment Token (OTET) in the Hub UI at `http://localhost:3000` (or via API).
2. On the developer's workstation, run:
   ```bash
   agentcontrol enroll --token <OTET_TOKEN> --hub-url http://<HUB_HOST>:8081
   ```
3. Once enrolled, the workstation automatically pulls organization policies and streams telemetry to the team hub.

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
  docker compose -f docker-compose.team.yml exec postgres pg_dump -U vexa vexa_control_plane > "backup-$(date +%F).sql"
  ```
- **Stop Hub:**
  ```bash
  docker compose -f docker-compose.team.yml down
  ```
