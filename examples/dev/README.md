# Development Environment Examples

This directory contains Docker Compose stacks and configurations intended **strictly for local development, integration testing, and mocking**.

> [!CAUTION]
> NEVER run services in this directory against production workloads or expose them to public networks.

## Files
- `docker-compose.yml`: Local dev stack with Mock OIDC, Mock Splunk HEC, Dev Vault, and Mock MCP Tool Server.
- `.env.dev.example`: Development environment variable template with explicit `DEV_MODE=true`.

## Quick Start
```bash
cp .env.dev.example .env
docker compose up -d
```
