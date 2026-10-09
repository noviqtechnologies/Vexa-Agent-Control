# ADR-005: Local Storage, Retention, Indexing, and Compaction

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** Architecture & Security Hardening Standard

---

## 1. Context & Problem Statement

Workstation agents generate substantial volumes of trace events and audit logs. Without explicit storage caps, rotation, and indexing:
- Developers' disks can fill up silently, leading to OS degradation.
- Searching historical traces in the local UI becomes sluggish.
- Sensitive historical traces persist indefinitely on developer machines without automated eviction.

---

## 2. Decision: Dual-Tier Local Storage Architecture

We implement a decoupled dual-tier local storage strategy:

```
[Agent Control Workstation Daemon]
      │
      ├── (Append-Only) ──► `audit.jsonl` (Cryptographic HMAC chain, 100MB files, compressed archives)
      │
      └── (Queryable)   ──► `traces.db` (SQLite with WAL mode, time-indexed, capped size)
```

### 2.1 File Storage: `audit.jsonl`
- **Format**: Flat JSON Lines with HMAC chain.
- **Rotation**: Rotates when file size reaches 100MB (or 7 days of inactivity).
- **Continuity**: The first entry of a new rotated file is a `log_rotation_seed` linking the old file's terminal HMAC.
- **Retention**: Retains up to 10 archived log files (`audit.1.jsonl.gz` ... `audit.10.jsonl.gz`), after which oldest files are purged or moved to SIEM cold storage.

### 2.2 Relational Store: `traces.db` (SQLite)
- **Engine**: SQLite with Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and synchronous normal (`PRAGMA synchronous = NORMAL`).
- **Schema**:
  ```sql
  CREATE TABLE traces (
      trace_id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      total_tokens INTEGER DEFAULT 0,
      status TEXT NOT NULL,
      has_blocked_actions INTEGER DEFAULT 0
  );

  CREATE TABLE spans (
      span_id TEXT PRIMARY KEY,
      trace_id TEXT NOT NULL REFERENCES traces(trace_id) ON DELETE CASCADE,
      parent_span_id TEXT,
      span_name TEXT NOT NULL,
      started_at TEXT NOT NULL,
      duration_ms REAL NOT NULL,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      FOREIGN KEY(trace_id) REFERENCES traces(trace_id)
  );

  CREATE INDEX idx_spans_trace_id ON spans(trace_id);
  CREATE INDEX idx_traces_started_at ON traces(started_at);
  CREATE INDEX idx_traces_blocked ON traces(has_blocked_actions);
  ```
- **Size Cap & Eviction**:
  - Maximum default database size: **500MB**.
  - Eviction policy: Rolling FIFO by `started_at` when size exceeds cap (or older than 14 days).
  - Background compaction (`VACUUM`) executes during daemon startup or idle maintenance windows.

---

## 3. Security & Cross-Platform Permissions

- **Windows**: Files created in `%APPDATA%\AgentWall\` with explicit NTFS DACLs granting access only to the executing user account (SID) and SYSTEM.
- **Linux / macOS**: Files created with POSIX mode `0600` in `${XDG_DATA_HOME:-~/.local/share}/agentwall/` or `~/Library/Application Support/agentwall/`.
