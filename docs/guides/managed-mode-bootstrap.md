# Managed Mode Secure Bootstrap Guide
## Setting Up Independent Cryptographic Policy Authority for Teams

**Document Version:** 1.0  
**PRD Reference:** `PRD/pending/Vexa_AgentControl_Enforcement_Assurance_PRD.md` FR-006, FR-007  
**Authoritative Positioning:**  
> *"Vexa helps engineering teams govern the AI-agent traffic they route through it, with centrally managed policies and verifiable, per-surface enforcement evidence."*

---

## 1. Overview: Why Independent Authority Matters

In **Team Managed Mode**, policy changes cannot be made arbitrarily on local developer laptops. Instead, policies are centrally authored, reviewed, and signed using an Ed25519 private key.

Workstations verify every incoming policy bundle against a **pinned organizational keyring** before compiling it into memory.

> [!CRITICAL]
> **Defect Remediation & Security Rule:**  
> The policy signing private key MUST be managed independently. **Never** derive or reuse the signing key from `GATEWAY_SECRET`, `POLICY_READ_SECRET`, database passwords, or session tokens. If no explicit `POLICY_SIGNING_PRIVATE_KEY` is provisioned, the control plane in managed mode will fail closed at startup with `signing_authority_missing`.

---

## 2. Step-by-Step Bootstrap Workflow

```
┌────────────────────────────────────────────────────────────────────────┐
│                   MANAGED TRUST BOOTSTRAP WORKFLOW                     │
│                                                                        │
│   [1. Generate Keypair] ──► [2. Provision Hub] ──► [3. Distribute PK] │
│          Ed25519                Private Key              Public Key    │
│      (KMS / CLI / HSM)       (Control Plane Env)     (MDM / Keyring)   │
│                                                                        │
│   [4. Enroll Workstations] ──► [5. Verify Posture]                     │
│      agentcontrol connect          agentcontrol status                 │
│                                    "TEAM_MANAGED"                      │
└────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Generate an Ed25519 Signing Keypair
Generate a cryptographically secure 32-byte Ed25519 keypair. You can use OpenSSL, the `agentcontrol` CLI, or your enterprise KMS:

```bash
# Using OpenSSL 3.0+
openssl genpkey -algorithm ED25519 -out policy_signer.pem
openssl pkey -in policy_signer.pem -pubout -out policy_signer_pub.pem

# Extract raw 64-char hex strings:
# Private key seed: 32 bytes hex
# Public key: 32 bytes hex
```

### Step 2: Configure the Central Control Plane / Hub
Inject the private key into the Vexa Control Plane via environment variable or secret manager:

```bash
export POLICY_SIGNING_PRIVATE_KEY="<64-hex-character-private-key-seed>"
```

In production container environments (Kubernetes / AWS ECS):
```yaml
env:
  - name: POLICY_SIGNING_PRIVATE_KEY
    valueFrom:
      secretKeyRef:
        name: vexa-secrets
        key: policy-signing-key
```

### Step 3: Distribute the Public Key to Workstations
Endpoints must be provisioned with the public key before they can verify signed policies.

**Method A: Environment Variable (Recommended for quick testing / CI)**
```bash
export AGENTCONTROL_MANAGED_MODE=1
export AGENTCONTROL_TRUSTED_KEYS="<64-hex-character-public-key>"
```

**Method B: Durable Keyring File (Recommended for MDM / Enterprise Deployments)**
Push a JSON keyring file via Jamf / Intune to `~/.agentcontrol/keyring.json` (or `C:\Users\<user>\.agentcontrol\keyring.json` on Windows):

```json
{
  "keys": [
    {
      "key_id": "corp-sec-2026-primary",
      "public_key_hex": "7f8b9c2a1e3d4c5b6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
      "description": "Corporate Security Lead Authority 2026",
      "created_at": "2026-10-16T00:00:00Z",
      "expires_at": "2027-10-16T00:00:00Z"
    }
  ],
  "rotation_policy": "Manual"
}
```

Set the managed mode flag:
```bash
export AGENTCONTROL_MANAGED_MODE=1
export AGENTCONTROL_KEYRING_PATH="~/.agentcontrol/keyring.json"
```

### Step 4: Verify Workstation Trust State
Start or restart the workstation daemon:
```bash
agentcontrol service restart
```

Inspect the runtime status:
```bash
agentcontrol status --json
```

Verify that the output contains:
```json
{
  "management_mode": "TEAM_MANAGED",
  "policy_trust_profile": "Managed",
  "policy_revision": 1,
  "policy_freshness_state": "FRESH"
}
```

---

## 3. Verifying Fail-Closed Security

To verify that the fail-closed protection works:
1. Temporarily unset `AGENTCONTROL_TRUSTED_KEYS` while keeping `AGENTCONTROL_MANAGED_MODE=1`.
2. Attempt to run `agentcontrol start`:
3. The daemon will refuse to start and output:
   ```
   [ERROR] Managed mode configured (AGENTCONTROL_MANAGED_MODE=1) but no trusted public keys found.
   This means no signed policy bundles will ever be accepted — the endpoint cannot enforce centrally authorized policy.
   ```
4. This confirms that an unconfigured managed endpoint will never silently degrade into an insecure default state.
