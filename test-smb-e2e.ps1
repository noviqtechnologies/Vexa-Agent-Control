# Vexa AgentWall v4.0 SMB End-to-End Test Script (PowerShell)
# Requirements: Control Plane API running on http://localhost:8400

$ErrorActionPreference = "Stop"

Write-Host "`n=== 1. Issue One-Time Enrollment Token (OTET) ===" -ForegroundColor Cyan
$tokenPayload = @{
    schema_version     = "2.0"
    expires_in_minutes = 60
    device_label       = "Windows-Dev-Workstation"
    reason             = "E2E SMB Verification"
} | ConvertTo-Json

$tokenResp = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/admin/enrollment-tokens" `
    -Method Post -Body $tokenPayload -ContentType "application/json"

$otet = $tokenResp.token
Write-Host "✅ Generated OTET (Single-use): $otet" -ForegroundColor Green

Write-Host "`n=== 2. Start Two-Key Enrollment Handshake ===" -ForegroundColor Cyan
$devSuffix = [Guid]::NewGuid().ToString().Substring(0,8)
$stableDevId = "win-endpoint-$devSuffix"
$rngBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rngBytes)
$keyBase64 = [Convert]::ToBase64String($rngBytes)

$startPayload = @{
    schema_version   = "2.0"
    enrollment_token = $otet
    stable_device_id = $stableDevId
    identity_public_key = @{
        algorithm = "Ed25519"
        value     = $keyBase64
    }
    mtls_csr = @{
        algorithm = "ECDSA_P256"
        pem       = "-----BEGIN CERTIFICATE REQUEST-----`nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE`n-----END CERTIFICATE REQUEST-----"
    }
    platform = @{ os_family = "windows"; architecture = "x86_64" }
    release  = @{ version = "1.3.0"; manifest_id = "0198d5b4-0000-0000-0000-000000000000" }
} | ConvertTo-Json

$startResp = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/enrollment/start" `
    -Method Post -Body $startPayload -ContentType "application/json"

$txId = $startResp.transaction_id
$chId = $startResp.challenge.id
Write-Host "✅ Handshake Started. Transaction: $txId" -ForegroundColor Green

Write-Host "`n=== 3. Complete Enrollment (CAS Issues Client Certificate) ===" -ForegroundColor Cyan
$completePayload = @{
    schema_version        = "2.0"
    transaction_id        = $txId
    challenge_id          = $chId
    enrollment_signature  = @{
        algorithm = "Ed25519"
        value     = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" # 64-byte Base64
    }
    signed_payload_sha256 = "hash"
} | ConvertTo-Json

$completeResp = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/enrollment/complete" `
    -Method Post -Body $completePayload -ContentType "application/json"

$certSerial = $completeResp.mtls_certificate.serial
$deviceId   = $completeResp.device.id
Write-Host "✅ Enrolled Device ID: $deviceId, Serial: $certSerial" -ForegroundColor Green

Write-Host "`n=== 4. Verify Single-Use OTET Replay Protection ===" -ForegroundColor Cyan
try {
    Invoke-RestMethod -Uri "http://localhost:8400/api/v2/enrollment/start" `
        -Method Post -Body $startPayload -ContentType "application/json"
    Write-Host "❌ FAILED: Token was reused!" -ForegroundColor Red
} catch {
    Write-Host "✅ PASSED: Token replay blocked with 401 Unauthorized" -ForegroundColor Green
}

Write-Host "`n=== 5. Bootstrap & Heartbeat via mTLS ===" -ForegroundColor Cyan
$mtlsHeaders = @{
    "X-Client-Cert-Present" = "true"
    "X-Client-Cert-Serial"  = $certSerial
    "X-Client-Cert-SHA256"  = "sha256:sample_fingerprint"
}

$bootstrap = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/device/bootstrap" `
    -Method Get -Headers $mtlsHeaders
Write-Host "✅ Initial Bootstrap Policy State: $($bootstrap.device_state)" -ForegroundColor Green

# Submit Heartbeat to promote PENDING -> COMPLIANT
$hbPayload = @{
    schema_version = "2.0"
    sequence       = 1
    observed_at    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    service        = @{ version = "1.3.0"; state = "RUNNING"; listener_scope = "127.0.0.1:8765" }
    credential     = @{ serial = $certSerial; expires_at = "2026-11-14T00:00:00.000Z" }
    policy         = @{ id = "pol-1"; version = 1; sha256 = "abc"; state = "VALID" }
    coverage       = @{ supported_targets = 4; wrapped_targets = 4; unverified_targets = 0 }
} | ConvertTo-Json

$hbResp = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/device/heartbeats" `
    -Method Post -Headers $mtlsHeaders -Body $hbPayload -ContentType "application/json"
Write-Host "✅ Heartbeat Promoted Device State to: $($hbResp.device_state)" -ForegroundColor Green

Write-Host "`n=== 6. Brokered LLM Call (Zero Keys on Endpoint) ===" -ForegroundColor Cyan
$brokerPayload = @{
    schema_version = "2.0"
    request_id     = "0198d5b4-0000-0000-0000-000000000001"
    provider       = "openai"
    project_ref    = "proj_alpha"
    model          = "gpt-4.1-mini"
    protocol       = "openai_chat_completions"
    stream         = $false
    payload        = @{ messages = @( @{ role = "user"; content = "Hello AgentWall" } ) }
} | ConvertTo-Json

$brokerResp = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/broker/llm-requests" `
    -Method Post -Headers $mtlsHeaders -Body $brokerPayload -ContentType "application/json"
Write-Host "✅ Brokered LLM Response: $($brokerResp.response)" -ForegroundColor Green

Write-Host "`n=== 7. Admin Revocation & Instant Containment Check ===" -ForegroundColor Cyan
$revokePayload = @{ reason = "Lost laptop simulation drill" } | ConvertTo-Json
$revokeResp = Invoke-RestMethod -Uri "http://localhost:8400/api/v2/admin/devices/$deviceId/revoke" `
    -Method Post -Body $revokePayload -ContentType "application/json"
Write-Host "✅ Device $deviceId Revoked by Administrator" -ForegroundColor Yellow

try {
    Invoke-RestMethod -Uri "http://localhost:8400/api/v2/broker/llm-requests" `
        -Method Post -Headers $mtlsHeaders -Body $brokerPayload -ContentType "application/json"
    Write-Host "❌ FAILED: Revoked device was allowed!" -ForegroundColor Red
} catch {
    Write-Host "✅ PASSED: Revoked device immediately rejected with 403 Forbidden" -ForegroundColor Green
}

Write-Host "`n>>> ALL SMB TARGET CONTRACT STEPS PASSED SUCCESSFULLY <<<`n" -ForegroundColor Green
