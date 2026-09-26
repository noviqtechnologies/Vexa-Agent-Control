package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
)

// InsertRequestLog records a proxied LLM request into the spend_reservations table
// so it is visible in the Request Logs tab and Run Explorer.
func (s *Store) InsertRequestLog(ctx context.Context, tenantID string, log *model.LlmRequestLog) error {
	if s == nil || s.pool == nil || log == nil || !log.Valid() {
		return nil
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}

	deviceID := "gateway-proxy"
	if log.DeviceID != nil && *log.DeviceID != "" {
		deviceID = *log.DeviceID
	}

	createdAt := time.Now().UTC()
	if log.TimestampMs > 0 {
		createdAt = time.UnixMilli(log.TimestampMs).UTC()
	}

	settledAt := createdAt.Add(time.Duration(log.LatencyMs * float64(time.Millisecond)))
	expiresAt := createdAt.Add(24 * time.Hour)

	state := "SETTLED"
	if log.Verdict == "block" || log.Verdict == "deny" || log.StatusCode == 403 {
		state = "DENIED"
	} else if log.StatusCode >= 400 && log.StatusCode < 500 {
		state = "RELEASED"
	} else if log.StatusCode >= 500 {
		state = "FAILED"
	}

	statusCode := log.StatusCode
	if statusCode == 0 {
		if state == "DENIED" {
			statusCode = 403
		} else {
			statusCode = 200
		}
	}

	tagsMap := map[string]interface{}{
		"is_streaming": log.IsStreaming,
		"verdict":      log.Verdict,
		"protocol":     log.Protocol,
		"is_estimated": log.IsEstimated,
		"latency_ms":   log.LatencyMs,
	}
	if log.RequestIP != nil && *log.RequestIP != "" {
		tagsMap["request_ip"] = *log.RequestIP
	}
	if log.KeyHash != nil && *log.KeyHash != "" {
		tagsMap["key_hash"] = *log.KeyHash
	}
	if log.IdentityEmail != nil && *log.IdentityEmail != "" {
		tagsMap["identity_email"] = *log.IdentityEmail
	}
	tagsJSON, _ := json.Marshal(tagsMap)

	query := `
		INSERT INTO spend_reservations (
			organization_id, request_id, gateway_id, project_id, state,
			reserved_microcents, settled_microcents, currency, expires_at,
			policy_snapshot, price_book_version_id, provider, model,
			input_tokens, output_tokens, cached_tokens, status_code,
			session_id, internal_user_id, end_user_id, virtual_key_hash,
			tags, created_at, settled_at
		) VALUES (
			$1::uuid, $2, $3, 'default', $4,
			0, 0, 'USD', $5,
			'[]'::jsonb, 'v1', $6, $7,
			$8, $9, 0, $10,
			$11, $12, $13, $14,
			$15, $16, $17
		)
		ON CONFLICT (organization_id, request_id) DO UPDATE SET
			status_code = EXCLUDED.status_code,
			input_tokens = EXCLUDED.input_tokens,
			output_tokens = EXCLUDED.output_tokens,
			settled_at = EXCLUDED.settled_at,
			tags = EXCLUDED.tags,
			internal_user_id = COALESCE(NULLIF(EXCLUDED.internal_user_id, ''), spend_reservations.internal_user_id),
			end_user_id = COALESCE(NULLIF(EXCLUDED.end_user_id, ''), spend_reservations.end_user_id),
			state = EXCLUDED.state,
			provider = EXCLUDED.provider,
			model = EXCLUDED.model
	`

	var internalUser, endUser, vKeyHash, sessionID *string
	if log.IdentityEmail != nil && *log.IdentityEmail != "" {
		internalUser = log.IdentityEmail
		endUser = log.IdentityEmail
	} else if log.IdentitySub != nil && *log.IdentitySub != "" {
		internalUser = log.IdentitySub
		endUser = log.IdentitySub
	}
	if log.KeyHash != nil && *log.KeyHash != "" {
		vKeyHash = log.KeyHash
	}
	if log.SessionID != "" {
		sessionID = &log.SessionID
	}

	_, err := s.pool.Exec(ctx, query,
		tenantID, log.RequestID, deviceID, state,
		expiresAt, log.Provider, log.Model,
		log.PromptTokens, log.CompletionTokens, statusCode,
		sessionID, internalUser, endUser, vKeyHash,
		tagsJSON, createdAt, settledAt,
	)
	return err
}
