package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/broker"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

type BrokerV2Handler struct {
	Store          *store.Store
	SpendStore     *spend.Store
	ProviderClient broker.ProviderClient
	MasterKey      []byte
}

func NewBrokerV2Handler(st *store.Store, pc broker.ProviderClient, masterKey []byte, spendStore *spend.Store) *BrokerV2Handler {
	return &BrokerV2Handler{
		Store:          st,
		SpendStore:     spendStore,
		ProviderClient: pc,
		MasterKey:      masterKey,
	}
}

type BrokerRequestPayload struct {
	SchemaVersion      string          `json:"schema_version"`
	RequestID          string          `json:"request_id"`
	Provider           string          `json:"provider"`
	ProjectRef         string          `json:"project_ref"`
	Model              string          `json:"model"`
	Protocol           string          `json:"protocol"`
	Stream             bool            `json:"stream"`
	LLMMode            string          `json:"llm_mode,omitempty"` // central_enforce | central_shadow | local_compat
	InputTokenEstimate int64           `json:"input_token_estimate,omitempty"`
	MaxOutputTokens    int64           `json:"max_output_tokens,omitempty"`
	VirtualKey         string          `json:"virtual_key,omitempty"`
	Payload            json.RawMessage `json:"payload"`
}

func buildSpendDenialError(authResp *spend.AuthorizeResponse, provider, reqID string) map[string]any {
	scopeName := strings.ToLower(authResp.DisclosureSafeScope)
	var scopeDesc string
	switch scopeName {
	case "provider":
		scopeDesc = fmt.Sprintf("LLM provider '%s'", strings.ToUpper(provider))
	case "project":
		scopeDesc = "project / workload"
	case "organization":
		scopeDesc = "organization"
	default:
		scopeDesc = "spend budget"
	}

	msg := fmt.Sprintf("Spend budget limit exceeded for %s.", scopeDesc)
	if authResp.ResetAt != nil && !authResp.ResetAt.IsZero() {
		msg += fmt.Sprintf(" Quota window resets at %s UTC.", authResp.ResetAt.UTC().Format("2006-01-02 15:04:05"))
	}
	remediation := "Request a budget adjustment from your workspace administrator under LLM Providers & Spend Governance in the AgentControl Console, or switch to an alternate project/model."

	errObj := map[string]any{
		"code":           authResp.ReasonCode,
		"type":           "spend_governance_denied",
		"origin":         "agentcontrol_broker",
		"message":        msg,
		"remediation":    remediation,
		"scope":          authResp.DisclosureSafeScope,
		"provider":       provider,
		"correlation_id": reqID,
	}
	if authResp.ResetAt != nil && !authResp.ResetAt.IsZero() {
		errObj["reset_at"] = authResp.ResetAt.UTC().Format(time.RFC3339)
	}

	return map[string]any{
		"error": errObj,
	}
}

// POST /api/v2/broker/llm-requests and POST /api/v3/broker/llm-requests
func (h *BrokerV2Handler) HandleLLMRequest(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/v2/") {
		w.Header().Set("Deprecation", "@1741564800")
		w.Header().Set("Sunset", "Thu, 31 Dec 2026 23:59:59 GMT")
		w.Header().Set("Link", "</api/v3/broker/dispatch>; rel=\"successor-version\"")
	}

	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	if principal.DeviceState == model.DeviceStateRevoked || principal.DeviceState == model.DeviceStateNonCompliant {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"device_state_denied","message":"Device compliance state (%s) prohibits LLM execution"}}`, principal.DeviceState), http.StatusForbidden)
		return
	}

	var req BrokerRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}

	tenantID := principal.OrganizationID
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	reqID := req.RequestID
	if reqID == "" {
		reqID = principal.RequestID
	}
	if reqID == "" {
		reqID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	llmMode := req.LLMMode
	if llmMode == "" {
		llmMode = "central_enforce"
	}

	// 0. Extract & Validate Scoped Virtual Key if present
	virtualKeySecret := r.Header.Get("X-Virtual-Key")
	if virtualKeySecret == "" {
		virtualKeySecret = req.VirtualKey
	}
	virtualKeySecret = strings.TrimPrefix(virtualKeySecret, "Bearer ")
	virtualKeySecret = strings.TrimSpace(virtualKeySecret)

	var vk *store.VirtualKey
	if virtualKeySecret != "" && h.Store != nil {
		hasher := sha256.New()
		hasher.Write([]byte(virtualKeySecret))
		keyHash := hex.EncodeToString(hasher.Sum(nil))
		vk, _ = h.Store.GetVirtualKeyByHash(r.Context(), keyHash)
	}

	if vk != nil {
		if vk.MonthlyBudgetMicrocents > 0 && vk.SpentMicrocents >= vk.MonthlyBudgetMicrocents {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "budget_exceeded",
					"message": "Monthly spend budget exceeded for this virtual key",
				},
			})
			return
		}
		if len(vk.AllowedModels) > 0 {
			modelAllowed := false
			for _, m := range vk.AllowedModels {
				if strings.EqualFold(m, req.Model) || m == "*" {
					modelAllowed = true
					break
				}
			}
			if !modelAllowed {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":    "model_not_allowed",
						"message": fmt.Sprintf("Model '%s' is not permitted for this virtual key", req.Model),
					},
				})
				return
			}
		}
	}

	// 1. Spend Preflight Authorization
	var authResp *spend.AuthorizeResponse
	if h.SpendStore != nil {
		inputEst := req.InputTokenEstimate
		if inputEst <= 0 {
			inputEst = int64(len(req.Payload) / 4)
			if inputEst == 0 {
				inputEst = 1
			}
		}
		maxOutput := req.MaxOutputTokens
		if maxOutput <= 0 {
			maxOutput = 4096
		}

		projID := req.ProjectRef
		if projID == "" {
			projID = "default"
		}

		authReq := &spend.AuthorizeRequest{
			GatewayID:          principal.DeviceID,
			RequestID:          reqID,
			IdempotencyKey:     fmt.Sprintf("auth-%s", reqID),
			ProjectID:          projID,
			Provider:           req.Provider,
			Model:              req.Model,
			InputTokenEstimate: inputEst,
			MaxOutputTokens:    maxOutput,
			RequestHash:        reqID,
		}

		var err error
		authResp, err = h.SpendStore.Authorize(r.Context(), tenantID, authReq)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"code":"spend_authorization_error","message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}

		if authResp != nil && authResp.Decision == "deny" {
			if llmMode == "central_enforce" && authResp.ReasonCode != spend.ErrCodePriceUnknown {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(buildSpendDenialError(authResp, req.Provider, reqID))
				return
			}
			// price_unknown or central_shadow: clear reservation and proceed
			authResp = nil
		}
	}

	// 2. Resolve & Decrypt Provider Key with AAD
	var apiKey string
	if h.Store != nil && len(h.MasterKey) > 0 {
		pk, err := h.Store.GetProviderKeyByProvider(r.Context(), tenantID, req.Provider)
		if err == nil && pk != nil && pk.APIKeyEncrypted != "" {
			// First attempt decryption with AAD
			aad := []byte(fmt.Sprintf("%s|%s|%s|%d", tenantID, req.Provider, pk.KeyAlias, pk.Version))
			decrypted, decErr := crypto.DecryptWithAAD(h.MasterKey, pk.APIKeyEncrypted, aad)
			if decErr == nil {
				apiKey = decrypted
			} else {
				// Fallback to nil-AAD for pre-migration keys
				decryptedLegacy, decLegacyErr := crypto.Decrypt(h.MasterKey, pk.APIKeyEncrypted)
				if decLegacyErr == nil {
					apiKey = decryptedLegacy
				}
			}
		}
	}

	if apiKey == "" {
		if strings.EqualFold(req.Provider, "openai") {
			apiKey = os.Getenv("OPENAI_API_KEY")
		} else if strings.EqualFold(req.Provider, "anthropic") {
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		} else if strings.EqualFold(req.Provider, "google") || strings.EqualFold(req.Provider, "gemini") {
			apiKey = os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				apiKey = os.Getenv("GOOGLE_API_KEY")
			}
		}
	}

	if apiKey == "" {
		if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil {
			relReq := &spend.ReleaseRequest{
				RequestID:      reqID,
				IdempotencyKey: fmt.Sprintf("release-%s", reqID),
				Reason:         "provider_credential_unavailable",
				StatusCode:     http.StatusServiceUnavailable,
				RequestHash:    reqID,
			}
			_, _ = h.SpendStore.Release(r.Context(), tenantID, authResp.ReservationID, relReq)
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":       "provider_credential_unavailable",
				"message":    "Provider API credential is not configured or cannot be decrypted for this tenant",
				"request_id": reqID,
			},
		})
		return
	}

	// 3. Dispatch Egress & Handle Streaming / Buffered
	if req.Stream {
		h.handleStreamingDispatch(w, r, tenantID, reqID, &req, apiKey, authResp, vk)
		return
	}

	llmResp, usageRep, err := h.ProviderClient.ForwardLLMRequest(
		r.Context(),
		req.Provider,
		req.Model,
		false,
		req.Payload,
		apiKey,
	)

	if err != nil {
		if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil {
			relReq := &spend.ReleaseRequest{
				RequestID:      reqID,
				IdempotencyKey: fmt.Sprintf("release-%s", reqID),
				Reason:         "upstream_provider_error",
				StatusCode:     http.StatusBadGateway,
				RequestHash:    reqID,
			}
			_, _ = h.SpendStore.Release(r.Context(), tenantID, authResp.ReservationID, relReq)
		}
		var upstreamErr *broker.UpstreamHTTPError
		if errors.As(err, &upstreamErr) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(upstreamErr.StatusCode)
			_, _ = w.Write(upstreamErr.Body)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":{"code":"upstream_provider_error","message":%q}}`, err.Error()), http.StatusBadGateway)
		return
	}

	// 4. Settle Reservation & Record Virtual Key Spend
	var settledMicrocents int64
	if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil && usageRep != nil {
		settleReq := &spend.SettleRequest{
			RequestID:         reqID,
			IdempotencyKey:    fmt.Sprintf("settle-%s", reqID),
			ProviderRequestID: usageRep.ProviderRequestID,
			InputTokens:       usageRep.InputTokens,
			OutputTokens:      usageRep.OutputTokens,
			CachedInputTokens: usageRep.CachedInputTokens,
			IsEstimated:       usageRep.IsEstimated,
			UsageSource:       usageRep.UsageSource,
			Status:            usageRep.StatusCode,
			RequestHash:       reqID,
		}
		settledResp, _ := h.SpendStore.Settle(r.Context(), tenantID, authResp.ReservationID, settleReq)
		if settledResp != nil && settledResp.SettledMicrocents > 0 {
			settledMicrocents = int64(settledResp.SettledMicrocents)
		}
	}
	if settledMicrocents <= 0 && usageRep != nil {
		toks := usageRep.InputTokens + usageRep.OutputTokens
		if toks <= 0 {
			toks = req.InputTokenEstimate + 50
		}
		settledMicrocents = toks * 1000
	}
	if vk != nil && settledMicrocents > 0 && h.Store != nil {
		_, _ = h.Store.IncrementVirtualKeySpend(r.Context(), tenantID, vk.ID, settledMicrocents)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(llmResp)
}

// POST /api/v3/broker/llm-stream
func (h *BrokerV2Handler) HandleLLMStream(w http.ResponseWriter, r *http.Request) {
	principal, ok := middleware.GetDevicePrincipal(r.Context())
	if !ok {
		http.Error(w, `{"error":{"code":"device_auth_required"}}`, http.StatusUnauthorized)
		return
	}

	if principal.DeviceState == model.DeviceStateRevoked || principal.DeviceState == model.DeviceStateNonCompliant {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"device_state_denied","message":"Device compliance state (%s) prohibits LLM execution"}}`, principal.DeviceState), http.StatusForbidden)
		return
	}

	var req BrokerRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_schema"}}`, http.StatusBadRequest)
		return
	}
	req.Stream = true

	tenantID := principal.OrganizationID
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	reqID := req.RequestID
	if reqID == "" {
		reqID = principal.RequestID
	}
	if reqID == "" {
		reqID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	llmMode := req.LLMMode
	if llmMode == "" {
		llmMode = "central_enforce"
	}

	// 0. Extract & Validate Scoped Virtual Key if present
	virtualKeySecret := r.Header.Get("X-Virtual-Key")
	if virtualKeySecret == "" {
		virtualKeySecret = req.VirtualKey
	}
	virtualKeySecret = strings.TrimPrefix(virtualKeySecret, "Bearer ")
	virtualKeySecret = strings.TrimSpace(virtualKeySecret)

	var vk *store.VirtualKey
	if virtualKeySecret != "" && h.Store != nil {
		hasher := sha256.New()
		hasher.Write([]byte(virtualKeySecret))
		keyHash := hex.EncodeToString(hasher.Sum(nil))
		vk, _ = h.Store.GetVirtualKeyByHash(r.Context(), keyHash)
	}

	if vk != nil {
		if vk.MonthlyBudgetMicrocents > 0 && vk.SpentMicrocents >= vk.MonthlyBudgetMicrocents {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "budget_exceeded",
					"message": "Monthly spend budget exceeded for this virtual key",
				},
			})
			return
		}
		if len(vk.AllowedModels) > 0 {
			modelAllowed := false
			for _, m := range vk.AllowedModels {
				if strings.EqualFold(m, req.Model) || m == "*" {
					modelAllowed = true
					break
				}
			}
			if !modelAllowed {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":    "model_not_allowed",
						"message": fmt.Sprintf("Model '%s' is not permitted for this virtual key", req.Model),
					},
				})
				return
			}
		}
	}

	// Spend Preflight Authorization
	var authResp *spend.AuthorizeResponse
	if h.SpendStore != nil {
		inputEst := req.InputTokenEstimate
		if inputEst <= 0 {
			inputEst = int64(len(req.Payload) / 4)
			if inputEst == 0 {
				inputEst = 1
			}
		}
		maxOutput := req.MaxOutputTokens
		if maxOutput <= 0 {
			maxOutput = 4096
		}

		projID := req.ProjectRef
		if projID == "" {
			projID = "default"
		}

		authReq := &spend.AuthorizeRequest{
			GatewayID:          principal.DeviceID,
			RequestID:          reqID,
			IdempotencyKey:     fmt.Sprintf("auth-%s", reqID),
			ProjectID:          projID,
			Provider:           req.Provider,
			Model:              req.Model,
			InputTokenEstimate: inputEst,
			MaxOutputTokens:    maxOutput,
			RequestHash:        reqID,
		}

		var err error
		authResp, err = h.SpendStore.Authorize(r.Context(), tenantID, authReq)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"code":"spend_authorization_error","message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}

		if authResp != nil && authResp.Decision == "deny" && llmMode == "central_enforce" {
			// price_unknown means model is not in the price book — soft-pass (allow request, skip spend tracking)
			if authResp.ReasonCode != spend.ErrCodePriceUnknown {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(buildSpendDenialError(authResp, req.Provider, reqID))
				return
			}
			// Clear authResp so downstream doesn't try to settle a non-existent reservation
			authResp = nil
		}
	}

	// Decrypt Provider Key
	var apiKey string
	if h.Store != nil && len(h.MasterKey) > 0 {
		pk, err := h.Store.GetProviderKeyByProvider(r.Context(), tenantID, req.Provider)
		if err == nil && pk != nil && pk.APIKeyEncrypted != "" {
			aad := []byte(fmt.Sprintf("%s|%s|%s|%d", tenantID, req.Provider, pk.KeyAlias, pk.Version))
			decrypted, decErr := crypto.DecryptWithAAD(h.MasterKey, pk.APIKeyEncrypted, aad)
			if decErr == nil {
				apiKey = decrypted
			} else {
				decryptedLegacy, decLegacyErr := crypto.Decrypt(h.MasterKey, pk.APIKeyEncrypted)
				if decLegacyErr == nil {
					apiKey = decryptedLegacy
				}
			}
		}
	}

	if apiKey == "" {
		if strings.EqualFold(req.Provider, "openai") {
			apiKey = os.Getenv("OPENAI_API_KEY")
		} else if strings.EqualFold(req.Provider, "anthropic") {
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		} else if strings.EqualFold(req.Provider, "google") || strings.EqualFold(req.Provider, "gemini") {
			apiKey = os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				apiKey = os.Getenv("GOOGLE_API_KEY")
			}
		}
	}

	if apiKey == "" {
		if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil {
			relReq := &spend.ReleaseRequest{
				RequestID:      reqID,
				IdempotencyKey: fmt.Sprintf("release-%s", reqID),
				Reason:         "provider_credential_unavailable",
				StatusCode:     http.StatusServiceUnavailable,
				RequestHash:    reqID,
			}
			_, _ = h.SpendStore.Release(r.Context(), tenantID, authResp.ReservationID, relReq)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":       "provider_credential_unavailable",
				"message":    "Provider API credential is not configured or cannot be decrypted for this tenant",
				"request_id": reqID,
			},
		})
		return
	}

	h.handleStreamingDispatch(w, r, tenantID, reqID, &req, apiKey, authResp, vk)
}

func (h *BrokerV2Handler) handleStreamingDispatch(
	w http.ResponseWriter,
	r *http.Request,
	tenantID, reqID string,
	req *BrokerRequestPayload,
	apiKey string,
	authResp *spend.AuthorizeResponse,
	vk *store.VirtualKey,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":{"code":"streaming_unsupported"}}`, http.StatusInternalServerError)
		return
	}

	var headersWritten bool
	onChunk := func(chunk []byte) error {
		select {
		case <-r.Context().Done():
			return errors.New("client disconnected")
		default:
			if !headersWritten {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")
				w.Header().Set("X-Accel-Buffering", "no")
				w.WriteHeader(http.StatusOK)
				headersWritten = true
			}
			_, err := w.Write(chunk)
			if err != nil {
				return err
			}
			flusher.Flush()
			return nil
		}
	}

	usageRep, err := h.ProviderClient.ForwardLLMRequestStream(
		r.Context(),
		req.Provider,
		req.Model,
		req.Payload,
		apiKey,
		onChunk,
	)

	if err != nil {
		if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil {
			relReq := &spend.ReleaseRequest{
				RequestID:      reqID,
				IdempotencyKey: fmt.Sprintf("release-%s", reqID),
				Reason:         "streaming_interrupted",
				StatusCode:     http.StatusBadGateway,
				RequestHash:    reqID,
			}
			_, _ = h.SpendStore.Release(r.Context(), tenantID, authResp.ReservationID, relReq)
		}

		if !headersWritten {
			var upstreamErr *broker.UpstreamHTTPError
			if errors.As(err, &upstreamErr) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(upstreamErr.StatusCode)
				_, _ = w.Write(upstreamErr.Body)
			} else {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusBadGateway)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":       "upstream_provider_error",
						"message":    err.Error(),
						"request_id": reqID,
					},
				})
			}
		} else {
			errEvt := fmt.Sprintf("data: {\"error\":{\"code\":\"streaming_interrupted\",\"message\":%q,\"type\":\"upstream_error\"}}\n\ndata: [DONE]\n\n", err.Error())
			_, _ = w.Write([]byte(errEvt))
			flusher.Flush()
		}
		return
	}

	if !headersWritten {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}

	var settledMicrocents int64
	if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil && usageRep != nil {
		settleReq := &spend.SettleRequest{
			RequestID:         reqID,
			IdempotencyKey:    fmt.Sprintf("settle-%s", reqID),
			ProviderRequestID: usageRep.ProviderRequestID,
			InputTokens:       usageRep.InputTokens,
			OutputTokens:      usageRep.OutputTokens,
			CachedInputTokens: usageRep.CachedInputTokens,
			IsEstimated:       usageRep.IsEstimated,
			UsageSource:       usageRep.UsageSource,
			Status:            usageRep.StatusCode,
			RequestHash:       reqID,
		}
		settledResp, _ := h.SpendStore.Settle(r.Context(), tenantID, authResp.ReservationID, settleReq)
		if settledResp != nil && settledResp.SettledMicrocents > 0 {
			settledMicrocents = int64(settledResp.SettledMicrocents)
		}
	}
	if settledMicrocents <= 0 && usageRep != nil {
		toks := usageRep.InputTokens + usageRep.OutputTokens
		if toks <= 0 {
			toks = req.InputTokenEstimate + 50
		}
		settledMicrocents = toks * 1000
	}
	if vk != nil && settledMicrocents > 0 && h.Store != nil {
		_, _ = h.Store.IncrementVirtualKeySpend(r.Context(), tenantID, vk.ID, settledMicrocents)
	}
}
