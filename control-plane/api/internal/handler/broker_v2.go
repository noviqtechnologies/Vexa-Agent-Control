package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/broker"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/routing"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/telemetry"
)

type BrokerV2Handler struct {
	Store          *store.Store
	SpendStore     *spend.Store
	ProviderClient broker.ProviderClient
	MasterKey      []byte
	routerEngine   *routing.Engine
	activeStreams  sync.Map
}

func NewBrokerV2Handler(st *store.Store, pc broker.ProviderClient, masterKey []byte, spendStore *spend.Store) *BrokerV2Handler {
	return &BrokerV2Handler{
		Store:          st,
		SpendStore:     spendStore,
		ProviderClient: pc,
		MasterKey:      masterKey,
		routerEngine:   routing.NewEngine(st),
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

func (h *BrokerV2Handler) resolveAPIKey(ctx context.Context, tenantID, provider string) string {
	var apiKey string
	if h.Store != nil && len(h.MasterKey) > 0 {
		pk, err := h.Store.GetProviderKeyByProvider(ctx, tenantID, provider)
		if err == nil && pk != nil && pk.APIKeyEncrypted != "" {
			aad := []byte(fmt.Sprintf("%s|%s|%s|%d", tenantID, provider, pk.KeyAlias, pk.Version))
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
		lower := strings.ToLower(provider)
		if lower == "openai" {
			apiKey = os.Getenv("OPENAI_API_KEY")
		} else if lower == "anthropic" {
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		} else if lower == "google" || lower == "gemini" {
			apiKey = os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				apiKey = os.Getenv("GOOGLE_API_KEY")
			}
		}
	}
	return apiKey
}

// POST /api/v2/broker/llm-requests and POST /api/v3/broker/llm-requests
func (h *BrokerV2Handler) HandleLLMRequest(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/v2/") {
		w.Header().Set("Deprecation", "@1741564800")
		w.Header().Set("Sunset", "Thu, 31 Dec 2026 23:59:59 GMT")
		w.Header().Set("Link", "</api/v3/broker/dispatch>; rel=\"successor-version\"")
	}

	// 1. Trace Context
	traceCtx := telemetry.ExtractOrGenerateTraceContext(r)
	w.Header().Set("traceparent", traceCtx.FormatTraceparent())

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
	w.Header().Set("X-Request-ID", reqID)

	// Check Idempotency Key
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		idempotencyKey = r.Header.Get("X-Idempotency-Key")
	}

	if idempotencyKey != "" && h.Store != nil {
		existingReq, err := h.Store.GetBrokerRequestByIdempotencyKey(r.Context(), tenantID, idempotencyKey)
		if err == nil && existingReq != nil && len(existingReq.CachedResponse) > 0 {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("X-Idempotent-Replay", "true")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(existingReq.CachedResponse)
			return
		}
	}

	llmMode := req.LLMMode
	if llmMode == "" {
		llmMode = "central_enforce"
	}

	// 2. Resolve Virtual Key if present
	virtualKeySecret := r.Header.Get("X-Virtual-Key")
	if virtualKeySecret == "" {
		virtualKeySecret = req.VirtualKey
	}
	if virtualKeySecret == "" {
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "Bearer ") {
			cand := strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer "))
			if strings.HasPrefix(cand, "sk-vex-") || strings.HasPrefix(cand, "vex_") || strings.HasPrefix(cand, "vexa_") {
				virtualKeySecret = cand
			}
		}
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
			modelLower := strings.ToLower(req.Model)
			for _, m := range vk.AllowedModels {
				mLower := strings.ToLower(m)
				if mLower == "*" || mLower == modelLower || (strings.HasSuffix(mLower, "*") && strings.HasPrefix(modelLower, strings.TrimSuffix(mLower, "*"))) {
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

	// 3. Resolve Authoritative Route (Primary + Fallback)
	var routeRes *routing.RouteResult
	if h.routerEngine != nil {
		routeRes, _ = h.routerEngine.ResolveRoute(r.Context(), tenantID, "chat_completions", req.Model, "")
	}
	if routeRes == nil {
		routeRes = &routing.RouteResult{
			Primary: routing.TargetCandidate{
				Type:     "primary",
				Provider: req.Provider,
				Model:    req.Model,
			},
			MaxAttempts:  2,
			DeadlineMs:   30000,
			RetryClasses: []string{"502", "503", "504", "429", "connect_timeout", "dns_error"},
		}
	}

	// 4. Preflight Spend Authorization
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

		var vkPrefix, vkAlias, internalUser string
		if vk != nil {
			vkPrefix = vk.KeyPrefix
			vkAlias = vk.Name
			if vk.CreatedBy != "" {
				internalUser = vk.CreatedBy
			}
		} else if virtualKeySecret != "" {
			if len(virtualKeySecret) > 14 {
				vkPrefix = virtualKeySecret[:10] + "..."
			} else {
				vkPrefix = virtualKeySecret
			}
			vkAlias = vkPrefix
		}

		if internalUser == "" && principal != nil {
			if principal.ProviderSubject != nil && *principal.ProviderSubject != "" {
				internalUser = *principal.ProviderSubject
			} else if principal.UserID != nil && *principal.UserID != "" {
				internalUser = *principal.UserID
			}
		}

		authReq := &spend.AuthorizeRequest{
			GatewayID:          principal.DeviceID,
			RequestID:          reqID,
			IdempotencyKey:     fmt.Sprintf("auth-%s", reqID),
			ProjectID:          projID,
			Provider:           routeRes.Primary.Provider,
			Model:              routeRes.Primary.Model,
			InputTokenEstimate: inputEst,
			MaxOutputTokens:    maxOutput,
			RequestHash:        reqID,
			VirtualKeyPrefix:   vkPrefix,
			VirtualKeyAlias:    vkAlias,
			InternalUserID:     internalUser,
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
			authResp = nil
		}
	}

	// 5. Register Broker Request in Store
	var profileIDPtr *string
	if routeRes.Profile != nil && routeRes.Profile.ID != "" {
		pID := routeRes.Profile.ID
		profileIDPtr = &pID
	}
	var resIDStr string
	if authResp != nil {
		resIDStr = authResp.ReservationID
	}

	if h.Store != nil {
		var uID string
		if principal.UserID != nil {
			uID = *principal.UserID
		}
		_ = h.Store.RecordBrokerRequest(r.Context(), &model.BrokerRequest{
			RequestID:          reqID,
			OrganizationID:     tenantID,
			IdempotencyKey:     idempotencyKey,
			TraceID:            traceCtx.TraceID,
			PrincipalDeviceID:  principal.DeviceID,
			PrincipalUserID:    uID,
			RouteProfileID:     profileIDPtr,
			RequestedProvider:  req.Provider,
			RequestedModel:     req.Model,
			Stream:             req.Stream,
			Status:             "in_flight",
			SpendReservationID: resIDStr,
		})
	}

	// 6. Handle Streaming vs Buffered Execution
	if req.Stream {
		h.handleStreamingDispatch(w, r, tenantID, reqID, &req, routeRes, authResp, vk, traceCtx)
		return
	}

	// 7. Authoritative Buffered 2-Attempt Loop
	deadlineDuration := time.Duration(routeRes.DeadlineMs) * time.Millisecond
	reqCtx, cancelReq := context.WithTimeout(r.Context(), deadlineDuration)
	defer cancelReq()

	var finalResp *broker.LLMResponse
	var finalUsage *broker.UsageReport
	var terminalError error
	var totalTokensReported int64

	targets := []routing.TargetCandidate{routeRes.Primary}
	if routeRes.Fallback != nil && routeRes.MaxAttempts >= 2 {
		targets = append(targets, *routeRes.Fallback)
	}

	for attemptIdx, target := range targets {
		attemptNum := attemptIdx + 1
		attemptID := fmt.Sprintf("%s-att-%d", reqID, attemptNum)

		apiKey := h.resolveAPIKey(reqCtx, tenantID, target.Provider)
		if apiKey == "" {
			terminalError = fmt.Errorf("credential unavailable for %s", target.Provider)
			if h.Store != nil {
				_ = h.Store.RecordBrokerAttemptStart(reqCtx, &model.BrokerAttempt{
					AttemptID:     attemptID,
					RequestID:     reqID,
					AttemptNumber: attemptNum,
					TargetType:    target.Type,
					Provider:      target.Provider,
					Model:         target.Model,
				})
				_ = h.Store.RecordBrokerAttemptComplete(reqCtx, &model.BrokerAttempt{
					AttemptID:            attemptID,
					HTTPStatus:           503,
					ErrorClass:           "credential_unavailable",
					ErrorMessageRedacted: "Provider API credential is not configured or cannot be decrypted for this tenant",
				})
			}
			continue
		}

		if h.Store != nil {
			_ = h.Store.RecordBrokerAttemptStart(reqCtx, &model.BrokerAttempt{
				AttemptID:     attemptID,
				RequestID:     reqID,
				AttemptNumber: attemptNum,
				TargetType:    target.Type,
				Provider:      target.Provider,
				Model:         target.Model,
			})
		}

		startTime := time.Now()
		llmResp, usageRep, err := h.ProviderClient.ForwardLLMRequest(
			reqCtx,
			target.Provider,
			target.Model,
			false,
			req.Payload,
			apiKey,
		)
		latency := int(time.Since(startTime).Milliseconds())

		if err == nil {
			// SUCCESS
			finalResp = llmResp
			finalUsage = usageRep
			terminalError = nil

			var inToks, outToks, cachedToks int64
			var usageSrc = "provider_reported"
			if usageRep != nil {
				inToks = usageRep.InputTokens
				outToks = usageRep.OutputTokens
				cachedToks = usageRep.CachedInputTokens
				usageSrc = usageRep.UsageSource
				totalTokensReported += inToks + outToks
			}

			if h.Store != nil {
				_ = h.Store.RecordBrokerAttemptComplete(reqCtx, &model.BrokerAttempt{
					AttemptID:    attemptID,
					LatencyMs:    latency,
					HTTPStatus:   200,
					InputTokens:  inToks,
					OutputTokens: outToks,
					CachedTokens: cachedToks,
					UsageSource:  usageSrc,
				})
			}
			break // Break on success!
		}

		// FAILURE on this attempt
		terminalError = err
		var statusCode = 500
		var upstreamErr *broker.UpstreamHTTPError
		if errors.As(err, &upstreamErr) {
			statusCode = upstreamErr.StatusCode
		}

		remainingTime := deadlineDuration - time.Since(startTime)
		classification := broker.ClassifyUpstreamError(err, statusCode, nil, remainingTime, routeRes.RetryClasses)

		if h.Store != nil {
			_ = h.Store.RecordBrokerAttemptComplete(reqCtx, &model.BrokerAttempt{
				AttemptID:            attemptID,
				LatencyMs:            latency,
				HTTPStatus:           statusCode,
				ErrorClass:           classification.ErrorClass,
				ErrorMessageRedacted: classification.ReasonDescription,
			})
		}

		// Check if we should retry
		if classification.IsRetryable && attemptNum < len(targets) && classification.CanFitInDeadline {
			backoff := broker.ComputeJitteredBackoff(attemptNum, 50*time.Millisecond, 1*time.Second)
			if classification.RetryAfter > 0 {
				backoff = classification.RetryAfter
			}
			select {
			case <-reqCtx.Done():
				terminalError = reqCtx.Err()
				break
			case <-time.After(backoff):
				// Proceed to next target in loop
			}
		} else {
			// Non-retryable error or exhausted attempts
			break
		}
	}

	// 8. Settle Spend & Finalize Request
	var settledMicrocents int64
	if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil {
		if finalResp != nil && finalUsage != nil {
			settleReq := &spend.SettleRequest{
				RequestID:         reqID,
				IdempotencyKey:    fmt.Sprintf("settle-%s", reqID),
				ProviderRequestID: finalUsage.ProviderRequestID,
				InputTokens:       finalUsage.InputTokens,
				OutputTokens:      finalUsage.OutputTokens,
				CachedInputTokens: finalUsage.CachedInputTokens,
				IsEstimated:       finalUsage.IsEstimated,
				UsageSource:       finalUsage.UsageSource,
				Status:            finalUsage.StatusCode,
				RequestHash:       reqID,
			}
			settledResp, _ := h.SpendStore.Settle(r.Context(), tenantID, authResp.ReservationID, settleReq)
			if settledResp != nil && settledResp.SettledMicrocents > 0 {
				settledMicrocents = int64(settledResp.SettledMicrocents)
			}
		} else {
			relReq := &spend.ReleaseRequest{
				RequestID:      reqID,
				IdempotencyKey: fmt.Sprintf("release-%s", reqID),
				Reason:         "attempts_failed",
				StatusCode:     http.StatusBadGateway,
				RequestHash:    reqID,
			}
			_, _ = h.SpendStore.Release(r.Context(), tenantID, authResp.ReservationID, relReq)
		}
	}

	if vk != nil && settledMicrocents > 0 && h.Store != nil {
		_, _ = h.Store.IncrementVirtualKeySpend(r.Context(), tenantID, vk.ID, settledMicrocents)
	}

	if finalResp != nil {
		respJSON, _ := json.Marshal(finalResp)
		if h.Store != nil {
			_ = h.Store.FinalizeBrokerRequest(r.Context(), reqID, "succeeded", "success", settledMicrocents, respJSON)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(respJSON)
		return
	}

	// Terminal Failure Response
	if h.Store != nil {
		_ = h.Store.FinalizeBrokerRequest(r.Context(), reqID, "failed", "upstream_error", 0, nil)
	}

	if terminalError != nil && strings.Contains(terminalError.Error(), "credential unavailable") {
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

	var upstreamErr *broker.UpstreamHTTPError
	if errors.As(terminalError, &upstreamErr) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(upstreamErr.StatusCode)
		_, _ = w.Write(upstreamErr.Body)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":       "broker_upstream_failure",
			"message":    terminalError.Error(),
			"request_id": reqID,
		},
	})
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
	w.Header().Set("X-Request-ID", reqID)

	traceCtx := telemetry.ExtractOrGenerateTraceContext(r)
	w.Header().Set("traceparent", traceCtx.FormatTraceparent())

	// Route Resolution
	var routeRes *routing.RouteResult
	if h.routerEngine != nil {
		routeRes, _ = h.routerEngine.ResolveRoute(r.Context(), tenantID, "chat_completions", req.Model, "")
	}
	if routeRes == nil {
		routeRes = &routing.RouteResult{
			Primary: routing.TargetCandidate{
				Type:     "primary",
				Provider: req.Provider,
				Model:    req.Model,
			},
			MaxAttempts: 2,
			DeadlineMs:  30000,
		}
	}

	// Virtual Key
	var vk *store.VirtualKey
	if req.VirtualKey != "" && h.Store != nil {
		hasher := sha256.New()
		hasher.Write([]byte(req.VirtualKey))
		vk, _ = h.Store.GetVirtualKeyByHash(r.Context(), hex.EncodeToString(hasher.Sum(nil)))
	}

	// Spend Preflight
	var authResp *spend.AuthorizeResponse
	if h.SpendStore != nil {
		authReq := &spend.AuthorizeRequest{
			GatewayID:          principal.DeviceID,
			RequestID:          reqID,
			IdempotencyKey:     fmt.Sprintf("auth-%s", reqID),
			ProjectID:          "default",
			Provider:           routeRes.Primary.Provider,
			Model:              routeRes.Primary.Model,
			InputTokenEstimate: 100,
			MaxOutputTokens:    4096,
			RequestHash:        reqID,
		}
		authResp, _ = h.SpendStore.Authorize(r.Context(), tenantID, authReq)
	}

	h.handleStreamingDispatch(w, r, tenantID, reqID, &req, routeRes, authResp, vk, traceCtx)
}

func (h *BrokerV2Handler) handleStreamingDispatch(
	w http.ResponseWriter,
	r *http.Request,
	tenantID, reqID string,
	req *BrokerRequestPayload,
	routeRes *routing.RouteResult,
	authResp *spend.AuthorizeResponse,
	vk *store.VirtualKey,
	traceCtx *telemetry.TraceContext,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":{"code":"streaming_unsupported"}}`, http.StatusInternalServerError)
		return
	}

	streamCtx, cancelStream := context.WithCancel(r.Context())
	h.activeStreams.Store(reqID, cancelStream)
	defer func() {
		h.activeStreams.Delete(reqID)
		cancelStream()
	}()

	var headersWritten bool
	var streamCommitted bool
	var writeMu sync.Mutex

	onChunk := func(chunk []byte) error {
		select {
		case <-streamCtx.Done():
			return errors.New("client disconnected")
		default:
			writeMu.Lock()
			defer writeMu.Unlock()

			if !headersWritten {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")
				w.Header().Set("X-Accel-Buffering", "no")
				w.WriteHeader(http.StatusOK)
				headersWritten = true
				streamCommitted = true
			}
			_, err := w.Write(chunk)
			if err != nil {
				return err
			}
			flusher.Flush()
			return nil
		}
	}

	primaryKey := h.resolveAPIKey(streamCtx, tenantID, routeRes.Primary.Provider)
	if primaryKey == "" {
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

	targets := []routing.TargetCandidate{routeRes.Primary}
	if routeRes.Fallback != nil && routeRes.MaxAttempts >= 2 {
		targets = append(targets, *routeRes.Fallback)
	}

	var finalUsage *broker.UsageReport
	var streamErr error

	for attemptIdx, target := range targets {
		attemptNum := attemptIdx + 1
		attemptID := fmt.Sprintf("%s-att-%d", reqID, attemptNum)

		apiKey := h.resolveAPIKey(streamCtx, tenantID, target.Provider)
		if apiKey == "" {
			streamErr = fmt.Errorf("credential unavailable for %s", target.Provider)
			continue
		}

		if h.Store != nil {
			_ = h.Store.RecordBrokerAttemptStart(streamCtx, &model.BrokerAttempt{
				AttemptID:     attemptID,
				RequestID:     reqID,
				AttemptNumber: attemptNum,
				TargetType:    target.Type,
				Provider:      target.Provider,
				Model:         target.Model,
			})
		}

		startTime := time.Now()
		usageRep, err := h.ProviderClient.ForwardLLMRequestStream(
			streamCtx,
			target.Provider,
			target.Model,
			req.Payload,
			apiKey,
			onChunk,
		)
		latency := int(time.Since(startTime).Milliseconds())

		if err == nil {
			// Stream completed successfully
			finalUsage = usageRep
			streamErr = nil
			if h.Store != nil {
				_ = h.Store.RecordBrokerAttemptComplete(streamCtx, &model.BrokerAttempt{
					AttemptID:       attemptID,
					LatencyMs:       latency,
					HTTPStatus:      200,
					StreamCommitted: true,
					UsageSource:     "provider_reported",
				})
			}
			break
		}

		// Stream failure
		streamErr = err
		if h.Store != nil {
			_ = h.Store.RecordBrokerAttemptComplete(streamCtx, &model.BrokerAttempt{
				AttemptID:            attemptID,
				LatencyMs:            latency,
				HTTPStatus:           500,
				StreamCommitted:      streamCommitted,
				ErrorClass:           "stream_error",
				ErrorMessageRedacted: err.Error(),
			})
		}

		// PRE-COMMIT RETRY BARRIER: Only retry if NO bytes have been flushed to downstream client
		if !streamCommitted && attemptNum < len(targets) {
			continue // Try fallback
		}
		// If stream was already committed downstream, do NOT retry; break immediately
		break
	}

	if !headersWritten && streamErr != nil {
		var upstreamErr *broker.UpstreamHTTPError
		if errors.As(streamErr, &upstreamErr) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(upstreamErr.StatusCode)
			_, _ = w.Write(upstreamErr.Body)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":{"code":"stream_failed","message":%q}}`, streamErr.Error()), http.StatusBadGateway)
		return
	}

	// Settle Stream
	if authResp != nil && authResp.ReservationID != "" && h.SpendStore != nil {
		if streamErr == nil && finalUsage != nil {
			settleReq := &spend.SettleRequest{
				RequestID:         reqID,
				IdempotencyKey:    fmt.Sprintf("settle-%s", reqID),
				ProviderRequestID: finalUsage.ProviderRequestID,
				InputTokens:       finalUsage.InputTokens,
				OutputTokens:      finalUsage.OutputTokens,
				CachedInputTokens: finalUsage.CachedInputTokens,
				IsEstimated:       finalUsage.IsEstimated,
				UsageSource:       finalUsage.UsageSource,
				Status:            finalUsage.StatusCode,
				RequestHash:       reqID,
			}
			_, _ = h.SpendStore.Settle(r.Context(), tenantID, authResp.ReservationID, settleReq)
		} else {
			relReq := &spend.ReleaseRequest{
				RequestID:      reqID,
				IdempotencyKey: fmt.Sprintf("release-%s", reqID),
				Reason:         "stream_error",
				StatusCode:     http.StatusBadGateway,
				RequestHash:    reqID,
			}
			_, _ = h.SpendStore.Release(r.Context(), tenantID, authResp.ReservationID, relReq)
		}
	}
}

// CancelStream handles POST /api/v3/broker/llm-stream/{id}/cancel
func (h *BrokerV2Handler) CancelStream(w http.ResponseWriter, r *http.Request) {
	reqID := chi.URLParam(r, "id")
	if cancel, ok := h.activeStreams.Load(reqID); ok {
		if cancelFn, ok := cancel.(context.CancelFunc); ok {
			cancelFn()
		}
		h.activeStreams.Delete(reqID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":     "cancelled",
		"request_id": reqID,
	})
}
