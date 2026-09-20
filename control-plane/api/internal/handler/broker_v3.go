package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/broker"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/valkey"
)

type BrokerV3Handler struct {
	store          DataStore
	kmsProvider    kms.KMSProvider
	spendStore     *spend.Store
	providerClient broker.ProviderClient
	valkeyClient   valkey.Client
}

func NewBrokerV3Handler(
	st DataStore,
	kmsProvider kms.KMSProvider,
	spendStore *spend.Store,
	pc broker.ProviderClient,
) *BrokerV3Handler {
	vkClient, _ := valkey.NewClient()
	return &BrokerV3Handler{
		store:          st,
		kmsProvider:    kmsProvider,
		spendStore:     spendStore,
		providerClient: pc,
		valkeyClient:   vkClient,
	}
}

func (h *BrokerV3Handler) SetValkeyClient(c valkey.Client) {
	h.valkeyClient = c
}

type BrokerV3DispatchPayload struct {
	RequestID          string          `json:"request_id"`
	Provider           string          `json:"provider"`
	Model              string          `json:"model"`
	InputTokenEstimate int64           `json:"input_token_estimate,omitempty"`
	MaxOutputTokens    int64           `json:"max_output_tokens,omitempty"`
	Stream             bool            `json:"stream"`
	Payload            json.RawMessage `json:"payload"`
}

// POST /api/v3/broker/dispatch
func (h *BrokerV3Handler) Dispatch(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate via Virtual Key (Bearer token or X-Virtual-Key header)
	authHeader := r.Header.Get("Authorization")
	virtualKeySecret := strings.TrimPrefix(authHeader, "Bearer ")
	if virtualKeySecret == authHeader || virtualKeySecret == "" {
		virtualKeySecret = r.Header.Get("X-Virtual-Key")
	}

	var vk *store.VirtualKey
	var tenantID string

	if virtualKeySecret != "" {
		hasher := sha256.New()
		hasher.Write([]byte(virtualKeySecret))
		keyHash := hex.EncodeToString(hasher.Sum(nil))

		var err error
		vk, err = h.store.GetVirtualKeyByHash(r.Context(), keyHash)
		if err != nil {
			if errors.Is(err, store.ErrVirtualKeyNotFound) {
				writeBrokerJSONError(w, http.StatusUnauthorized, "invalid_virtual_key", "Invalid, expired, or revoked virtual key")
				return
			}
			writeBrokerJSONError(w, http.StatusInternalServerError, "internal_error", "An internal error occurred while validating virtual key")
			return
		}
		tenantID = vk.TenantID
	} else {
		tenantID = getTenantID(r)
		if tenantID == "" {
			writeBrokerJSONError(w, http.StatusUnauthorized, "auth_required", "Authorization header or virtual key required")
			return
		}
	}

	var req BrokerV3DispatchPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrokerJSONError(w, http.StatusBadRequest, "invalid_request", "Malformed JSON request body")
		return
	}

	// 2. Validate Scoped Route / Model Allowlist if Virtual Key is present
	if vk != nil {
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
				writeBrokerJSONError(w, http.StatusForbidden, "model_not_allowed", fmt.Sprintf("Model '%s' is not permitted for this virtual key", req.Model))
				return
			}
		}
	}

	// 3. Preflight Microcents Spend Reservation Check (Valkey-backed atomic CAS)
	if vk != nil && vk.MonthlyBudgetMicrocents > 0 {
		estimatedTokens := req.InputTokenEstimate + req.MaxOutputTokens
		if estimatedTokens == 0 {
			estimatedTokens = 1000 // default conservative reservation
		}
		// Baseline estimate: 1000 microcents per token
		estimatedMicrocents := estimatedTokens * 1000

		if h.valkeyClient != nil {
			_, err := h.valkeyClient.ReserveSpend(r.Context(), vk.ID, estimatedMicrocents, vk.MonthlyBudgetMicrocents)
			if err != nil {
				if errors.Is(err, valkey.ErrBudgetCapExceeded) {
					writeBrokerJSONError(w, http.StatusPaymentRequired, "budget_exceeded", "Monthly spend budget exceeded for this virtual key")
					return
				}
				// Fail-closed on connection or infrastructure error
				writeBrokerJSONError(w, http.StatusServiceUnavailable, "spend_service_unavailable", "Unable to verify spend budget reservation")
				return
			}
		} else {
			_, err := h.store.IncrementVirtualKeySpend(r.Context(), tenantID, vk.ID, estimatedMicrocents)
			if err != nil {
				if errors.Is(err, store.ErrVirtualKeyBudgetExceeded) {
					writeBrokerJSONError(w, http.StatusPaymentRequired, "budget_exceeded", "Monthly spend budget exceeded for this virtual key")
					return
				}
				writeBrokerJSONError(w, http.StatusServiceUnavailable, "spend_service_unavailable", "Unable to record spend reservation")
				return
			}
		}
	}

	// 4. Retrieve Decrypted Upstream Provider Secret from Central KMS Vault
	providerSecret, err := h.store.GetDecryptedProviderKey(r.Context(), tenantID, req.Provider, h.kmsProvider)
	if err != nil {
		if errors.Is(err, store.ErrProviderKeyNotFound) {
			writeBrokerJSONError(w, http.StatusNotFound, "provider_unconfigured", fmt.Sprintf("No provider API key configured for '%s'", req.Provider))
			return
		}
		writeBrokerJSONError(w, http.StatusInternalServerError, "kms_error", "Internal encryption service error")
		return
	}

	// 5. Forward to Upstream Provider using ProviderClient
	w.Header().Set("X-Vexa-Tenant-ID", tenantID)
	w.Header().Set("X-Broker-Version", "v3")

	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, isFlusher := w.(http.Flusher)

		_, err := h.providerClient.ForwardLLMRequestStream(r.Context(), req.Provider, req.Model, req.Payload, providerSecret, func(chunk []byte) error {
			if _, wErr := w.Write(chunk); wErr != nil {
				return wErr
			}
			if isFlusher {
				flusher.Flush()
			}
			return nil
		})

		if err != nil {
			// Stream already started, error reported
			return
		}
	} else {
		w.Header().Set("Content-Type", "application/json")

		llmResp, _, err := h.providerClient.ForwardLLMRequest(r.Context(), req.Provider, req.Model, false, req.Payload, providerSecret)
		if err != nil {
			writeBrokerJSONError(w, http.StatusBadGateway, "upstream_error", "The upstream provider request failed")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(llmResp.Response)
	}
}
