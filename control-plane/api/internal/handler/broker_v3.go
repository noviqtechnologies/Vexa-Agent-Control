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
				http.Error(w, `{"error":{"code":"invalid_virtual_key","message":"Invalid or revoked virtual key"}}`, http.StatusUnauthorized)
				return
			}
			http.Error(w, fmt.Sprintf(`{"error":{"code":"internal_error","message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}
		tenantID = vk.TenantID
	} else {
		tenantID = getTenantID(r)
		if tenantID == "" {
			http.Error(w, `{"error":{"code":"auth_required","message":"Authorization header or virtual key required"}}`, http.StatusUnauthorized)
			return
		}
	}

	var req BrokerV3DispatchPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":{"code":"invalid_request","message":"Malformed JSON request body"}}`, http.StatusBadRequest)
		return
	}

	// 2. Validate Scoped Route / Model Allowlist if Virtual Key is present
	if vk != nil {
		if len(vk.AllowedModels) > 0 {
			modelAllowed := false
			for _, m := range vk.AllowedModels {
				if strings.EqualFold(m, req.Model) || m == "*" {
					modelAllowed = true
					break
				}
			}
			if !modelAllowed {
				http.Error(w, fmt.Sprintf(`{"error":{"code":"model_not_allowed","message":"Model '%s' is not permitted for this virtual key"}}`, req.Model), http.StatusForbidden)
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
					http.Error(w, `{"error":{"code":"budget_exceeded","message":"Monthly spend budget exceeded for this virtual key"}}`, http.StatusPaymentRequired)
					return
				}
			}
		} else {
			_, err := h.store.IncrementVirtualKeySpend(r.Context(), tenantID, vk.ID, estimatedMicrocents)
			if err != nil {
				if errors.Is(err, store.ErrVirtualKeyBudgetExceeded) {
					http.Error(w, `{"error":{"code":"budget_exceeded","message":"Monthly spend budget exceeded for this virtual key"}}`, http.StatusPaymentRequired)
					return
				}
				http.Error(w, fmt.Sprintf(`{"error":{"code":"internal_error","message":%q}}`, err.Error()), http.StatusInternalServerError)
				return
			}
		}
	}

	// 4. Retrieve Decrypted Upstream Provider Secret from Central KMS Vault
	providerSecret, err := h.store.GetDecryptedProviderKey(r.Context(), tenantID, req.Provider, h.kmsProvider)
	if err != nil {
		if errors.Is(err, store.ErrProviderKeyNotFound) {
			http.Error(w, fmt.Sprintf(`{"error":{"code":"provider_unconfigured","message":"No provider API key configured for '%s'"}}`, req.Provider), http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":{"code":"kms_error","message":%q}}`, err.Error()), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":{"code":"upstream_error","message":%q}}`, err.Error()), http.StatusBadGateway)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(llmResp.Response)
	}
}
