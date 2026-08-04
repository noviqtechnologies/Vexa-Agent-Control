package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/model"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
)

type PolicyMgmtHandler struct {
	store  *store.Store
	broker *sse.Broker
}

func NewPolicyMgmtHandler(s *store.Store, b *sse.Broker) *PolicyMgmtHandler {
	return &PolicyMgmtHandler{store: s, broker: b}
}

func (h *PolicyMgmtHandler) List(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.ListPolicies(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policies == nil {
		policies = []*model.Policy{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (h *PolicyMgmtHandler) GetActive(w http.ResponseWriter, r *http.Request) {
	var policy *model.Policy
	var err error
	
	if r.URL.Query().Get("raw") == "true" {
		policy, err = h.store.GetRawActivePolicy(r.Context())
	} else {
		policy, err = h.store.GetActivePolicy(r.Context())
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if policy == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func (h *PolicyMgmtHandler) Save(w http.ResponseWriter, r *http.Request) {
	var p model.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	
	if p.Version == "" || p.Content == "" {
		http.Error(w, "version and content are required", http.StatusBadRequest)
		return
	}
	
	p.IsActive = true
	if err := h.store.SavePolicy(r.Context(), &p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)

	// Broadcast the new policy over SSE to connected gateways
	if h.broker != nil {
		h.broker.Publish(formatSSE("policy_update", p.Content))
	}
}

func formatSSE(event, data string) []byte {
	var sb strings.Builder
	sb.WriteString("event: " + event + "\n")
	for _, line := range strings.Split(data, "\n") {
		sb.WriteString("data: " + line + "\n")
	}
	sb.WriteString("\n")
	return []byte(sb.String())
}

func (h *PolicyMgmtHandler) Subscribe(w http.ResponseWriter, r *http.Request) {
	if h.broker == nil {
		http.Error(w, "SSE broker not configured", http.StatusInternalServerError)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientChan, cleanup := h.broker.Subscribe()
	defer cleanup()

	// Send initial active policy if available
	policy, err := h.store.GetActivePolicy(r.Context())
	if err == nil && policy != nil {
		w.Write(formatSSE("policy_update", policy.Content))
		flusher.Flush()
	}

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case payload := <-clientChan:
			w.Write(payload)
			flusher.Flush()
		}
	}
}
