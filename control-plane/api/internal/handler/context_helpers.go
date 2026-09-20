package handler

import (
	"encoding/json"
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
)

// getTenantID extracts the tenant UUID from the current request context
// using the middleware's TenantIDFromContext resolver.
func getTenantID(r *http.Request) string {
	return middleware.TenantIDFromContext(r.Context())
}

// writeBrokerJSONError standardizes machine-readable error responses with application/json Content-Type
func writeBrokerJSONError(w http.ResponseWriter, statusCode int, code, publicMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": publicMessage,
		},
	})
}
