package handler

import (
	"net/http"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
)

// getTenantID extracts the tenant UUID from the current request context
// using the middleware's TenantIDFromContext resolver.
func getTenantID(r *http.Request) string {
	return middleware.TenantIDFromContext(r.Context())
}
