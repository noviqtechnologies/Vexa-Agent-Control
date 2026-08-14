package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

// LegacyQuarantineGate blocks new v1 enrollments and strictly denies LLM broker access to legacy clients.
func LegacyQuarantineGate() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Prohibit new enrollments via legacy /api/v1/enroll
			if strings.HasPrefix(r.URL.Path, "/api/v1/enroll") && r.Method == http.MethodPost {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusGone)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":             "legacy_enrollment_retired",
						"message":          "Shared-secret v1 enrollment is permanently retired. Use /api/v2/enrollment.",
						"remediation_code": "USE_V2_ENROLLMENT",
					},
				})
				return
			}

			// 2. Prohibit raw credential downloads
			if strings.HasPrefix(r.URL.Path, "/api/v1/credentials") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":             "raw_credentials_prohibited",
						"message":          "Raw provider API keys are no longer delivered to endpoints. Use /api/v2/broker.",
						"remediation_code": "MIGRATE_TO_BROKER_V2",
					},
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
