package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

func TestP0_RouterAuth_AllThreeEndpointsRejectAnonymous(t *testing.T) {
	st := &store.Store{} // nil pool for mock
	ingressSecret := "test-ingress-secret"

	r := chi.NewRouter()

	ds := &mockStore{}
	ingestH := NewIngestHandler(ds, nil, nil)
	effectiveH := NewEffectivePolicyHandler(nil, ds)

	r.Route("/api/v2/policy", func(r chi.Router) {
		r.Use(middleware.StrictDeviceOrAssertionAuth(st, ingressSecret))
		r.Get("/effective", effectiveH.GetEffectiveSigned)
	})

	r.Route("/api/v2/telemetry", func(r chi.Router) {
		r.Use(middleware.StrictDeviceOrAssertionAuth(st, ingressSecret))
		r.Post("/ingest", ingestH.PostTelemetryIngest)
	})

	r.Route("/api/v2/audit", func(r chi.Router) {
		r.Use(middleware.StrictDeviceOrAssertionAuth(st, ingressSecret))
		r.Get("/checkpoints", ingestH.GetAuditCheckpoints)
	})

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v2/policy/effective"},
		{http.MethodPost, "/api/v2/telemetry/ingest"},
		{http.MethodGet, "/api/v2/audit/checkpoints"},
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for anonymous %s %s, got %d (body: %s)",
				ep.method, ep.path, rec.Code, rec.Body.String())
		}
	}
}
