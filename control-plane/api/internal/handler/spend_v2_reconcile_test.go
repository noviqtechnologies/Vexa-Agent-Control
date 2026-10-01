package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
)

func TestSpendV2Handler_ReconcileExport_CSV(t *testing.T) {
	spendStore := spend.NewStore(nil)
	h := NewSpendV2Handler(spendStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/spend/reconcile", nil)
	rec := httptest.NewRecorder()

	h.ReconcileExport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/csv") {
		t.Errorf("expected text/csv Content-Type, got %s", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "date,provider,model,total_requests") {
		t.Errorf("expected CSV header in body, got %s", body)
	}
}

func TestSpendV2Handler_ReconcileExport_JSON(t *testing.T) {
	spendStore := spend.NewStore(nil)
	h := NewSpendV2Handler(spendStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/spend/reconcile?format=json", nil)
	rec := httptest.NewRecorder()

	h.ReconcileExport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected application/json Content-Type, got %s", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"report"`) {
		t.Errorf("expected JSON report field in body, got %s", body)
	}
}
