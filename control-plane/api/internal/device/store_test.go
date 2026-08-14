package device

import (
	"testing"
	"time"
)

func TestDeviceTypesAndPayloads(t *testing.T) {
	req := &EnrollDeviceRequest{
		Hostname:       "test-laptop",
		UserIdentifier: "dev@example.com",
		OS:             "windows",
		OSVersion:      "11",
		PublicKey:      "ed25519:test",
		DaemonVersion:  "2.1.0",
	}

	if req.Hostname != "test-laptop" {
		t.Fatalf("expected test-laptop, got %s", req.Hostname)
	}

	heartbeat := &TelemetryHeartbeatRequest{
		DeviceID:          "device-123",
		OverallCompliance: ComplianceStateCompliant,
		IdeTargets: []IdeTargetStatus{
			{
				Name:            "cursor",
				Installed:       true,
				ProxyConfigured: true,
				ComplianceState: ComplianceStateCompliant,
			},
		},
		TamperEvents: []TamperEventPayload{
			{
				IdeName:            "cursor",
				EventType:          EventTypeAutoHealed,
				TamperDetails:      "restored base url",
				HealedSuccessfully: true,
				OccurredAt:         time.Now().UTC(),
			},
		},
		Timestamp: time.Now().UTC(),
	}

	if len(heartbeat.IdeTargets) != 1 || heartbeat.IdeTargets[0].Name != "cursor" {
		t.Fatalf("unexpected ide targets: %+v", heartbeat.IdeTargets)
	}

	if len(heartbeat.TamperEvents) != 1 || heartbeat.TamperEvents[0].EventType != EventTypeAutoHealed {
		t.Fatalf("unexpected tamper events: %+v", heartbeat.TamperEvents)
	}
}

func TestGenerateToken(t *testing.T) {
	tok := generateToken("otet_dev")
	if len(tok) < 15 || tok[:9] != "otet_dev_" {
		t.Fatalf("unexpected token generated: %s", tok)
	}
}
