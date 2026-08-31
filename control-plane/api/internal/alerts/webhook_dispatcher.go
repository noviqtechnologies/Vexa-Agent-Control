package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

type WebhookAlert struct {
	EventID   string      `json:"event_id"`
	TenantID  string      `json:"tenant_id"`
	Type      string      `json:"type"` // "budget_threshold_80", "budget_threshold_100", "key_revoked", "policy_violation"
	Timestamp time.Time   `json:"timestamp"`
	Payload   interface{} `json:"payload"`
}

type WebhookDispatcher struct {
	httpClient *http.Client
	signingKey []byte
}

func NewWebhookDispatcher(signingKey []byte) *WebhookDispatcher {
	return &WebhookDispatcher{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		signingKey: signingKey,
	}
}

func (d *WebhookDispatcher) DispatchAsync(webhookURL string, alert WebhookAlert) {
	if webhookURL == "" {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		body, err := json.Marshal(alert)
		if err != nil {
			return
		}

		req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(body))
		if err != nil {
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AgentControl-WebhookDispatcher/v1")

		if len(d.signingKey) > 0 {
			mac := hmac.New(sha256.New, d.signingKey)
			mac.Write(body)
			signature := hex.EncodeToString(mac.Sum(nil))
			req.Header.Set("X-Vexa-Signature-256", signature)
		}

		resp, err := d.httpClient.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
		}
	}()
}
