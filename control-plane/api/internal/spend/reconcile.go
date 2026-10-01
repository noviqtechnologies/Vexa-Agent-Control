package spend

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"
)

// SpendReconciliationRow represents a single line in a provider reconciliation export
type SpendReconciliationRow struct {
	Date                 string  `json:"date"`
	Provider             string  `json:"provider"`
	Model                string  `json:"model"`
	TotalRequests        int64   `json:"total_requests"`
	PromptTokens         int64   `json:"prompt_tokens"`
	CompletionTokens     int64   `json:"completion_tokens"`
	TotalTokens          int64   `json:"total_tokens"`
	SettledCostMicrocents int64   `json:"settled_cost_microcents"`
	SettledCostUSD       float64 `json:"settled_cost_usd"`
}

// GetReconciliationReport queries the database or memory for aggregated provider usage
func (s *Store) GetReconciliationReport(ctx context.Context, orgID string, since time.Time, until time.Time) ([]SpendReconciliationRow, error) {
	if s.pool == nil {
		// Mock / in-memory empty result
		return []SpendReconciliationRow{}, nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT 
			TO_CHAR(COALESCE(occurred_at, now()), 'YYYY-MM-DD') AS report_date,
			COALESCE(usage_json->>'provider', 'openai') AS provider,
			COALESCE(usage_json->>'model', 'unknown') AS model,
			COUNT(event_id) AS total_requests,
			COALESCE(SUM((usage_json->>'prompt_tokens')::bigint), 0) AS prompt_tokens,
			COALESCE(SUM((usage_json->>'completion_tokens')::bigint), 0) AS completion_tokens,
			COALESCE(SUM((usage_json->>'total_tokens')::bigint), 0) AS total_tokens,
			COALESCE(SUM(amount_microcents), 0) AS settled_cost_microcents
		FROM spend_events
		WHERE organization_id = $1
		  AND event_type = 'SETTLED'
		  AND occurred_at >= $2
		  AND occurred_at <= $3
		GROUP BY 1, 2, 3
		ORDER BY 1 DESC, 2, 3
	`, orgID, since, until)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []SpendReconciliationRow
	for rows.Next() {
		var r SpendReconciliationRow
		if err := rows.Scan(
			&r.Date, &r.Provider, &r.Model, &r.TotalRequests,
			&r.PromptTokens, &r.CompletionTokens, &r.TotalTokens,
			&r.SettledCostMicrocents,
		); err == nil {
			r.SettledCostUSD = float64(r.SettledCostMicrocents) / 100_000_000.0
			result = append(result, r)
		}
	}

	return result, rows.Err()
}

// ExportReconciliationCSV generates a CSV file for provider invoice reconciliation
func (s *Store) ExportReconciliationCSV(ctx context.Context, orgID string, since time.Time, until time.Time) ([]byte, error) {
	report, err := s.GetReconciliationReport(ctx, orgID, since, until)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// CSV Header
	header := []string{
		"date", "provider", "model", "total_requests",
		"prompt_tokens", "completion_tokens", "total_tokens",
		"settled_cost_microcents", "settled_cost_usd",
	}
	if err := w.Write(header); err != nil {
		return nil, err
	}

	for _, row := range report {
		record := []string{
			row.Date,
			row.Provider,
			row.Model,
			fmt.Sprintf("%d", row.TotalRequests),
			fmt.Sprintf("%d", row.PromptTokens),
			fmt.Sprintf("%d", row.CompletionTokens),
			fmt.Sprintf("%d", row.TotalTokens),
			fmt.Sprintf("%d", row.SettledCostMicrocents),
			fmt.Sprintf("%.6f", row.SettledCostUSD),
		}
		if err := w.Write(record); err != nil {
			return nil, err
		}
	}

	w.Flush()
	return buf.Bytes(), w.Error()
}
