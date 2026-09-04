package spend

import (
	"context"
	"fmt"
	"time"
)

// ── SPEND ANALYTICS & EVENTS ─────────────────────────────────────────────────

func (s *Store) ListEffectiveBudgetWindows(ctx context.Context, orgID string) ([]BudgetWindow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT window_id, organization_id, policy_version_id, scope_type, scope_id,
		       window_start, window_end, limit_microcents, reserved_microcents, settled_microcents, version
		FROM budget_windows
		WHERE organization_id = $1 AND window_end >= now()
		ORDER BY scope_type, scope_id, window_start DESC
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []BudgetWindow
	for rows.Next() {
		var w BudgetWindow
		if err := rows.Scan(
			&w.WindowID, &w.OrganizationID, &w.PolicyVersionID, &w.ScopeType, &w.ScopeID,
			&w.WindowStart, &w.WindowEnd, &w.LimitMicrocents, &w.ReservedMicrocents, &w.SettledMicrocents, &w.Version,
		); err == nil {
			w.AvailableMicrocents = w.LimitMicrocents - w.ReservedMicrocents - w.SettledMicrocents
			res = append(res, w)
		}
	}
	return res, rows.Err()
}

func (s *Store) ListSpendEvents(ctx context.Context, orgID string, limit int) ([]SpendEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT se.event_id, se.organization_id, se.reservation_id, se.request_id, se.event_type,
		       se.amount_microcents, se.currency, se.usage_json, se.provider_request_id, se.actor,
		       COALESCE(NULLIF(d.display_name, ''), d.stable_device_id, se.actor) AS actor_name,
		       se.reason_code, se.occurred_at
		FROM spend_events se
		LEFT JOIN devices d ON (
			d.organization_id = se.organization_id 
			AND (d.id::text = se.actor OR d.stable_device_id = se.actor OR d.display_name = se.actor)
		)
		WHERE se.organization_id = $1
		ORDER BY se.occurred_at DESC
		LIMIT $2
	`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []SpendEvent
	for rows.Next() {
		var e SpendEvent
		var usageRaw []byte
		if err := rows.Scan(
			&e.EventID, &e.OrganizationID, &e.ReservationID, &e.RequestID, &e.EventType,
			&e.AmountMicrocents, &e.Currency, &usageRaw, &e.ProviderRequestID, &e.Actor, &e.ActorName, &e.ReasonCode, &e.OccurredAt,
		); err == nil {
			e.UsageJSON = string(usageRaw)
			res = append(res, e)
		}
	}
	return res, rows.Err()
}

// GetSpendAnalytics returns server-aggregated ledger totals, hourly time-series, and top spenders.
func (s *Store) GetSpendAnalytics(ctx context.Context, orgID string, hours int, groupBy string) (*SpendAnalytics, error) {
	if s.pool == nil {
		return &SpendAnalytics{
			Summary:     SpendAnalyticsSummary{},
			TimeSeries:  []SpendTimeSeriesPoint{},
			TopEntities: []SpendTopEntity{},
		}, nil
	}

	if hours <= 0 || hours > 720 {
		hours = 24
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	var a SpendAnalytics
	a.TimeSeries = []SpendTimeSeriesPoint{}
	a.TopEntities = []SpendTopEntity{}

	// 1. High-level Summary
	err := s.pool.QueryRow(ctx, `
		SELECT 
			COALESCE(SUM(reserved_microcents), 0),
			COALESCE(SUM(settled_microcents), 0),
			COALESCE(SUM(CASE WHEN state = 'RELEASED' THEN reserved_microcents - settled_microcents ELSE 0 END), 0),
			COUNT(*),
			COUNT(*) FILTER (WHERE state = 'DENIED'),
			COALESCE(SUM(cached_tokens), 0),
			COALESCE(SUM(input_tokens), 0),
			COALESCE(SUM(output_tokens), 0)
		FROM spend_reservations
		WHERE organization_id = $1 AND created_at >= $2
	`, orgID, since).Scan(
		&a.Summary.TotalReservedMoney,
		&a.Summary.TotalSettledMoney,
		&a.Summary.TotalReleasedMoney,
		&a.Summary.RequestCount,
		&a.Summary.DeniedCount,
		&a.Summary.TotalCachedTokens,
		&a.Summary.TotalInputTokens,
		&a.Summary.TotalOutputTokens,
	)
	if err != nil {
		return nil, fmt.Errorf("spend analytics summary: %w", err)
	}

	// 2. Hourly Time Series
	tsRows, err := s.pool.Query(ctx, `
		SELECT 
			to_char(date_trunc('hour', created_at), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as hr,
			COALESCE(SUM(reserved_microcents), 0),
			COALESCE(SUM(settled_microcents), 0),
			COALESCE(SUM(CASE WHEN state = 'RELEASED' THEN reserved_microcents - settled_microcents ELSE 0 END), 0),
			COUNT(*)
		FROM spend_reservations
		WHERE organization_id = $1 AND created_at >= $2
		GROUP BY date_trunc('hour', created_at)
		ORDER BY date_trunc('hour', created_at) ASC
	`, orgID, since)
	if err == nil {
		defer tsRows.Close()
		for tsRows.Next() {
			var pt SpendTimeSeriesPoint
			if err := tsRows.Scan(&pt.Hour, &pt.ReservedMicrocents, &pt.SettledMicrocents, &pt.ReleasedMicrocents, &pt.RequestCount); err == nil {
				a.TimeSeries = append(a.TimeSeries, pt)
			}
		}
	}

	// 3. Top Entities by Dimension
	if groupBy == "device" {
		query := `
			SELECT 
				COALESCE(sr.gateway_id, 'unknown') AS entity_id,
				COALESCE(NULLIF(d.display_name, ''), d.stable_device_id, sr.gateway_id, 'unknown') AS entity_name,
				COALESCE(SUM(sr.settled_microcents), 0),
				COUNT(*)
			FROM spend_reservations sr
			LEFT JOIN devices d ON (
				d.organization_id = sr.organization_id 
				AND (d.id::text = sr.gateway_id OR d.stable_device_id = sr.gateway_id OR d.display_name = sr.gateway_id)
			)
			WHERE sr.organization_id = $1 AND sr.created_at >= $2
			GROUP BY sr.gateway_id, d.display_name, d.stable_device_id
			ORDER BY SUM(sr.settled_microcents) DESC, COUNT(*) DESC
			LIMIT 20
		`
		topRows, err := s.pool.Query(ctx, query, orgID, since)
		if err == nil {
			defer topRows.Close()
			for topRows.Next() {
				var ent SpendTopEntity
				if err := topRows.Scan(&ent.EntityID, &ent.EntityName, &ent.SettledMicrocents, &ent.RequestCount); err == nil {
					a.TopEntities = append(a.TopEntities, ent)
				}
			}
		}
	} else {
		validGroupBy := map[string]string{
			"provider": "provider",
			"model":    "model",
			"project":  "project_id",
			"user":     "COALESCE(internal_user_id, end_user_id, 'unattributed')",
			"team":     "COALESCE(virtual_key_alias, 'default')",
		}
		col, ok := validGroupBy[groupBy]
		if !ok {
			col = "provider"
		}

		query := fmt.Sprintf(`
			SELECT 
				COALESCE(%s, 'unknown'),
				COALESCE(SUM(settled_microcents), 0),
				COUNT(*)
			FROM spend_reservations
			WHERE organization_id = $1 AND created_at >= $2
			GROUP BY %s
			ORDER BY SUM(settled_microcents) DESC, COUNT(*) DESC
			LIMIT 20
		`, col, col)

		topRows, err := s.pool.Query(ctx, query, orgID, since)
		if err == nil {
			defer topRows.Close()
			for topRows.Next() {
				var ent SpendTopEntity
				if err := topRows.Scan(&ent.EntityID, &ent.SettledMicrocents, &ent.RequestCount); err == nil {
					ent.EntityName = ent.EntityID
					a.TopEntities = append(a.TopEntities, ent)
				}
			}
		}
	}

	return &a, nil
}
