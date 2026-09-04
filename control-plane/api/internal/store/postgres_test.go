package store_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseCloudSqlURL(t *testing.T) {
	connStr := "postgres://agentwall:secret123@/agentcontrol?host=/cloudsql/vexa-prod:europe-west1:agentcontrol-stage-pg-0r8oiy"
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		t.Fatalf("failed to parse Cloud SQL connection string: %v", err)
	}

	if cfg.ConnConfig.Database != "agentcontrol" {
		t.Errorf("expected database 'agentcontrol', got '%s'", cfg.ConnConfig.Database)
	}
	if cfg.ConnConfig.User != "agentwall" {
		t.Errorf("expected user 'agentwall', got '%s'", cfg.ConnConfig.User)
	}
	if cfg.ConnConfig.Host != "/cloudsql/vexa-prod:europe-west1:agentcontrol-stage-pg-0r8oiy" {
		t.Errorf("expected unix socket host, got '%s'", cfg.ConnConfig.Host)
	}
}
