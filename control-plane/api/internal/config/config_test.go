package config

import (
	"os"
	"testing"
)

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func clearDashboardEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"DATABASE_URL", "PORT", "DASHBOARD_PORT", "GATEWAY_SECRET",
		"OIDC_ISSUER", "OIDC_CLIENT_ID", "DEV_MODE", "ALLOW_DEV_MODE",
		"POLICY_READ_SECRET", "GATEWAY_URL", "PROVIDER_KEY_ENCRYPTION_SECRET", "AGENTCONTROL_HUB_LICENSE_KEY",
		"INGRESS_AUTH_SECRET", "VPC_INGRESS_AUTH_SECRET", "DIRECT_TLS_ENABLED",
	} {
		os.Unsetenv(k)
	}
}

func productionEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":                   "postgres://localhost:5432/test",
		"GATEWAY_SECRET":                 "prod_gateway_secret_very_secure_67890",
		"OIDC_ISSUER":                    "https://accounts.example.com",
		"OIDC_CLIENT_ID":                "dashboard-client",
		"PROVIDER_KEY_ENCRYPTION_SECRET": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
		"INGRESS_AUTH_SECRET":           "prod_ingress_secret_auth_token_12345",
	}
}

func TestLoad_Production_AllRequired(t *testing.T) {
	clearDashboardEnv(t)
	setEnv(t, productionEnv())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 8400 {
		t.Errorf("Port = %d, want 8400", cfg.Port)
	}
	if cfg.DevMode {
		t.Error("DevMode should be false in production")
	}
	if cfg.GatewaySecret != "prod_gateway_secret_very_secure_67890" {
		t.Errorf("GatewaySecret = %q, want %q", cfg.GatewaySecret, "prod_gateway_secret_very_secure_67890")
	}
}

func TestLoad_RejectsKnownPlaceholdersInProduction(t *testing.T) {
	clearDashboardEnv(t)
	env := productionEnv()
	env["PROVIDER_KEY_ENCRYPTION_SECRET"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	setEnv(t, env)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when placeholder master key is used in production mode")
	}
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	clearDashboardEnv(t)
	setEnv(t, map[string]string{
		"GATEWAY_SECRET": "prod_gateway_secret_very_secure_67890",
		"OIDC_ISSUER":    "https://accounts.example.com",
		"OIDC_CLIENT_ID": "dashboard-client",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing DATABASE_URL")
	}
}

func TestLoad_MissingGatewaySecret_NonDevMode(t *testing.T) {
	clearDashboardEnv(t)
	setEnv(t, map[string]string{
		"DATABASE_URL":   "postgres://localhost:5432/test",
		"OIDC_ISSUER":    "https://accounts.example.com",
		"OIDC_CLIENT_ID": "dashboard-client",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing GATEWAY_SECRET in production mode")
	}
}

func TestLoad_MissingOIDC_NonDevMode(t *testing.T) {
	clearDashboardEnv(t)
	setEnv(t, map[string]string{
		"DATABASE_URL":                   "postgres://localhost:5432/test",
		"GATEWAY_SECRET":                 "prod_gateway_secret_very_secure_67890",
		"PROVIDER_KEY_ENCRYPTION_SECRET": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
		"INGRESS_AUTH_SECRET":           "prod_ingress_secret_auth_token_12345",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error when OIDC env vars omitted: %v", err)
	}
	if cfg.GatewaySecret != "prod_gateway_secret_very_secure_67890" {
		t.Errorf("GatewaySecret = %q, want %q", cfg.GatewaySecret, "prod_gateway_secret_very_secure_67890")
	}
}

func TestLoad_DevMode_RequiresBothFlags(t *testing.T) {
	clearDashboardEnv(t)

	tests := []struct {
		name    string
		devMode string
		allow   string
		wantDev bool
		wantErr bool
	}{
		{"both_true", "true", "true", true, false},
		{"only_dev_mode", "true", "", false, true},
		{"only_allow", "", "true", false, true},
		{"neither", "", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearDashboardEnv(t)
			env := map[string]string{"DATABASE_URL": "postgres://localhost:5432/test"}
			if tt.devMode != "" {
				env["DEV_MODE"] = tt.devMode
			}
			if tt.allow != "" {
				env["ALLOW_DEV_MODE"] = tt.allow
			}
			setEnv(t, env)

			cfg, err := Load()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.DevMode != tt.wantDev {
				t.Errorf("DevMode = %v, want %v", cfg.DevMode, tt.wantDev)
			}
		})
	}
}

func TestLoad_CustomPort(t *testing.T) {
	clearDashboardEnv(t)
	env := productionEnv()
	env["DASHBOARD_PORT"] = "9000"
	setEnv(t, env)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 9000 {
		t.Errorf("Port = %d, want 9000", cfg.Port)
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	clearDashboardEnv(t)
	env := productionEnv()
	env["DASHBOARD_PORT"] = "not-a-number"
	setEnv(t, env)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}
