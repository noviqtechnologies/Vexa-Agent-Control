package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
)

type Config struct {
	Port        int
	DatabaseURL string

	// GatewaySecret is a shared HMAC key the gateway includes in the
	// Authorization header when POSTing to the ingest endpoints.
	// Dashboard operators do NOT use this — they use OIDC.
	GatewaySecret string

	// PolicyReadSecret authenticates dashboard-api → gateway requests for
	// self-healing/policy-read endpoints. Separate trust boundary from
	// GatewaySecret (which is gateway → dashboard-api for ingest).
	PolicyReadSecret string

	// GatewayURL is the internal URL of the Agent Control gateway (e.g.
	// http://agentwall-gateway:8080). Used to proxy policy-read requests.
	GatewayURL string

	// ProviderKeyEncryptionSecret is the 32-byte key used to encrypt provider API keys in DB.
	ProviderKeyEncryptionSecret []byte

	// LicenseKey is the Ed25519-signed JWT license key for Agent Control Hub.
	LicenseKey string

	// DevMode disables auth requirements. Requires BOTH DEV_MODE=true AND
	// ALLOW_DEV_MODE=true to activate — prevents accidental copy-paste of
	// dev config into production Helm values.
	DevMode bool
}

func Load() (*Config, error) {
	port := 8400
	if v := os.Getenv("DASHBOARD_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid DASHBOARD_PORT: %w", err)
		}
		port = p
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	devMode := os.Getenv("DEV_MODE") == "true" && os.Getenv("ALLOW_DEV_MODE") == "true"

	gatewaySecret := os.Getenv("GATEWAY_SECRET")
	policyReadSecret := os.Getenv("POLICY_READ_SECRET")
	gatewayURL := os.Getenv("GATEWAY_URL")
	licenseKey := os.Getenv("AGENTCONTROL_HUB_LICENSE_KEY")

	encryptionHex := os.Getenv("PROVIDER_KEY_ENCRYPTION_SECRET")
	var encryptionSecret []byte
	if encryptionHex != "" {
		key, err := crypto.ParseMasterKey(encryptionHex)
		if err != nil {
			return nil, fmt.Errorf("PROVIDER_KEY_ENCRYPTION_SECRET error: %w", err)
		}
		encryptionSecret = key
	} else if devMode {
		// Default 32-byte key for local development when in devMode
		key, _ := crypto.ParseMasterKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		encryptionSecret = key
	} else {
		return nil, fmt.Errorf("PROVIDER_KEY_ENCRYPTION_SECRET is required (set DEV_MODE=true and ALLOW_DEV_MODE=true for dev fallback)")
	}

	if !devMode {
		if gatewaySecret == "" {
			return nil, fmt.Errorf("GATEWAY_SECRET is required (set DEV_MODE=true and ALLOW_DEV_MODE=true to disable auth for local development)")
		}
	}

	return &Config{
		Port:                        port,
		DatabaseURL:                 dbURL,
		GatewaySecret:               gatewaySecret,
		PolicyReadSecret:            policyReadSecret,
		GatewayURL:                  gatewayURL,
		ProviderKeyEncryptionSecret: encryptionSecret,
		LicenseKey:                  licenseKey,
		DevMode:                     devMode,
	}, nil
}

