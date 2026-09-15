package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
)

var knownInsecurePlaceholders = []string{
	"vexa_secure_password",
	"vexa_team_gateway_secret_key_12345",
	"local-dev-policy-read-secret-change-me",
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	"vexa_team_session_signing_secret_67890",
	"VexaAdminPassword2026!",
	"admin123!",
	"admin12345678",
	"admin",
	"password",
	"secret",
	"changeme",
	"change-me",
}

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

	// IngressAuthSecret is the shared secret verified against X-VPC-Ingress-Auth
	// when operating behind a managed ingress / load balancer (e.g. GCP ALB mTLS).
	IngressAuthSecret string

	// SessionSecret is the cookie-signing secret for dashboard sessions.
	SessionSecret string

	// AdminPassword is the optional platform administrator initial password.
	AdminPassword string

	// AdminEmail is the dedicated Control Hub administrator email.
	AdminEmail string

	// AdminPassword is the dedicated Control Hub administrator password.
	// OrganizationName is the customer organization display name.
	OrganizationName string

	// OrganizationID is the primary organization UUID (default: 00000000-0000-0000-0000-000000000001).
	OrganizationID string

	// Legacy backward compatibility fields
	SaaSOperatorEmail       string
	SaaSOperatorPassword    string
	TenantAdminEmail        string
	TenantAdminPassword     string
	TenantAdminOrgName      string
	ControlHubAdminEmail    string
	ControlHubAdminPassword string

	// LicenseKey is the Ed25519-signed JWT license key for Agent Control Hub.
	LicenseKey string

	// LegacySingleTenantMode enables single-tenant legacy compatibility with GATEWAY_SECRET.
	LegacySingleTenantMode bool
	LegacyTenantID         string

	// DevMode disables auth requirements. Requires BOTH DEV_MODE=true AND
	// ALLOW_DEV_MODE=true to activate — prevents accidental copy-paste of
	// dev config into production Helm values.
	DevMode bool
}

func isPlaceholder(val string) bool {
	clean := strings.TrimSpace(strings.ToLower(val))
	for _, placeholder := range knownInsecurePlaceholders {
		if clean == strings.ToLower(placeholder) {
			return true
		}
	}
	return false
}

func Load() (*Config, error) {
	port := 8400
	if v := os.Getenv("PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("invalid PORT: %w", err)
		}
		port = p
	} else if v := os.Getenv("DASHBOARD_PORT"); v != "" {
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
	ingressAuthSecret := os.Getenv("INGRESS_AUTH_SECRET")
	if ingressAuthSecret == "" {
		ingressAuthSecret = os.Getenv("VPC_INGRESS_AUTH_SECRET")
	}
	sessionSecret := os.Getenv("AGENTCONTROL_SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = os.Getenv("AGENTWALL_SESSION_SECRET")
	}
	// Canonical Single-Tenant Administration Configuration
	adminEmail := strings.TrimSpace(os.Getenv("ADMIN_EMAIL"))
	if adminEmail == "" {
		adminEmail = strings.TrimSpace(os.Getenv("TENANT_ADMIN_EMAIL"))
	}
	if adminEmail == "" {
		adminEmail = strings.TrimSpace(os.Getenv("CONTROL_HUB_ADMIN_EMAIL"))
	}

	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = os.Getenv("TENANT_ADMIN_PASSWORD")
	}
	if adminPassword == "" {
		adminPassword = os.Getenv("CONTROL_HUB_ADMIN_PASSWORD")
	}
	if adminPassword == "" && devMode {
		adminPassword = "admin12345678"
	}

	orgName := os.Getenv("ORGANIZATION_NAME")
	if orgName == "" {
		orgName = os.Getenv("TENANT_ADMIN_ORG_NAME")
	}
	if orgName == "" {
		orgName = "Primary Organization"
	}

	orgID := strings.TrimSpace(os.Getenv("ORGANIZATION_ID"))
	if orgID == "" {
		orgID = strings.TrimSpace(os.Getenv("LEGACY_TENANT_ID"))
	}
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}

	// Legacy backward compatibility values
	tenantAdminEmail := adminEmail
	tenantAdminPassword := adminPassword
	tenantAdminOrgName := orgName
	controlHubAdminEmail := adminEmail
	controlHubAdminPassword := adminPassword

	legacySingleTenant := os.Getenv("LEGACY_SINGLE_TENANT_MODE") == "true"
	legacyTenantID := strings.TrimSpace(os.Getenv("LEGACY_TENANT_ID"))
	if legacySingleTenant && legacyTenantID == "" {
		if devMode {
			legacyTenantID = "00000000-0000-0000-0000-000000000001"
		} else {
			return nil, fmt.Errorf("LEGACY_TENANT_ID is required when LEGACY_SINGLE_TENANT_MODE=true in production")
		}
	}

	encryptionHex := os.Getenv("PROVIDER_KEY_ENCRYPTION_SECRET")
	var encryptionSecret []byte
	if encryptionHex != "" {
		if !devMode && isPlaceholder(encryptionHex) {
			return nil, fmt.Errorf("PROVIDER_KEY_ENCRYPTION_SECRET uses a known insecure placeholder; provide a cryptographically random 32-byte hex key")
		}
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
		if isPlaceholder(gatewaySecret) || len(gatewaySecret) < 16 {
			return nil, fmt.Errorf("GATEWAY_SECRET must not use a known placeholder and must be at least 16 characters in production")
		}

		if sessionSecret != "" && (isPlaceholder(sessionSecret) || len(sessionSecret) < 16) {
			return nil, fmt.Errorf("AGENTCONTROL_SESSION_SECRET must not use a known placeholder and must be at least 16 characters in production")
		}

		if policyReadSecret != "" && isPlaceholder(policyReadSecret) {
			return nil, fmt.Errorf("POLICY_READ_SECRET must not use a known placeholder in production")
		}

		if strings.EqualFold(adminEmail, "admin") || strings.EqualFold(adminEmail, "admin@agentcontrol.local") {
			return nil, fmt.Errorf("ADMIN_EMAIL must not use default email 'admin' or 'admin@agentcontrol.local' in production")
		}

		if (tenantAdminPassword != "" || adminPassword != "") && adminEmail == "" {
			return nil, fmt.Errorf("ADMIN_EMAIL is required when ADMIN_PASSWORD is configured in production")
		}

		if tenantAdminPassword != "" && isPlaceholder(tenantAdminPassword) {
			return nil, fmt.Errorf("TENANT_ADMIN_PASSWORD / ADMIN_PASSWORD must not use a known default password in production")
		}

		if controlHubAdminPassword != "" && isPlaceholder(controlHubAdminPassword) {
			return nil, fmt.Errorf("CONTROL_HUB_ADMIN_PASSWORD / SAAS_OPERATOR_PASSWORD must not use a known default password in production")
		}

		if ingressAuthSecret == "" && os.Getenv("DIRECT_TLS_ENABLED") != "true" {
			return nil, fmt.Errorf("INGRESS_AUTH_SECRET is required in production when running behind an HTTP ingress boundary (set DIRECT_TLS_ENABLED=true or provide a secure secret)")
		}

		if ingressAuthSecret != "" && (isPlaceholder(ingressAuthSecret) || len(ingressAuthSecret) < 16) {
			return nil, fmt.Errorf("INGRESS_AUTH_SECRET must not use a known placeholder and must be at least 16 characters in production")
		}

		if strings.Contains(dbURL, "vexa_secure_password") {
			return nil, fmt.Errorf("DATABASE_URL contains known default password 'vexa_secure_password'; please configure a secure database password")
		}
	}

	return &Config{
		Port:                        port,
		DatabaseURL:                 dbURL,
		GatewaySecret:               gatewaySecret,
		PolicyReadSecret:            policyReadSecret,
		GatewayURL:                  gatewayURL,
		ProviderKeyEncryptionSecret: encryptionSecret,
		IngressAuthSecret:           ingressAuthSecret,
		SessionSecret:               sessionSecret,
		AdminEmail:                  adminEmail,
		AdminPassword:               adminPassword,
		OrganizationName:            orgName,
		OrganizationID:              orgID,
		SaaSOperatorEmail:           controlHubAdminEmail,
		SaaSOperatorPassword:        controlHubAdminPassword,
		TenantAdminEmail:            tenantAdminEmail,
		TenantAdminPassword:         tenantAdminPassword,
		TenantAdminOrgName:          tenantAdminOrgName,
		ControlHubAdminEmail:        controlHubAdminEmail,
		ControlHubAdminPassword:     controlHubAdminPassword,
		LicenseKey:                  licenseKey,
		LegacySingleTenantMode:      legacySingleTenant,
		LegacyTenantID:              legacyTenantID,
		DevMode:                     devMode,
	}, nil
}


