package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/broker"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/config"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/crypto"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/device"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/handler"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if cfg.DevMode {
		log.Println("WARNING: running in DEV_MODE — all auth is disabled. DO NOT deploy to production.")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	if err := db.EnsureOrganizationsSchema(ctx); err != nil {
		log.Printf("[organizations] schema verification warning: %v", err)
	}
	if err := db.EnsureUsersSchema(ctx); err != nil {
		log.Printf("[users] schema verification warning: %v", err)
	}
	if err := db.EnsureAuthProvidersSchema(ctx); err != nil {
		log.Printf("[auth_providers] schema verification warning: %v", err)
	}
	if err := db.EnsureCoreSchema(ctx); err != nil {
		log.Printf("[core] schema verification warning: %v", err)
	}
	if err := db.EnsurePoliciesSchema(ctx); err != nil {
		log.Printf("[policies] schema verification warning: %v", err)
	}
	if err := db.EnsureGroupPoliciesSchema(ctx); err != nil {
		log.Printf("[group_policies] schema verification warning: %v", err)
	}
	if err := db.EnsureTemplatesTable(ctx); err != nil {
		log.Printf("[templates] schema verification warning: %v", err)
	}
	if err := db.EnsureProviderKeysSchema(ctx); err != nil {
		log.Printf("[provider_keys] schema verification warning: %v", err)
	}
	if err := db.EnsureDevicesSchema(ctx); err != nil {
		log.Printf("[devices] schema verification warning: %v", err)
	}
	if err := db.EnsureEnrollmentV2Schema(ctx); err != nil {
		log.Printf("[enrollment_v2] schema verification warning: %v", err)
	}
	if err := db.EnsureIdempotencySchema(ctx); err != nil {
		log.Printf("[idempotency] schema verification warning: %v", err)
	}
	if err := db.EnsureSpendV1Schema(ctx); err != nil {
		log.Printf("[spend_v1] schema verification warning: %v", err)
	}

	// Initialize Spend v2 Store and Sweeper
	spendStore := spend.NewStore(db.Pool())
	if err := spendStore.EnsureSchema(ctx); err != nil {
		log.Printf("[spend] schema initialization warning: %v", err)
	}
	spendSweeper := spend.NewSweeper(spendStore, 30*time.Second)
	spendSweeper.Start(ctx)
	defer spendSweeper.Stop()
	spendV2H := handler.NewSpendV2Handler(spendStore)

	// Initialize Device Governance Store & Handler
	deviceStore := device.NewStore(db.Pool())
	if err := deviceStore.EnsureSchema(ctx); err != nil {
		log.Printf("[device] schema initialization warning: %v", err)
	}
	deviceH := handler.NewDeviceHandler(deviceStore)

	sseBroker := sse.NewBroker()

	// Initialize Automated License Issuer (GCP Secret Manager / Env)
	licenseIssuer, err := license.NewIssuerFromEnv()
	if err != nil {
		log.Printf("[license] issuer initialization warning: %v", err)
	} else if licenseIssuer != nil {
		log.Printf("[license] automated license issuer initialized with Ed25519 signing key")
	}

	var activeClaims *license.Claims
	if cfg.LicenseKey != "" {
		v, err := license.NewValidatorFromEnv()
		if err == nil {
			c, err := v.Validate(cfg.LicenseKey)
			if err == nil {
				activeClaims = c
				log.Printf("license verified: org=%s tier=%s seats=%d", c.OrgID, c.Tier, c.MaxSeats)
			} else {
				log.Printf("WARNING: license validation failed (%v), falling back to Community mode (10 seats)", err)
				activeClaims = license.CommunityClaims()
			}
		} else {
			activeClaims = license.CommunityClaims()
		}
	} else {
		log.Println("no AGENTCONTROL_HUB_LICENSE_KEY provided, running in Community mode (10 seats)")
		activeClaims = license.CommunityClaims()
	}

	licenseH := handler.NewLicenseHandler(db, activeClaims)
	ingestH := handler.NewIngestHandler(db, sseBroker, activeClaims)
	fleetH := handler.NewFleetHandler(db)
	identityH := handler.NewIdentityHandler(db)
	mcpServersH := handler.NewMcpServersHandler(db)
	alertH := handler.NewAlertHandler(db, sseBroker)
	threatH := handler.NewThreatHandler(db)
	policyH := handler.NewPolicyHandler(cfg.GatewayURL, cfg.PolicyReadSecret)
	rotationH := handler.NewRotationHandler(cfg.GatewayURL, cfg.PolicyReadSecret)

	authH := handler.NewAuthHandler(db, cfg)
	authProviderH := handler.NewAuthProviderHandler(db)
	userH := handler.NewUserHandler(db)
	policyMgmtH := handler.NewPolicyMgmtHandler(db, sseBroker)
	templateH := handler.NewTemplateHandler(db)
	safeModeH := handler.NewSafeModeHandler()
	spendH := handler.NewSpendHandler(db)
	saasOpH := handler.NewSaaSOperatorHandler(db, licenseIssuer)

	authH.CheckBootstrap()

	groupPolicyH := handler.NewGroupPolicyHandler(db)
	gatewayH := handler.NewGatewayHandler()
	providerKeysH := handler.NewProviderKeysHandler(db, cfg.ProviderKeyEncryptionSecret)
	hubSpecH := handler.NewHubSpecHandler(db, sseBroker, cfg.ProviderKeyEncryptionSecret)

	enrollmentH := handler.NewEnrollmentHandler(db, cfg.GatewaySecret)
	heartbeatH := handler.NewHeartbeatHandler(db)
	deviceAdminH := handler.NewDeviceAdminHandler(db)

	// Target Contract v4.0 (v2 API Handlers)
	softwareCAS, err := crypto.NewSoftwareCASIssuer()
	if err != nil {
		log.Fatalf("failed to initialize CAS issuer: %v", err)
	}
	enrollmentV2H := handler.NewEnrollmentV2Handler(db, softwareCAS)
	adminV2H := handler.NewAdminV2Handler(db)
	deviceV2H := handler.NewDeviceV2Handler(db)
	genericProviderClient := broker.NewGenericProviderClient()
	brokerV2H := handler.NewBrokerV2Handler(db, genericProviderClient, cfg.ProviderKeyEncryptionSecret)

	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(middleware.LegacyQuarantineGate())

	// Health check — no auth.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// === Target Contract v4.0 API Routes ===
	// 1. Enrollment Handlers (Unauthenticated - OTET & Key Proof)
	r.Route("/api/v2/enrollment", func(r chi.Router) {
		r.Post("/start", enrollmentV2H.StartEnrollment)
		r.Post("/complete", enrollmentV2H.CompleteEnrollment)
	})

	// 2. Admin Console v2 Handlers
	r.Route("/api/v2/admin", func(r chi.Router) {
		r.Use(middleware.DashboardAuth())
		r.Use(middleware.RequireAdmin())
		r.Post("/enrollment-tokens", adminV2H.CreateEnrollmentToken)
		r.Post("/devices/{device_id}/revoke", adminV2H.RevokeDevice)
		r.Post("/devices/{id}/revoke", adminV2H.RevokeDevice)
	})

	// 3. Strict Device Control API (Edge mTLS Header Validation)
	r.Route("/api/v2/device", func(r chi.Router) {
		r.Use(middleware.StrictDeviceMTLS(db, cfg.IngressAuthSecret))
		r.Get("/bootstrap", deviceV2H.GetBootstrap)
		r.Post("/heartbeats", deviceV2H.SubmitHeartbeat)
		r.Get("/status", deviceV2H.GetDeviceStatus)
	})

	// 4. Provider LLM Broker (Edge mTLS Header Validation & Capability Gates)
	r.Route("/api/v2/broker", func(r chi.Router) {
		r.Use(middleware.StrictDeviceMTLS(db, cfg.IngressAuthSecret))
		r.Use(middleware.RequireTenantFeature(db, "group_policies"))
		r.Post("/llm-requests", brokerV2H.HandleLLMRequest)
	})

	// 5. Authoritative Central Spend Ledger API v2
	r.Route("/api/v2/spend", func(r chi.Router) {
		r.Use(middleware.RequireTenantFeature(db, "spend_caps"))
		
		// Workload / Gateway spend reservation lifecycle routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.GatewayAuth(cfg.GatewaySecret, db))
			r.Post("/authorize", spendV2H.Authorize)
			r.Post("/reservations/{reservation_id}/settle", spendV2H.Settle)
			r.Post("/reservations/{reservation_id}/release", spendV2H.Release)
		})

		// Operator / Dashboard spend policy management & reporting routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.DashboardAuth())
			r.Get("/effective", spendV2H.GetEffective)
			r.Get("/events", spendV2H.ListEvents)
			r.Get("/policies", spendV2H.ListPolicies)
			r.Post("/policies", spendV2H.CreatePolicy)
			r.Post("/policies/{id}/publish", spendV2H.PublishPolicy)
			r.Get("/increase-requests", spendV2H.ListIncreaseRequests)
			r.Post("/increase-requests", spendV2H.CreateIncreaseRequest)
			r.Post("/increase-requests/{id}/decide", spendV2H.DecideIncreaseRequest)
		})
	})

	// 6. Device Governance & Sentry Compliance API
	r.Post("/api/v1/devices/enroll", deviceH.EnrollDevice)
	r.With(middleware.GatewayAuth(cfg.GatewaySecret, db)).Post("/api/v1/devices/{id}/telemetry", deviceH.RecordTelemetry)

	// Public PKI Enrollment route (Unauthenticated)
	r.Post("/api/v1/enroll", enrollmentH.PostEnroll)

	// Gateway API Spec endpoints (Gateway / Read Secret Auth)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Get("/api/v1/bootstrap", hubSpecH.GetBootstrap)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Get("/api/v1/events", hubSpecH.GetEventsStream)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Get("/api/v1/policies/{id}", hubSpecH.GetPolicyByID)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Get("/api/v1/credentials/{provider}", hubSpecH.GetProviderCredential)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Post("/api/v1/credentials/rotate", hubSpecH.RotateCredential)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Get("/api/v1/policies/active", policyMgmtH.GetActive)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Get("/api/v1/policy/active", policyMgmtH.GetActive)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret)).Get("/api/v1/policy/subscribe", policyMgmtH.Subscribe)
	r.With(middleware.GatewayAuth(cfg.GatewaySecret, db)).Post("/api/v1/telemetry", hubSpecH.PostTelemetry)

	// Ingest endpoints — gateway auth (shared secret / enrolled device ID), NOT OIDC.
	r.Route("/api/v1/ingest", func(r chi.Router) {
		r.Use(middleware.GatewayAuth(cfg.GatewaySecret, db))
		r.Post("/events", ingestH.PostEvent)
		r.Post("/alerts", ingestH.PostAlert)
		r.Post("/credentials", ingestH.PostCredential)
		r.Post("/mcp-servers", ingestH.PostMcpServers)
		r.Post("/spend-snapshots", spendH.SyncSnapshot)
		r.Post("/heartbeat", heartbeatH.PostHeartbeat)
		r.Post("/tamper-log", deviceAdminH.PostTamperLog)
	})

	// Auth Routes
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", authH.Login)
		r.Post("/logout", authH.Logout)
		r.Get("/providers", authH.ListPublicProviders)
		r.Get("/oauth/{provider_id}/login", authH.OAuthLogin)
		r.Get("/oauth/{provider_id}/callback", authH.OAuthCallback)
		r.With(middleware.DashboardAuth()).Get("/me", authH.Me)
		r.With(middleware.DashboardAuth()).Post("/setup-initial-password", authH.SetupInitialPassword)
	})

	// Dashboard API — session cookie auth for human operators & admins.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.DashboardAuth())

		// SaaS Operator Admin Routes (Platform Super-Admin only)
		r.Route("/operator", func(r chi.Router) {
			r.Use(middleware.RequireSaaSOperator())
			r.Post("/organizations", saasOpH.CreateOrganization)
			r.Get("/organizations", saasOpH.ListOrganizations)
			r.Get("/organizations/{id}", saasOpH.GetOrganization)
			r.Put("/organizations/{id}", saasOpH.UpdateOrganization)
			r.Post("/organizations/{id}/status", saasOpH.UpdateStatus)
			r.Post("/organizations/{id}/renew-license", saasOpH.RenewLicense)
			r.Post("/organizations/{id}/regenerate-bootstrap", saasOpH.RegenerateBootstrapToken)
			r.Get("/stats", saasOpH.GetStats)
		})

		r.Get("/license/status", licenseH.GetStatus)
		r.Get("/gateways", hubSpecH.ListGateways)
		r.Get("/fleet/overview", fleetH.GetOverview)
		r.Get("/fleet/agents", fleetH.ListAgents)
		r.Get("/fleet/heatmap", fleetH.GetHeatmap)
		r.Get("/fleet/events", fleetH.ListEvents)
		r.Get("/fleet/agents/{agentID}/events", fleetH.ListEvents)

		// Sentry Device Governance & Tamper Log
		r.Get("/devices", deviceH.ListDevices)
		r.Get("/devices/tamper-log", deviceH.ListTamperEvents)
		r.Get("/devices/{id}", deviceH.GetDevice)

		// Admin-only fleet routes
		r.Route("/fleet/mcp-servers", func(r chi.Router) {
			r.Use(middleware.RequireAdmin())
			r.Get("/", mcpServersH.ListFleetWide)
			r.Get("/{agentID}", mcpServersH.ListByAgent)
		})

		r.Get("/identity/credentials", identityH.ListCredentials)

		r.Get("/alerts/recent", alertH.ListRecent)
		r.Get("/alerts/stream", alertH.Stream)

		r.Get("/threats/summary", threatH.GetSummary)
		r.Get("/threats/timeline", threatH.GetTimeline)
		r.Get("/threats/top-patterns", threatH.GetTopPatterns)

		r.Get("/policy/status", policyH.GetStatus)
		r.Post("/policy/suggestions", policyH.GetSuggestions)

		r.Post("/identity/rotate", rotationH.TriggerRotation)
		
		// Auth Providers
		r.Get("/auth_providers", authProviderH.List)
		r.Get("/auth_providers/{id}", authProviderH.Get)
		r.With(middleware.RequireAdmin()).Put("/auth_providers", authProviderH.Upsert)
		
		// Users
		r.Get("/users", userH.List)
		r.With(middleware.RequireAdmin()).Post("/users", userH.Create)
		r.Post("/users/{id}/password", userH.UpdatePassword)
		r.Put("/users/{id}/password", userH.UpdatePassword)
		r.With(middleware.RequireAdmin()).Delete("/users/{id}", userH.Delete)
		
		// Policy Management (Operator Auth)
		r.Get("/policies", policyMgmtH.List)
		r.Get("/policies/active", policyMgmtH.GetActive)
		r.Get("/policy/active", policyMgmtH.GetActive)
		r.Get("/policies/{id}", hubSpecH.GetPolicyByID)
		r.With(middleware.RequireAdmin()).Post("/policies", hubSpecH.CreatePolicy)
		r.Get("/policies/templates", templateH.ListTemplates)
		r.Get("/policies/templates/{id}", templateH.GetTemplate)
		r.With(middleware.RequireAdmin()).Post("/policies/templates", templateH.CreateCustomTemplate)
		r.With(middleware.RequireAdmin()).Delete("/policies/templates/{id}", templateH.DeleteCustomTemplate)

		// Gateway Management (Phase 1 Mock)
		r.Post("/gateways/register", gatewayH.Register)

		// Provider API Keys Management
		r.Route("/providers/keys", func(r chi.Router) {
			r.Use(middleware.RequireAdmin())
			r.Get("/", providerKeysH.List)
			r.Post("/", providerKeysH.Save)
			r.Delete("/{id}", providerKeysH.Delete)
		})

		// Group Policy Management
		r.Route("/group-policies", func(r chi.Router) {
			r.Use(middleware.RequireTenantFeature(db, "group_policies"))
			r.Get("/", groupPolicyH.ListGroupPolicies)
			r.Get("/{groupID}", groupPolicyH.GetGroupPolicy)
			r.With(middleware.RequireAdmin()).Post("/", groupPolicyH.PublishGroupPolicy)
		})

		// Safe Mode status (always active — static endpoint)
		r.Get("/policy/safe-mode/status", safeModeH.GetStatus)

		// Spend Caps (Admin + Gateway API)
		r.Route("/spend", func(r chi.Router) {
			r.Use(middleware.RequireTenantFeature(db, "spend_caps"))
			r.Get("/budgets", spendH.ListBudgets)
			r.With(middleware.RequireAdmin()).Post("/budgets", spendH.CreateBudget)
			r.Get("/snapshots", spendH.ListSnapshots)
			r.Get("/requests", spendH.ListIncreaseRequests)
			r.Post("/requests", spendH.SubmitIncreaseRequest)
			r.With(middleware.RequireAdmin()).Post("/requests/{id}/resolve", spendH.ResolveIncreaseRequest)
		})

		// Central Device Governance (Admin)
		r.Route("/admin/devices", func(r chi.Router) {
			r.Use(middleware.RequireAdmin())
			r.Get("/", deviceAdminH.ListDevices)
			r.Post("/{id}/revoke", deviceAdminH.RevokeDevice)
		})
		r.With(middleware.RequireAdmin()).Post("/admin/enrollment-tokens", enrollmentH.PostCreateToken)
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // SSE streams need unbounded writes
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("dashboard-api listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
}
