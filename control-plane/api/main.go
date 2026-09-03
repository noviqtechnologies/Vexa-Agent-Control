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
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/kms"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/license"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/spend"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if cfg.DevMode {
		log.Println("WARNING: running in DEV_MODE.")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 1. Initialize router and start listening immediately
	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(middleware.LegacyQuarantineGate())

	// Health check — responds immediately
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
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
		log.Printf("dashboard-api listening on %s (Single-Tenant Open-Core Engine)", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	// 2. Connect to database with retry loop for sidecar boot
	var pool *pgxpool.Pool
	for attempt := 1; attempt <= 30; attempt++ {
		pool, err = pgxpool.New(ctx, cfg.DatabaseURL)
		if err == nil {
			if pingErr := pool.Ping(ctx); pingErr == nil {
				log.Printf("successfully connected to PostgreSQL on attempt %d", attempt)
				break
			} else {
				err = pingErr
				pool.Close()
			}
		}
		log.Printf("waiting for database to become ready (attempt %d/30): %v", attempt, err)
		select {
		case <-ctx.Done():
			log.Fatalf("context cancelled while waiting for database: %v", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	if err != nil {
		log.Fatalf("database connection error after 30 attempts: %v", err)
	}
	defer pool.Close()

	db := store.New(pool)
	if err := db.EnsureAllSchemas(ctx); err != nil {
		log.Printf("schema initialization warning: %v", err)
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

	// Load license claims (or Developer defaults)
	var activeClaims *license.Claims
	if cfg.LicenseKey != "" {
		v, err := license.NewValidatorFromEnv()
		if err == nil {
			c, err := v.Validate(cfg.LicenseKey)
			if err == nil {
				activeClaims = c
				log.Printf("License active: org=%s tier=%s max_devices=%d", c.OrgID, c.Tier, c.MaxDevices)
			} else {
				log.Printf("WARNING: license validation failed (%v), running in Developer tier (1 device)", err)
				activeClaims = license.DeveloperClaims()
			}
		} else {
			activeClaims = license.DeveloperClaims()
		}
	} else {
		log.Println("Running with default Developer license (1 device)")
		activeClaims = license.DeveloperClaims()
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

	groupPolicyH := handler.NewGroupPolicyHandler(db)
	gatewayH := handler.NewGatewayHandler()
	providerKeysH := handler.NewProviderKeysHandler(db, cfg.ProviderKeyEncryptionSecret)
	hubSpecH := handler.NewHubSpecHandler(db, sseBroker, cfg.ProviderKeyEncryptionSecret)

	enrollmentH := handler.NewEnrollmentHandler(db, cfg.GatewaySecret)
	heartbeatH := handler.NewHeartbeatHandler(db)
	deviceAdminH := handler.NewDeviceAdminHandler(db)

	softwareCAS, err := crypto.NewSoftwareCASIssuer()
	if err != nil {
		log.Fatalf("failed to initialize CAS issuer: %v", err)
	}
	enrollmentV2H := handler.NewEnrollmentV2Handler(db, softwareCAS)
	adminV2H := handler.NewAdminV2Handler(db)
	deviceV2H := handler.NewDeviceV2Handler(db)
	genericProviderClient := broker.NewGenericProviderClient()
	brokerV2H := handler.NewBrokerV2Handler(db, genericProviderClient, cfg.ProviderKeyEncryptionSecret, spendStore)

	// KMS provider and Virtual Key infrastructure
	kmsProvider, err := kms.NewLocalMasterKeyProvider()
	if err != nil {
		log.Fatalf("kms: %v", err)
	}
	invalidationBroadcaster := handler.NewInvalidationBroadcaster()
	virtualKeyH := handler.NewVirtualKeyHandler(db, invalidationBroadcaster)
	brokerV3H := handler.NewBrokerV3Handler(db, kmsProvider, spendStore, genericProviderClient)
	runH := handler.NewRunHandler(spendStore, db, deviceStore)
	observabilityH := handler.NewObservabilityHandler(spendStore, db)
	effectivePolicyH := handler.NewEffectivePolicyHandler(spendStore, db, deviceStore)
	sessionH := handler.NewSessionHandler(spendStore, db)
	coverageHealthH := handler.NewCoverageHealthHandler(deviceStore)
	healthH := handler.NewHealthHandler(db)

	legacyAuthCfg := middleware.LegacyAuthConfig{
		LegacySingleTenantMode: true,
		LegacyTenantID:         middleware.DefaultOrganizationID,
	}

	// 1. Enrollment Handlers
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

	// 3. Strict Device Control API
	r.Route("/api/v2/device", func(r chi.Router) {
		r.Use(middleware.StrictDeviceMTLS(db, cfg.IngressAuthSecret))
		r.Get("/bootstrap", deviceV2H.GetBootstrap)
		r.Post("/heartbeats", deviceV2H.SubmitHeartbeat)
		r.Get("/status", deviceV2H.GetDeviceStatus)
		r.Get("/policy/active", policyMgmtH.GetActive)
		r.Get("/policy/subscribe", policyMgmtH.Subscribe)
	})

	// 4. Provider LLM Broker v2 & v3
	r.Route("/api/v2/broker", func(r chi.Router) {
		r.Use(middleware.StrictDeviceMTLS(db, cfg.IngressAuthSecret))
		r.Use(middleware.RequireOrganizationFeature(db, "group_policies"))
		r.Post("/llm-requests", brokerV2H.HandleLLMRequest)
	})

	r.Route("/api/v3/broker", func(r chi.Router) {
		r.Use(middleware.StrictDeviceMTLS(db, cfg.IngressAuthSecret))
		r.Use(middleware.RequireOrganizationFeature(db, "group_policies"))
		r.Post("/llm-requests", brokerV2H.HandleLLMRequest)
		r.Post("/llm-stream", brokerV2H.HandleLLMStream)
	})

	r.Post("/api/v3/broker/dispatch", brokerV3H.Dispatch)

	// Virtual Key management
	r.Route("/api/v1/virtual-keys", func(r chi.Router) {
		r.Use(middleware.DashboardAuth())
		r.Post("/", virtualKeyH.Create)
		r.Get("/", virtualKeyH.List)
		r.Get("/deleted", virtualKeyH.ListDeleted)
		r.Delete("/{id}", virtualKeyH.Delete)
		r.Post("/{id}/rotate", virtualKeyH.Rotate)
		r.Post("/{id}/reset-spend", virtualKeyH.Reset)
	})

	// Internal edge proxy endpoints
	r.Route("/api/v1/internal", func(r chi.Router) {
		r.Use(middleware.GatewayAuth(cfg.GatewaySecret, db, legacyAuthCfg))
		r.Get("/invalidation-stream", invalidationBroadcaster.ServeHTTP)
		r.Get("/virtual-keys/resolve", virtualKeyH.Resolve)
	})

	r.Get("/readyz", healthH.Readyz)
	r.Get("/healthz", healthH.Healthz)

	r.Route("/api/v3/gateway-broker", func(r chi.Router) {
		r.Use(middleware.GatewayAuth(cfg.GatewaySecret, db, legacyAuthCfg))
		r.Use(middleware.RequireOrganizationFeature(db, "group_policies"))
		r.Post("/llm-requests", brokerV2H.HandleLLMRequest)
		r.Post("/llm-stream", brokerV2H.HandleLLMStream)
	})

	// 5. Authoritative Central Spend Ledger API v2
	r.Route("/api/v2/spend", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(middleware.GatewayAuth(cfg.GatewaySecret, db, legacyAuthCfg))
			r.Use(middleware.RequireOrganizationFeature(db, "spend_caps"))
			r.Post("/authorize", spendV2H.Authorize)
			r.Post("/reservations/{reservation_id}/settle", spendV2H.Settle)
			r.Post("/reservations/{reservation_id}/release", spendV2H.Release)
		})

		r.Group(func(r chi.Router) {
			r.Use(middleware.DashboardAuth())
			r.Use(middleware.RequireOrganizationFeature(db, "spend_caps"))
			r.Get("/effective", spendV2H.GetEffective)
			r.Get("/analytics", spendV2H.GetAnalytics)
			r.Get("/events", spendV2H.ListEvents)
			r.Get("/policies", spendV2H.ListPolicies)
			r.Post("/policies", spendV2H.CreatePolicy)
			r.Post("/policies/{id}/publish", spendV2H.PublishPolicy)
			r.Get("/increase-requests", spendV2H.ListIncreaseRequests)
			r.Post("/increase-requests", spendV2H.CreateIncreaseRequest)
			r.Post("/increase-requests/{id}/decide", spendV2H.DecideIncreaseRequest)
		})
	})

	// 6. Device Governance
	r.Post("/api/v1/devices/enroll", deviceH.EnrollDevice)
	r.With(middleware.GatewayAuth(cfg.GatewaySecret, db, legacyAuthCfg)).Post("/api/v1/devices/{id}/telemetry", deviceH.RecordTelemetry)
	r.Post("/api/v1/enroll", enrollmentH.PostEnroll)

	// Gateway API Spec endpoints
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Get("/api/v1/bootstrap", hubSpecH.GetBootstrap)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Get("/api/v1/events", hubSpecH.GetEventsStream)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Get("/api/v1/policies/{id}", hubSpecH.GetPolicyByID)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Get("/api/v1/credentials/{provider}", hubSpecH.GetProviderCredential)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Post("/api/v1/credentials/rotate", hubSpecH.RotateCredential)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Get("/api/v1/policies/active", policyMgmtH.GetActive)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Get("/api/v1/policy/active", policyMgmtH.GetActive)
	r.With(middleware.PolicyReadAuth(cfg.PolicyReadSecret, legacyAuthCfg)).Get("/api/v1/policy/subscribe", policyMgmtH.Subscribe)
	r.With(middleware.GatewayAuth(cfg.GatewaySecret, db, legacyAuthCfg)).Post("/api/v1/telemetry", hubSpecH.PostTelemetry)

	// Ingest endpoints
	r.Route("/api/v1/ingest", func(r chi.Router) {
		r.Use(middleware.GatewayAuth(cfg.GatewaySecret, db, legacyAuthCfg))
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

	// Dashboard API
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.DashboardAuth())

		// Organization & License Management
		r.Get("/organization", licenseH.GetOrganization)
		r.Put("/organization", licenseH.UpdateOrganization)
		r.Get("/license/status", licenseH.GetStatus)
		r.With(middleware.RequireAdmin()).Post("/license/activate", licenseH.ActivateLicense)

		r.Get("/gateways", hubSpecH.ListGateways)
		r.Get("/fleet/overview", fleetH.GetOverview)
		r.Get("/fleet/coverage-health", coverageHealthH.GetCoverageHealth)
		r.Get("/fleet/agents", fleetH.ListAgents)
		r.Get("/fleet/heatmap", fleetH.GetHeatmap)
		r.Get("/fleet/events", fleetH.ListEvents)
		r.Get("/fleet/agents/{agentID}/events", fleetH.ListEvents)

		// Observability Center
		r.Route("/observability", func(r chi.Router) {
			r.Get("/request-logs", observabilityH.ListRequestLogs)
			r.Get("/request-logs/stream", observabilityH.StreamRequestLogs)
			r.Get("/audit-logs", observabilityH.ListAuditLogs)
			r.Get("/deleted-keys", observabilityH.ListDeletedKeys)
			r.Get("/deleted-teams", observabilityH.ListDeletedTeams)
		})
		r.Get("/audit/logs", observabilityH.ListAuditLogs)

		// Run Explorer & Forensics
		r.Get("/runs", runH.ListRuns)
		r.Get("/runs/{run_id}", runH.GetRun)

		// Session Forensics & Multi-Turn Tracing
		r.Get("/sessions/{session_id}", sessionH.GetSessionTrace)

		// Effective Policy Explorer
		r.Get("/policy/effective-explorer", effectivePolicyH.GetEffective)

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
		
		// Policy Management
		r.Get("/policies", policyMgmtH.List)
		r.Get("/policies/active", policyMgmtH.GetActive)
		r.Get("/policy/active", policyMgmtH.GetActive)
		r.Get("/policies/{id}", hubSpecH.GetPolicyByID)
		r.With(middleware.RequireAdmin()).Post("/policies", policyMgmtH.Save)
		r.Get("/policies/templates", templateH.ListTemplates)
		r.Get("/policies/templates/{id}", templateH.GetTemplate)
		r.With(middleware.RequireAdmin()).Post("/policies/templates", templateH.CreateCustomTemplate)
		r.With(middleware.RequireAdmin()).Delete("/policies/templates/{id}", templateH.DeleteCustomTemplate)

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
			r.Use(middleware.RequireOrganizationFeature(db, "group_policies"))
			r.Get("/", groupPolicyH.ListGroupPolicies)
			r.Get("/{groupID}", groupPolicyH.GetGroupPolicy)
			r.With(middleware.RequireAdmin()).Post("/", groupPolicyH.PublishGroupPolicy)
		})

		// Safe Mode status
		r.Get("/policy/safe-mode/status", safeModeH.GetStatus)

		// Spend Caps
		r.Route("/spend", func(r chi.Router) {
			r.Use(middleware.RequireOrganizationFeature(db, "spend_caps"))
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

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
}
