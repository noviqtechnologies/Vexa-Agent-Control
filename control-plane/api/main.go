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
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/config"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/handler"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/middleware"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/sse"
	"github.com/noviqtechnologies/agentwall/control-plane/api/internal/store"
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

	broker := sse.NewBroker()

	ingestH := handler.NewIngestHandler(db, broker)
	fleetH := handler.NewFleetHandler(db)
	identityH := handler.NewIdentityHandler(db)
	mcpServersH := handler.NewMcpServersHandler(db)
	alertH := handler.NewAlertHandler(db, broker)
	threatH := handler.NewThreatHandler(db)
	policyH := handler.NewPolicyHandler(cfg.GatewayURL, cfg.PolicyReadSecret)
	rotationH := handler.NewRotationHandler(cfg.GatewayURL, cfg.PolicyReadSecret)

	authH := handler.NewAuthHandler(db)
	authProviderH := handler.NewAuthProviderHandler(db)
	userH := handler.NewUserHandler(db)
	policyMgmtH := handler.NewPolicyMgmtHandler(db)
	safeModeH := handler.NewSafeModeHandler()
	spendH := handler.NewSpendHandler(db)

	authH.CheckBootstrap()

	groupPolicyH := handler.NewHandler(db)

	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	// Health check — no auth.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Ingest endpoints — gateway auth (shared secret), NOT OIDC.
	r.Route("/api/v1/ingest", func(r chi.Router) {
		r.Use(middleware.GatewayAuth(cfg.GatewaySecret))
		r.Post("/events", ingestH.PostEvent)
		r.Post("/alerts", ingestH.PostAlert)
		r.Post("/credentials", ingestH.PostCredential)
		r.Post("/mcp-servers", ingestH.PostMcpServers)
		r.Post("/spend-snapshots", spendH.SyncSnapshot)
	})

	// Unauthenticated Auth Routes
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", authH.Login)
		r.Post("/logout", authH.Logout)
		r.Get("/providers", authH.ListPublicProviders)
		r.Get("/oauth/{provider_id}/login", authH.OAuthLogin)
		r.Get("/oauth/{provider_id}/callback", authH.OAuthCallback)
	})

	// Dashboard API — session cookie auth for human operators.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.DashboardAuth())

		r.Get("/fleet/overview", fleetH.GetOverview)
		r.Get("/fleet/agents", fleetH.ListAgents)
		r.Get("/fleet/heatmap", fleetH.GetHeatmap)
		r.Get("/fleet/events", fleetH.ListEvents)
		r.Get("/fleet/agents/{agentID}/events", fleetH.ListEvents)

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
		r.Put("/auth_providers", authProviderH.Upsert)
		
		// Users
		r.Get("/users", userH.List)
		r.Post("/users", userH.Create)
		r.Delete("/users/{id}", userH.Delete)
		
		// Policy Management
		r.Get("/policies", policyMgmtH.List)
		r.Get("/policies/active", policyMgmtH.GetActive)
		r.Post("/policies", policyMgmtH.Save)

		// Group Policy Management
		r.Route("/group-policies", func(r chi.Router) {
			r.Get("/", groupPolicyH.ListGroupPolicies)
			r.Get("/{groupID}", groupPolicyH.GetGroupPolicy)
			r.Post("/", groupPolicyH.PublishGroupPolicy)
		})

		// Safe Mode status (always active — static endpoint)
		r.Get("/policy/safe-mode/status", safeModeH.GetStatus)

		// Spend Caps (Admin + Gateway API)
		r.Route("/spend", func(r chi.Router) {
			r.Get("/budgets", spendH.ListBudgets)
			r.Post("/budgets", spendH.CreateBudget)
			r.Get("/snapshots", spendH.ListSnapshots)
			r.Get("/requests", spendH.ListIncreaseRequests)
			r.Post("/requests", spendH.SubmitIncreaseRequest)
			r.Post("/requests/{id}/resolve", spendH.ResolveIncreaseRequest)
		})
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
