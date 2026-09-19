package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/config"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/handler"
	"github.com/noviqtechnologies/agentcontrol/control-plane/api/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "break-glass":
		runBreakGlass(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Vexa Agent Control — Host-Bound Administration CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  agentcontrol-admin <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  break-glass    Generate a single-use emergency recovery token for host administrator")
	fmt.Println("  help           Show command usage")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  agentcontrol-admin break-glass --email admin@agentcontrol.local")
	fmt.Println("  agentcontrol-admin break-glass --org-id 00000000-0000-0000-0000-000000000001 --email owner@company.com")
}

func runBreakGlass(args []string) {
	fs := flag.NewFlagSet("break-glass", flag.ExitOnError)
	orgID := fs.String("org-id", store.DefaultOrgID, "Organization ID")
	email := fs.String("email", "", "Target administrator corporate email")
	userID := fs.String("user-id", "", "Target user ID (optional)")

	if err := fs.Parse(args); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	*email = strings.TrimSpace(*email)
	if *email == "" && *userID == "" {
		cfg, _ := config.Load()
		if cfg != nil && cfg.AdminEmail != "" {
			*email = cfg.AdminEmail
		} else {
			*email = "admin@agentcontrol.local"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	st := store.New(pool)
	var targetUserEmail = *email
	var targetUserID = *userID

	if targetUserEmail != "" {
		u, err := st.GetUserByEmail(ctx, *orgID, "", targetUserEmail)
		if err == nil && u != nil {
			targetUserID = u.ID
			targetUserEmail = u.Email
		}
	} else if targetUserID != "" {
		u, err := st.GetUserByID(ctx, targetUserID)
		if err == nil && u != nil {
			targetUserEmail = u.Email
		}
	}

	token, err := handler.GenerateBreakGlassToken(*orgID, targetUserID, targetUserEmail)
	if err != nil {
		log.Fatalf("failed to generate break-glass token: %v", err)
	}

	fmt.Println()
	fmt.Println("✔ Emergency Break-Glass Token Generated")
	fmt.Println("────────────────────────────────────────────────────────────────────────")
	fmt.Printf("  Organization ID: %s\n", *orgID)
	fmt.Printf("  Target Admin:    %s\n", targetUserEmail)
	fmt.Printf("  Recovery Token:  %s\n", token)
	fmt.Println("  Redemption URL:  http://127.0.0.1:8081/break-glass")
	fmt.Println("  Validity:        15 minutes (Single-Use Only)")
	fmt.Println("────────────────────────────────────────────────────────────────────────")
	fmt.Println("⚠ WARNING: Redeeming this token will grant emergency owner access.")
	fmt.Println("  Use this token to sign in, reset credentials, and review audit logs.")
	fmt.Println()
}
