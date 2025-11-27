package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/devchuckcamp/goauthx"
)

func main() {
	// Configure the authentication library
	cfg := goauthx.DefaultConfig()
	cfg.Database = goauthx.DatabaseConfig{
		Driver:          goauthx.Postgres,
		DSN:             "postgres://authdb:authdb@localhost:5432/authdb?sslmode=disable",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
	}
	cfg.JWT = goauthx.JWTConfig{
		Secret:            "your-super-secret-jwt-key-min-32-chars-long",
		AccessTokenExpiry: 15 * time.Minute,
		Issuer:            "my-app",
		Audience:          "my-app-users",
	}
	
	// Configure Google OAuth
	cfg.OAuth = goauthx.OAuthConfig{
		Google: goauthx.GoogleOAuthConfig{
			ClientID:     "<GOOGLE_ACCOUNT_CLIENT_ID>",
            ClientSecret: "<GOOGLE_ACCOUNT_Secret>",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
			Enabled:      true,
		},
	}
	
	// Create the store
	store, err := goauthx.NewStore(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()
	
	// Run migrations
	migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
	if err := migrator.Up(context.Background()); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	log.Println("Migrations completed successfully")
	
	// Create the auth service
	authService, err := goauthx.NewService(cfg, store)
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}
	
	// Create HTTP mux
	mux := http.NewServeMux()
	
	// Option 1: Use pre-built handlers with default routes
	handlers := goauthx.NewHandlers(authService, nil) // nil uses default routes
	handlers.RegisterRoutes(mux)
	
	// Option 2: Use custom routes (commented out example)
	// routeConfig := goauthx.DefaultRouteConfig()
	// routeConfig.RegisterPath = "/api/register"  // Customize paths
	// routeConfig.LoginPath = "/api/login"
	// handlers := goauthx.NewHandlers(authService, routeConfig)
	// handlers.RegisterRoutes(mux)
	
	// Add a welcome endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"message": "Welcome to goauthx API",
			"endpoints": {
				"register": "POST /auth/register",
				"login": "POST /auth/login",
				"refresh": "POST /auth/refresh",
				"logout": "POST /auth/logout (authenticated)",
				"profile": "GET /auth/profile (authenticated)",
				"change_password": "POST /auth/change-password (authenticated)",
				"forgot_password": "POST /auth/forgot-password",
				"reset_password": "POST /auth/reset-password",
				"verify_email": "POST /auth/verify-email",
				"resend_verification": "POST /auth/resend-verification (authenticated)",
				"google_oauth": "GET /auth/google - Sign in with Google",
				"google_oauth_callback": "GET /auth/google/callback - Google OAuth callback",
				"unlink_google": "POST /auth/google/unlink - Unlink Google account (authenticated)"
			}
		}`))
	})
	
	// Start server
	log.Println("Server starting on :8080")
	log.Println("Available endpoints:")
	log.Println("  POST /auth/register - Register a new user")
	log.Println("  POST /auth/login - Login")
	log.Println("  POST /auth/refresh - Refresh access token")
	log.Println("  POST /auth/logout - Logout (authenticated)")
	log.Println("  GET  /auth/profile - Get user profile (authenticated)")
	log.Println("  POST /auth/change-password - Change password (authenticated)")
	log.Println("  POST /auth/forgot-password - Request password reset")
	log.Println("  POST /auth/reset-password - Reset password with token")
	log.Println("  POST /auth/verify-email - Verify email with token")
	log.Println("  POST /auth/resend-verification - Resend verification email (authenticated)")
	log.Println("  GET  /auth/google - Sign in with Google")
	log.Println("  GET  /auth/google/callback - Google OAuth callback")
	log.Println("  POST /auth/google/unlink - Unlink Google account (authenticated)")
	
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
