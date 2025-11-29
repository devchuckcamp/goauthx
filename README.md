# goauthx

A comprehensive, production-ready authentication and authorization library for Go. Framework-agnostic, supports multiple databases (MySQL, PostgreSQL, SQL Server), and provides JWT-based authentication with role-based access control (RBAC).

## Features

- ✅ **User Authentication**: Registration, login, logout, and password management
- ✅ **JWT Tokens**: Secure access tokens with refresh token support
- ✅ **Google OAuth**: Sign in with Google account integration
- ✅ **Role-Based Access Control (RBAC)**: Flexible roles and permissions system
- ✅ **Email Verification**: Built-in email verification system
- ✅ **Password Reset**: Secure password reset with tokens
- ✅ **Pre-built HTTP Handlers**: Ready-to-use REST API handlers
- ✅ **Configurable Routes**: Customize API endpoint paths
- ✅ **Multiple Database Support**: MySQL, PostgreSQL, and SQL Server
- ✅ **Framework Agnostic**: Works with `net/http`, Echo, Fiber, Gin, and others
- ✅ **Production Ready**: Comprehensive error handling, logging, and testing
- ✅ **Migration System**: Built-in database migration tool
- ✅ **Middleware Support**: Ready-to-use HTTP middleware for authentication and authorization

## Real-World Usage

See **goauthx** in action in a production e-commerce API built with the Gin framework:

🔗 **[gocommerce-api](https://github.com/devchuckcamp/gocommerce-api)** - A complete e-commerce REST API demonstrating:
- Gin framework integration with goauthx
- JWT authentication for protected routes
- Role-based authorization (admin, customer roles)
- Google OAuth login implementation
- User registration and management
- Production-ready authentication middleware

## Quick Start

### Installation

```bash
go get github.com/devchuckcamp/goauthx
```

### Basic Usage

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/devchuckcamp/goauthx"
)

func main() {
	// 1. Configure the library
	cfg := goauthx.DefaultConfig()
	cfg.Database = goauthx.DatabaseConfig{
		Driver: goauthx.Postgres,
		DSN:    "postgres://user:password@localhost:5432/authdb?sslmode=disable",
	}
	cfg.JWT.Secret = "your-super-secret-jwt-key-min-32-chars-long"
	
	// 2. Create the store
	store, err := goauthx.NewStore(cfg.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	
	// 3. Run migrations
	migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
	if err := migrator.Up(context.Background()); err != nil {
		log.Fatal(err)
	}
	
	// 4. Create the auth service
	authService, err := goauthx.NewService(cfg, store)
	if err != nil {
		log.Fatal(err)
	}
	
	// 5. Register a user
	resp, err := authService.Register(context.Background(), goauthx.RegisterRequest{
		Email:     "user@example.com",
		Password:  "securepassword123",
		FirstName: "John",
		LastName:  "Doe",
	})
	if err != nil {
		log.Fatal(err)
	}
	
	log.Printf("User registered: %s", resp.User.Email)
	log.Printf("Access token: %s", resp.AccessToken)
}
```

### Running Migrations

Use the CLI tool to manage database migrations:

```bash
# Build the migration tool
cd cmd/goauthx-migrate
go build

# Apply migrations
./goauthx-migrate --dsn "postgres://user:pass@localhost/dbname?sslmode=disable" --driver postgres up

# Check migration status
./goauthx-migrate --dsn "..." --driver postgres status

# Rollback last migration
./goauthx-migrate --dsn "..." --driver postgres down
```

### Using Pre-built HTTP Handlers

```go
package main

import (
	"context"
	"log"
	"net/http"
	"github.com/devchuckcamp/goauthx"
)

func main() {
	// Setup configuration, store, and service...
	cfg := goauthx.DefaultConfig()
	// ... configure database and JWT settings ...
	
	store, _ := goauthx.NewStore(cfg.Database)
	defer store.Close()
	
	// Run migrations
	migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
	migrator.Up(context.Background())
	
	authService, _ := goauthx.NewService(cfg, store)
	
	// Create HTTP handlers with default routes
	mux := http.NewServeMux()
	handlers := goauthx.NewHandlers(authService, nil)
	handlers.RegisterRoutes(mux)
	
	// All authentication endpoints are now available:
	// POST /auth/register
	// POST /auth/login
	// POST /auth/logout (authenticated)
	// POST /auth/refresh
	// GET  /auth/profile (authenticated)
	// POST /auth/change-password (authenticated)
	// POST /auth/forgot-password
	// POST /auth/reset-password
	// POST /auth/verify-email
	// POST /auth/resend-verification (authenticated)
	// GET  /auth/google - Google OAuth login
	// GET  /auth/google/callback - Google OAuth callback
	// POST /auth/google/unlink - Unlink Google account (authenticated)
	
	http.ListenAndServe(":8080", mux)
}
```

### Using Custom Routes

```go
// Customize endpoint paths
routeConfig := goauthx.DefaultRouteConfig()
routeConfig.RegisterPath = "/api/v1/register"
routeConfig.LoginPath = "/api/v1/login"
routeConfig.ProfilePath = "/api/v1/me"

handlers := goauthx.NewHandlers(authService, routeConfig)
handlers.RegisterRoutes(mux)
```

### Using Custom Middleware

```go
package main

import (
	"net/http"
	"github.com/devchuckcamp/goauthx"
)

func main() {
	// Setup (cfg, store, authService)...
	
	authMiddleware := goauthx.NewAuthMiddleware(authService)
	
	mux := http.NewServeMux()
	
	// Use pre-built handlers for auth endpoints
	handlers := goauthx.NewHandlers(authService, nil)
	handlers.RegisterRoutes(mux)
	
	// Add custom protected routes
	mux.Handle("/api/profile", authMiddleware.Authenticate(
		http.HandlerFunc(profileHandler),
	))
	
	// Admin only routes
	mux.Handle("/api/admin", authMiddleware.Authenticate(
		authMiddleware.RequireRole("admin")(
			http.HandlerFunc(adminHandler),
		),
	))
	
	http.ListenAndServe(":8080", mux)
}
```

## Supported Databases

### PostgreSQL
```go
cfg.Database = goauthx.DatabaseConfig{
	Driver: goauthx.Postgres,
	DSN:    "postgres://user:password@localhost:5432/dbname?sslmode=disable",
}
```

### MySQL
```go
cfg.Database = goauthx.DatabaseConfig{
	Driver: goauthx.MySQL,
	DSN:    "user:password@tcp(localhost:3306)/dbname?parseTime=true",
}
```

### SQL Server
```go
cfg.Database = goauthx.DatabaseConfig{
	Driver: goauthx.SQLServer,
	DSN:    "sqlserver://user:password@localhost:1433?database=dbname",
}
```

## Configuration

### Full Configuration Example

```go
cfg := &goauthx.Config{
	Database: goauthx.DatabaseConfig{
		Driver:          goauthx.Postgres,
		DSN:             "postgres://...",
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
	},
	JWT: goauthx.JWTConfig{
		Secret:            "your-secret-min-32-chars",
		AccessTokenExpiry: 15 * time.Minute,
		Issuer:            "my-app",
		Audience:          "my-app-users",
	},
	Password: goauthx.PasswordConfig{
		MinLength:  8,
		BcryptCost: 12,
	},
	Token: goauthx.TokenConfig{
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		RefreshTokenLength: 64,
	},
	OAuth: goauthx.OAuthConfig{
		Google: goauthx.GoogleOAuthConfig{
			:     "your-google-client-id",
			ClientSecret: "your-google-client-secret",
			RedirectURL:  "http://localhost:8080/auth/google/callback",
			Enabled:      true,
		},
	},
}
```

## Google OAuth Integration

### Setup

1. **Get Google OAuth Credentials**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
   - Add authorized redirect URIs (e.g., `http://localhost:8080/auth/google/callback`)
   - Copy Client ID and Client Secret

2. **Configure goauthx**:
```go
cfg := goauthx.DefaultConfig()
cfg.OAuth.Google.ClientId = "your-client-id"
cfg.OAuth.Google.ClientSecret = "your-client-secret"
cfg.OAuth.Google.RedirectURL = "http://localhost:8080/auth/google/callback"
cfg.OAuth.Google.Enabled = true
```

3. **Using Pre-built Handlers** (Recommended):
```go
handlers := goauthx.NewHandlers(authService, nil)
handlers.RegisterRoutes(mux)

// OAuth endpoints are automatically available:
// GET  /auth/google - Initiates Google OAuth flow
// GET  /auth/google/callback - Handles OAuth callback
// POST /auth/google/unlink - Unlinks Google account (authenticated)
```

### Usage Flows

**New User Registration via Google:**
1. User clicks "Sign in with Google"
2. Redirect to `/auth/google`
3. User authenticates with Google
4. Google redirects to `/auth/google/callback`
5. New user account is automatically created
6. User receives JWT access and refresh tokens

**Existing User Login via Google:**
1. User with existing account clicks "Sign in with Google"
2. OAuth flow completes
3. Google account is linked to existing user
4. User receives JWT tokens

**Linking Google to Existing Account:**
- Users can link their Google account after registration
- If email matches, accounts are automatically linked
- Email is marked as verified if Google account is verified

### Testing

```bash
# Start OAuth flow
curl http://localhost:8080/auth/google
# User will be redirected to Google login page

# After authentication, Google redirects to callback with tokens
# Response includes JWT access token and refresh token

# Unlink Google account (requires authentication)
curl -X POST http://localhost:8080/auth/google/unlink \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "oauth-account-id"}'
```

### Security Features

- **CSRF Protection**: State parameter for OAuth flow
- **Account Linking**: Prevents duplicate accounts
- **Password Optional**: Users can sign up with only Google
- **Safe Unlinking**: Can't unlink last auth method
- **Token Management**: Automatic OAuth token refresh

## Core Concepts

### Authentication

- **Register**: Create new user accounts with email and password
- **Login**: Authenticate users and issue JWT access tokens
- **Logout**: Revoke refresh tokens
- **Refresh**: Generate new access tokens using refresh tokens

### Authorization

- **Roles**: Group permissions (e.g., "admin", "user", "moderator")
- **Permissions**: Granular access control (e.g., "posts:read", "posts:write")
- **User-Role Assignment**: Users can have multiple roles
- **Role-Permission Assignment**: Roles can have multiple permissions

### Checking Permissions

```go
// Check if user has a role
hasRole, err := authService.HasRole(ctx, userID, "admin")

// Check if user has a permission
hasPerm, err := authService.HasPermission(ctx, userID, "posts:write")

// Get all user permissions
permissions, err := authService.GetUserPermissions(ctx, userID)
```

### Email Verification

```go
// During registration, create verification token
token, err := authService.ResendVerificationEmail(ctx, userID)
// In production: send token via email to user

// User verifies email with token
err := authService.VerifyEmail(ctx, token)
```

### Password Reset

```go
// User requests password reset
token, err := authService.RequestPasswordReset(ctx, "user@example.com")
// In production: send token via email to user

// User resets password with token
err := authService.ResetPassword(ctx, goauthx.ResetPasswordRequest{
	Token:       token,
	NewPassword: "newSecurePassword123",
})
```

### Change Password

```go
// User changes password (requires authentication)
err := authService.ChangePassword(ctx, userID, goauthx.ChangePasswordRequest{
	OldPassword: "currentPassword",
	NewPassword: "newSecurePassword123",
})
```

## Testing with Docker

### Quick Start with Docker PostgreSQL

1. **Start the PostgreSQL database**:
```bash
docker-compose up -d
```

This will start a PostgreSQL 16 container with:
- Database: `authdb`
- User: `authdb`
- Password: `authdb`
- Port: `5432`

2. **Run the example application**:
```bash
cd examples/with-handlers
go run main.go
```

The example app will automatically:
- Connect to the database
- Run all migrations
- Start the HTTP server on `:8080`

3. **Test the API endpoints**:

**Register a new user**:
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Login**:
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

**Access protected profile** (replace `YOUR_TOKEN` with the access_token from login):
```bash
curl -X GET http://localhost:8080/auth/profile \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Change password** (authenticated):
```bash
curl -X POST http://localhost:8080/auth/change-password \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "securepassword123",
    "new_password": "newSecurePassword456"
  }'
```

**Request password reset**:
```bash
curl -X POST http://localhost:8080/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**Reset password with token**:
```bash
curl -X POST http://localhost:8080/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "RESET_TOKEN_FROM_EMAIL",
    "new_password": "newSecurePassword456"
  }'
```

4. **Stop the database**:
```bash
docker-compose down
```

For more Docker commands and troubleshooting, see [DOCKER.md](DOCKER.md).

## Examples

See the `examples/` directory for a complete working example:

- `examples/with-handlers/` - Complete example using pre-built HTTP handlers

## Documentation

For detailed documentation, see the `docs/` directory:

- [Overview](docs/overview.md) - Architecture and design
- [Database](docs/database.md) - Database schema and relationships
- [Migrations](docs/migrations.md) - Migration system details
- [Usage Examples](docs/usage-examples.md) - More code examples
- [Google OAuth](docs/google-oauth.md) - Google OAuth integration guide

## License

MIT License - see [LICENSE](LICENSE) for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on GitHub.
