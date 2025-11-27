# Usage Examples

This document provides detailed code examples for common use cases.

## Table of Contents

1. [Basic Setup](#basic-setup)
2. [Using Pre-built HTTP Handlers](#using-pre-built-http-handlers)
3. [User Registration & Login](#user-registration--login)
4. [Token Refresh](#token-refresh)
5. [Password Management](#password-management)
6. [Email Verification](#email-verification)
7. [Role Management](#role-management)
8. [Permission Management](#permission-management)
9. [Custom Middleware](#custom-middleware)
10. [Framework Integration](#framework-integration)
11. [Testing](#testing)

## Basic Setup

### Minimal Configuration

```go
package main

import (
	"context"
	"log"

	"github.com/devchuckcamp/goauthx"
)

func main() {
	// Use default configuration
	cfg := goauthx.DefaultConfig()
	
	// Configure database
	cfg.Database.Driver = goauthx.Postgres
	cfg.Database.DSN = "postgres://user:pass@localhost:5432/authdb?sslmode=disable"
	
	// Configure JWT (REQUIRED - no default secret)
	cfg.JWT.Secret = "your-super-secret-key-minimum-32-characters-long"
	
	// Create store
	store, err := goauthx.NewStore(cfg.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	
	// Run migrations
	migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
	if err := migrator.Up(context.Background()); err != nil {
		log.Fatal(err)
	}
	
	// Create auth service
	authService, err := goauthx.NewService(cfg, store)
	if err != nil {
		log.Fatal(err)
	}
	
	log.Println("Authentication service ready!")
}
```

## Using Pre-built HTTP Handlers

### Quick Start with Default Routes

```go
package main

import (
	"context"
	"log"
	"net/http"
	
	"github.com/devchuckcamp/goauthx"
)

func main() {
	// Setup (cfg, store, authService as shown above)...
	
	// Create HTTP mux
	mux := http.NewServeMux()
	
	// Create handlers with default routes
	handlers := goauthx.NewHandlers(authService, nil)
	
	// Register all authentication endpoints
	handlers.RegisterRoutes(mux)
	
	// Available endpoints:
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
	
	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", mux)
}
```

### Custom Route Configuration

```go
// Create custom route configuration
routeConfig := goauthx.DefaultRouteConfig()

// Customize paths
routeConfig.RegisterPath = "/api/v1/auth/register"
routeConfig.LoginPath = "/api/v1/auth/login"
routeConfig.ProfilePath = "/api/v1/users/me"
routeConfig.ChangePasswordPath = "/api/v1/users/password"
routeConfig.RequestPasswordResetPath = "/api/v1/auth/forgot"
routeConfig.ResetPasswordPath = "/api/v1/auth/reset"

// Create handlers with custom routes
handlers := goauthx.NewHandlers(authService, routeConfig)
handlers.RegisterRoutes(mux)
```

### Adding Custom Endpoints

```go
// Create handlers
handlers := goauthx.NewHandlers(authService, nil)
handlers.RegisterRoutes(mux)

// Add your own custom endpoints
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to my API!"))
})

mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"status":"healthy"}`))
})

// Protected custom endpoint
middleware := goauthx.NewAuthMiddleware(authService)
mux.Handle("/api/data", middleware.Authenticate(
	http.HandlerFunc(myCustomHandler),
))
```

### Full Configuration

```go
cfg := &goauthx.Config{
	Database: goauthx.DatabaseConfig{
		Driver:          goauthx.MySQL,
		DSN:             "user:pass@tcp(localhost:3306)/authdb?parseTime=true",
		MaxOpenConns:    50,
		MaxIdleConns:    10,
		ConnMaxLifetime: 10 * time.Minute,
	},
	JWT: goauthx.JWTConfig{
		Secret:            "your-super-secret-jwt-key-min-32-chars",
		AccessTokenExpiry: 30 * time.Minute,
		Issuer:            "mycompany.com",
		Audience:          "myapp-users",
	},
	Password: goauthx.PasswordConfig{
		MinLength:  10,
		BcryptCost: 14, // Higher = more secure but slower
	},
	Token: goauthx.TokenConfig{
		RefreshTokenExpiry: 30 * 24 * time.Hour, // 30 days
		RefreshTokenLength: 128,
	},
}
```

## User Registration & Login

### Register New User

```go
func registerUser(service *goauthx.Service) {
	ctx := context.Background()
	
	req := goauthx.RegisterRequest{
		Email:     "john.doe@example.com",
		Password:  "SecurePass123!",
		FirstName: "John",
		LastName:  "Doe",
	}
	
	resp, err := service.Register(ctx, req)
	if err != nil {
		if err == goauthx.ErrEmailAlreadyExists {
			log.Println("Email already registered")
			return
		}
		log.Fatalf("Registration failed: %v", err)
	}
	
	log.Printf("User registered successfully!")
	log.Printf("User ID: %s", resp.User.ID)
	log.Printf("Access Token: %s", resp.AccessToken)
	log.Printf("Refresh Token: %s", resp.RefreshToken)
	log.Printf("Token expires at: %s", resp.ExpiresAt)
}
```

### Login User

```go
func loginUser(service *goauthx.Service) {
	ctx := context.Background()
	
	req := goauthx.LoginRequest{
		Email:    "john.doe@example.com",
		Password: "SecurePass123!",
	}
	
	resp, err := service.Login(ctx, req)
	if err != nil {
		switch err {
		case goauthx.ErrInvalidCredentials:
			log.Println("Invalid email or password")
		case goauthx.ErrUserInactive:
			log.Println("User account is inactive")
		default:
			log.Printf("Login failed: %v", err)
		}
		return
	}
	
	log.Printf("Login successful!")
	log.Printf("Welcome %s %s", resp.User.FirstName, resp.User.LastName)
	
	// Store tokens (e.g., in session, cookie, or local storage)
	storeTokens(resp.AccessToken, resp.RefreshToken)
}
```

### Logout User

```go
func logoutUser(service *goauthx.Service, userID string) {
	ctx := context.Background()
	
	// Revoke all refresh tokens for this user
	if err := service.Logout(ctx, userID); err != nil {
		log.Printf("Logout failed: %v", err)
		return
	}
	
	log.Println("User logged out successfully")
	
	// Clear stored tokens on client side
	clearTokens()
}
```

## Token Refresh

### Refresh Access Token

```go
func refreshToken(service *goauthx.Service, refreshToken string) (*goauthx.AuthResponse, error) {
	ctx := context.Background()
	
	resp, err := service.RefreshAccessToken(ctx, refreshToken)
	if err != nil {
		if err == goauthx.ErrInvalidRefreshToken {
			// Refresh token is invalid or expired
			// User needs to login again
			return nil, err
		}
		return nil, err
	}
	
	log.Println("Token refreshed successfully")
	
	// Update stored tokens
	storeTokens(resp.AccessToken, resp.RefreshToken)
	
	return resp, nil
}
```

### Automatic Token Refresh

```go
type AuthClient struct {
	service      *goauthx.Service
	accessToken  string
	refreshToken string
}

func (c *AuthClient) makeAuthenticatedRequest(req *http.Request) (*http.Response, error) {
	// Add access token to request
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	
	// Make request
	client := &http.Client{}
	resp, err := client.Do(req)
	
	// If unauthorized, try refreshing token
	if resp != nil && resp.StatusCode == http.StatusUnauthorized {
		// Refresh token
		authResp, err := c.service.RefreshAccessToken(context.Background(), c.refreshToken)
		if err != nil {
			return nil, fmt.Errorf("token refresh failed: %w", err)
		}
		
		// Update tokens
		c.accessToken = authResp.AccessToken
		c.refreshToken = authResp.RefreshToken
		
		// Retry request with new token
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
		resp, err = client.Do(req)
	}
	
	return resp, err
}
```

## Password Management

### Change Password (Authenticated User)

```go
func changePassword(service *goauthx.Service, userID string) {
	ctx := context.Background()
	
	req := goauthx.ChangePasswordRequest{
		OldPassword: "CurrentPassword123",
		NewPassword: "NewSecurePassword456!",
	}
	
	err := service.ChangePassword(ctx, userID, req)
	if err != nil {
		switch err {
		case goauthx.ErrInvalidCredentials:
			log.Println("Current password is incorrect")
		case goauthx.ErrUserNotFound:
			log.Println("User not found")
		default:
			log.Printf("Password change failed: %v", err)
		}
		return
	}
	
	log.Println("Password changed successfully")
	log.Println("All sessions have been invalidated - please login again")
}
```

### Request Password Reset

```go
func requestPasswordReset(service *goauthx.Service, email string) {
	ctx := context.Background()
	
	token, err := service.RequestPasswordReset(ctx, email)
	if err != nil {
		// Don't reveal if email exists (security best practice)
		log.Println("If the email exists, a reset link has been sent")
		return
	}
	
	// In production, send this token via email
	log.Printf("Password reset token: %s", token)
	
	// Example: emailService.SendPasswordResetEmail(email, token)
	log.Println("Password reset email sent")
}
```

### Reset Password with Token

```go
func resetPassword(service *goauthx.Service, resetToken string) {
	ctx := context.Background()
	
	req := goauthx.ResetPasswordRequest{
		Token:       resetToken,
		NewPassword: "NewSecurePassword456!",
	}
	
	err := service.ResetPassword(ctx, req)
	if err != nil {
		log.Printf("Password reset failed: %v", err)
		return
	}
	
	log.Println("Password reset successfully")
	log.Println("All sessions have been invalidated")
}
```

## Email Verification

### Send Verification Email

```go
func sendVerificationEmail(service *goauthx.Service, userID string) {
	ctx := context.Background()
	
	token, err := service.ResendVerificationEmail(ctx, userID)
	if err != nil {
		log.Printf("Failed to send verification email: %v", err)
		return
	}
	
	// In production: emailService.SendVerificationEmail(user.Email, token)
	log.Printf("Verification token: %s", token)
}
```

### Verify Email Address

```go
func verifyEmail(service *goauthx.Service, token string) {
	ctx := context.Background()
	
	err := service.VerifyEmail(ctx, token)
	if err != nil {
		log.Printf("Email verification failed: %v", err)
		return
	}
	
	log.Println("Email verified successfully")
}
```

### Complete Registration with Verification

```go
func registerWithVerification(service *goauthx.Service) {
	ctx := context.Background()
	
	// Register user
	regReq := goauthx.RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "SecurePass123!",
		FirstName: "Jane",
		LastName:  "Smith",
	}
	
	regResp, err := service.Register(ctx, regReq)
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	
	// Send verification email
	token, _ := service.ResendVerificationEmail(ctx, regResp.User.ID)
	// In production: emailService.SendVerificationEmail(email, token)
	
	log.Printf("User registered. Verification token: %s", token)
}
```

## Role Management

### Create Roles

```go
func setupRoles(store goauthx.Store) error {
	ctx := context.Background()
	
	roles := []goauthx.Role{
		{
			Name:        "admin",
			Description: "System administrator with full access",
		},
		{
			Name:        "editor",
			Description: "Can create and edit content",
		},
		{
			Name:        "viewer",
			Description: "Read-only access to content",
		},
	}
	
	for _, role := range roles {
		if err := store.Create(ctx, &role); err != nil {
			return fmt.Errorf("failed to create role %s: %w", role.Name, err)
		}
		log.Printf("Created role: %s", role.Name)
	}
	
	return nil
}
```

### Assign Role to User

```go
func assignRole(store goauthx.Store, userEmail, roleName string) error {
	ctx := context.Background()
	
	// Get user
	user, err := store.GetByEmail(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	
	// Get role
	role, err := store.GetByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}
	
	// Assign role
	if err := store.AssignRole(ctx, user.ID, role.ID); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	
	log.Printf("Assigned role '%s' to user '%s'", roleName, userEmail)
	return nil
}
```

### Check User Role

```go
func checkUserRole(service *goauthx.Service, userID, roleName string) {
	ctx := context.Background()
	
	hasRole, err := service.HasRole(ctx, userID, roleName)
	if err != nil {
		log.Printf("Error checking role: %v", err)
		return
	}
	
	if hasRole {
		log.Printf("User has role: %s", roleName)
	} else {
		log.Printf("User does NOT have role: %s", roleName)
	}
}
```

### Get User Roles

```go
func getUserRoles(store goauthx.Store, userID string) {
	ctx := context.Background()
	
	roles, err := store.GetUserRoles(ctx, userID)
	if err != nil {
		log.Printf("Error getting roles: %v", err)
		return
	}
	
	log.Println("User roles:")
	for _, role := range roles {
		log.Printf("  - %s: %s", role.Name, role.Description)
	}
}
```

## Permission Management

### Create Permissions

```go
func setupPermissions(store goauthx.Store) error {
	ctx := context.Background()
	
	permissions := []goauthx.Permission{
		{
			Name:        "posts:read",
			Resource:    "posts",
			Action:      "read",
			Description: "Read blog posts",
		},
		{
			Name:        "posts:write",
			Resource:    "posts",
			Action:      "write",
			Description: "Create new blog posts",
		},
		{
			Name:        "posts:edit",
			Resource:    "posts",
			Action:      "edit",
			Description: "Edit existing blog posts",
		},
		{
			Name:        "posts:delete",
			Resource:    "posts",
			Action:      "delete",
			Description: "Delete blog posts",
		},
		{
			Name:        "users:manage",
			Resource:    "users",
			Action:      "manage",
			Description: "Manage user accounts",
		},
	}
	
	for _, perm := range permissions {
		if err := store.Create(ctx, &perm); err != nil {
			return fmt.Errorf("failed to create permission %s: %w", perm.Name, err)
		}
		log.Printf("Created permission: %s", perm.Name)
	}
	
	return nil
}
```

### Grant Permission to Role

```go
func grantPermissionToRole(store goauthx.Store, roleName, permissionName string) error {
	ctx := context.Background()
	
	// Get role
	role, err := store.GetByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}
	
	// Get permission
	perm, err := store.GetByName(ctx, permissionName)
	if err != nil {
		return fmt.Errorf("permission not found: %w", err)
	}
	
	// Grant permission
	if err := store.GrantPermission(ctx, role.ID, perm.ID); err != nil {
		return fmt.Errorf("failed to grant permission: %w", err)
	}
	
	log.Printf("Granted permission '%s' to role '%s'", permissionName, roleName)
	return nil
}
```

### Complete RBAC Setup

```go
func setupCompleteRBAC(store goauthx.Store) error {
	ctx := context.Background()
	
	// 1. Create roles
	adminRole := &goauthx.Role{Name: "admin", Description: "Administrator"}
	editorRole := &goauthx.Role{Name: "editor", Description: "Content Editor"}
	viewerRole := &goauthx.Role{Name: "viewer", Description: "Viewer"}
	
	store.Create(ctx, adminRole)
	store.Create(ctx, editorRole)
	store.Create(ctx, viewerRole)
	
	// 2. Create permissions
	perms := map[string]*goauthx.Permission{
		"posts:read":   {Name: "posts:read", Resource: "posts", Action: "read"},
		"posts:write":  {Name: "posts:write", Resource: "posts", Action: "write"},
		"posts:delete": {Name: "posts:delete", Resource: "posts", Action: "delete"},
		"users:manage": {Name: "users:manage", Resource: "users", Action: "manage"},
	}
	
	for _, perm := range perms {
		store.Create(ctx, perm)
	}
	
	// 3. Grant permissions to roles
	// Admin gets all permissions
	for _, perm := range perms {
		store.GrantPermission(ctx, adminRole.ID, perm.ID)
	}
	
	// Editor can read, write (but not delete)
	store.GrantPermission(ctx, editorRole.ID, perms["posts:read"].ID)
	store.GrantPermission(ctx, editorRole.ID, perms["posts:write"].ID)
	
	// Viewer can only read
	store.GrantPermission(ctx, viewerRole.ID, perms["posts:read"].ID)
	
	log.Println("RBAC setup complete!")
	return nil
}
```

### Check User Permission

```go
func checkPermission(service *goauthx.Service, userID, permissionName string) bool {
	ctx := context.Background()
	
	hasPerm, err := service.HasPermission(ctx, userID, permissionName)
	if err != nil {
		log.Printf("Error checking permission: %v", err)
		return false
	}
	
	return hasPerm
}

// Usage
if checkPermission(authService, userID, "posts:delete") {
	// User can delete posts
	deletePost(postID)
} else {
	// Permission denied
	http.Error(w, "Forbidden", http.StatusForbidden)
}
```

## Custom Middleware

### Adding Custom Protected Routes

```go
func main() {
	// Setup auth service...
	authMiddleware := goauthx.NewAuthMiddleware(authService)
	
	mux := http.NewServeMux()
	
	// Register pre-built authentication handlers
	handlers := goauthx.NewHandlers(authService, nil)
	handlers.RegisterRoutes(mux)
	
	// Add custom public endpoints
	mux.HandleFunc("/health", healthHandler)
	
	// Add custom protected endpoint
	mux.Handle("/api/data", 
		authMiddleware.Authenticate(http.HandlerFunc(dataHandler)))
	
	http.ListenAndServe(":8080", mux)
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	// User is authenticated, get user info from context
	userID, _ := goauthx.GetUserID(r.Context())
	email, _ := goauthx.GetUserEmail(r.Context())
	
	json.NewEncoder(w).Encode(map[string]string{
		"user_id": userID,
		"email":   email,
	})
}
```

### Role-Based Custom Routes

```go
func main() {
	authMiddleware := goauthx.NewAuthMiddleware(authService)
	
	mux := http.NewServeMux()
	
	// Register pre-built handlers
	handlers := goauthx.NewHandlers(authService, nil)
	handlers.RegisterRoutes(mux)
	
	// Add admin only endpoint
	mux.Handle("/api/admin/users",
		authMiddleware.Authenticate(
			authMiddleware.RequireRole("admin")(
				http.HandlerFunc(listUsersHandler),
			),
		),
	)
	
	// Multiple roles allowed
	mux.Handle("/api/content",
		authMiddleware.Authenticate(
			authMiddleware.RequireAnyRole("admin", "editor")(
				http.HandlerFunc(manageContentHandler),
			),
		),
	)
	
	http.ListenAndServe(":8080", mux)
}
```

### Permission-Based Custom Routes

```go
func main() {
	authMiddleware := goauthx.NewAuthMiddleware(authService)
	
	mux := http.NewServeMux()
	
	// Register pre-built handlers
	handlers := goauthx.NewHandlers(authService, nil)
	handlers.RegisterRoutes(mux)
	
	// Add permission-protected endpoint
	mux.Handle("/api/posts",
		authMiddleware.Authenticate(
			authMiddleware.RequirePermission("posts:write")(
				http.HandlerFunc(createPostHandler),
			),
		),
	)
	
	http.ListenAndServe(":8080", mux)
}
```

### Chaining Multiple Middleware

```go
func main() {
	authMiddleware := goauthx.NewAuthMiddleware(authService)
	
	mux := http.NewServeMux()
	
	// Register pre-built handlers
	handlers := goauthx.NewHandlers(authService, nil)
	handlers.RegisterRoutes(mux)
	
	// Create a middleware chain for custom route
	protectedAdminHandler := goauthx.Chain(
		authMiddleware.Authenticate,
		authMiddleware.RequireRole("admin"),
		loggingMiddleware,
		rateLimitMiddleware,
	)(http.HandlerFunc(adminHandler))
	
	mux.Handle("/api/admin", protectedAdminHandler)
	
	http.ListenAndServe(":8080", mux)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
```

## Framework Integration

### Gin Framework

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/devchuckcamp/goauthx"
)

func GinAuthMiddleware(authMiddleware *goauthx.AuthMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization required"})
			c.Abort()
			return
		}
		
		tokenString, err := tokens.ExtractToken(authHeader)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid authorization header"})
			c.Abort()
			return
		}
		
		claims, err := authMiddleware.ValidateToken(tokenString)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("roles", claims.Roles)
		c.Next()
	}
}

func main() {
	// Setup auth service...
	authMiddleware := goauthx.NewAuthMiddleware(authService)
	
	r := gin.Default()
	
	// Public routes
	r.POST("/register", registerHandler)
	r.POST("/login", loginHandler)
	
	// Protected routes
	protected := r.Group("/api")
	protected.Use(GinAuthMiddleware(authMiddleware))
	{
		protected.GET("/profile", profileHandler)
		protected.GET("/posts", listPostsHandler)
	}
	
	r.Run(":8080")
}
```

### Echo Framework

```go
package main

import (
	"github.com/labstack/echo/v4"
	"github.com/devchuckcamp/goauthx"
)

func EchoAuthMiddleware(authMiddleware *goauthx.AuthMiddleware) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			// Validation logic...
			
			// Store in echo context
			c.Set("user_id", claims.UserID)
			return next(c)
		}
	}
}

func main() {
	// Setup auth service...
	authMiddleware := goauthx.NewAuthMiddleware(authService)
	
	e := echo.New()
	
	// Public routes
	e.POST("/register", registerHandler)
	e.POST("/login", loginHandler)
	
	// Protected group
	api := e.Group("/api")
	api.Use(EchoAuthMiddleware(authMiddleware))
	api.GET("/profile", profileHandler)
	
	e.Start(":8080")
}
```

## Testing

### Testing with Mock Store

```go
package main

import (
	"context"
	"testing"
	
	"github.com/devchuckcamp/goauthx"
)

type MockStore struct {
	users map[string]*goauthx.User
}

func (m *MockStore) GetByEmail(ctx context.Context, email string) (*goauthx.User, error) {
	user, ok := m.users[email]
	if !ok {
		return nil, goauthx.ErrUserNotFound
	}
	return user, nil
}

// Implement other Store methods...

func TestRegisterUser(t *testing.T) {
	cfg := goauthx.DefaultConfig()
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters"
	
	mockStore := &MockStore{users: make(map[string]*goauthx.User)}
	service, _ := goauthx.NewService(cfg, mockStore)
	
	req := goauthx.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	
	resp, err := service.Register(context.Background(), req)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	
	if resp.User.Email != req.Email {
		t.Errorf("Expected email %s, got %s", req.Email, resp.User.Email)
	}
}
```

### Integration Testing

```go
func TestFullAuthFlow(t *testing.T) {
	// Setup real database for integration testing
	cfg := goauthx.DefaultConfig()
	cfg.Database.Driver = goauthx.Postgres
	cfg.Database.DSN = "postgres://test:test@localhost:5432/testdb?sslmode=disable"
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters"
	
	store, err := goauthx.NewStore(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	
	// Run migrations
	migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
	migrator.Up(context.Background())
	defer migrator.Down(context.Background()) // Cleanup
	
	service, _ := goauthx.NewService(cfg, store)
	
	// Test registration
	registerReq := goauthx.RegisterRequest{
		Email:    "integration@test.com",
		Password: "testpass123",
	}
	registerResp, err := service.Register(context.Background(), registerReq)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	
	// Test login
	loginReq := goauthx.LoginRequest{
		Email:    "integration@test.com",
		Password: "testpass123",
	}
	loginResp, err := service.Login(context.Background(), loginReq)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	
	// Verify tokens are different (new tokens generated on login)
	if registerResp.AccessToken == loginResp.AccessToken {
		t.Error("Expected different access tokens")
	}
}
```

## Helper Functions

### Store Tokens (Client-Side)

```go
// For web applications (cookies)
func storeTokensInCookie(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		HttpOnly: true,
		Secure:   true, // HTTPS only
		SameSite: http.SameSiteStrictMode,
		MaxAge:   15 * 60, // 15 minutes
	})
	
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})
}

// For mobile/desktop apps (secure storage)
func storeTokensSecurely(accessToken, refreshToken string) {
	// Use platform-specific secure storage
	// iOS: Keychain
	// Android: KeyStore
	// Desktop: OS-specific credential managers
}
```

These examples cover the most common use cases. For more advanced scenarios, refer to the library's GoDoc documentation and the source code in the `pkg/` directory.
