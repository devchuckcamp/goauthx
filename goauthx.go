// Package goauthx provides a comprehensive authentication and authorization library for Go
package goauthx

import (
	"github.com/devchuckcamp/goauthx/pkg/auth"
	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/handlers"
	"github.com/devchuckcamp/goauthx/pkg/middleware"
	"github.com/devchuckcamp/goauthx/pkg/migrations"
	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/devchuckcamp/goauthx/pkg/store"
	"github.com/devchuckcamp/goauthx/pkg/store/sqlstore"
)

// Re-export commonly used types for convenience
type (
	Config                      = config.Config
	DatabaseConfig              = config.DatabaseConfig
	JWTConfig                   = config.JWTConfig
	PasswordConfig              = config.PasswordConfig
	TokenConfig                 = config.TokenConfig
	RouteConfig                 = config.RouteConfig
	DatabaseDriver              = config.DatabaseDriver
	OAuthConfig                 = config.OAuthConfig
	GoogleOAuthConfig           = config.GoogleOAuthConfig
	
	User                        = models.User
	Role                        = models.Role
	Permission                  = models.Permission
	RefreshToken                = models.RefreshToken
	EmailVerification           = models.EmailVerification
	PasswordReset               = models.PasswordReset
	OAuthAccount                = models.OAuthAccount
	OAuthProvider               = models.OAuthProvider
	GoogleUserInfo              = models.GoogleUserInfo
	
	Service                     = auth.Service
	RegisterRequest             = auth.RegisterRequest
	LoginRequest                = auth.LoginRequest
	AuthResponse                = auth.AuthResponse
	RefreshTokenRequest         = auth.RefreshTokenRequest
	ChangePasswordRequest       = auth.ChangePasswordRequest
	RequestPasswordResetRequest = auth.RequestPasswordResetRequest
	ResetPasswordRequest        = auth.ResetPasswordRequest
	VerifyEmailRequest          = auth.VerifyEmailRequest
	GoogleOAuthURLRequest       = auth.GoogleOAuthURLRequest
	GoogleOAuthCallbackRequest  = auth.GoogleOAuthCallbackRequest
	
	AuthMiddleware              = middleware.AuthMiddleware
	ContextKey                  = middleware.ContextKey
	
	Handlers                    = handlers.Handlers
	
	Store                       = store.Store
	Migrator                    = migrations.Migrator
)

// Database drivers
const (
	MySQL      = config.MySQL
	Postgres   = config.Postgres
	SQLServer  = config.SQLServer
)

// OAuth providers
const (
	OAuthProviderGoogle = models.OAuthProviderGoogle
)

// Context keys
const (
	UserIDKey    = middleware.UserIDKey
	UserEmailKey = middleware.UserEmailKey
	UserRolesKey = middleware.UserRolesKey
	ClaimsKey    = middleware.ClaimsKey
)

// Common errors
var (
	ErrInvalidCredentials = auth.ErrInvalidCredentials
	ErrUserNotFound       = auth.ErrUserNotFound
	ErrUserInactive       = auth.ErrUserInactive
	ErrEmailAlreadyExists = auth.ErrEmailAlreadyExists
	ErrInvalidRefreshToken = auth.ErrInvalidRefreshToken
	ErrPermissionDenied   = auth.ErrPermissionDenied
)

// NewService creates a new authentication service
func NewService(cfg *Config, store Store) (*Service, error) {
	return auth.NewService(cfg, store)
}

// NewStore creates a new SQL store
func NewStore(cfg DatabaseConfig) (Store, error) {
	return sqlstore.New(cfg)
}

// NewMigrator creates a new migrator
func NewMigrator(store Store, driver DatabaseDriver) *Migrator {
	return migrations.NewMigrator(store.DB(), driver)
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(service *Service) *AuthMiddleware {
	return middleware.NewAuthMiddleware(service)
}

// NewHandlers creates new HTTP handlers
func NewHandlers(service *Service, routeConfig *RouteConfig) *Handlers {
	return handlers.NewHandlers(service, routeConfig)
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return config.DefaultConfig()
}

// DefaultRouteConfig returns route configuration with sensible defaults
func DefaultRouteConfig() *RouteConfig {
	return config.DefaultRouteConfig()
}

// Helper functions from middleware package
var (
	GetUserID    = middleware.GetUserID
	GetUserEmail = middleware.GetUserEmail
	GetUserRoles = middleware.GetUserRoles
	GetClaims    = middleware.GetClaims
	Chain        = middleware.Chain
)
