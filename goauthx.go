// Package goauthx provides a comprehensive authentication and authorization library for Go
package goauthx

import (
	"github.com/devchuckcamp/goauthx/pkg/auth"
	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/handlers"
	"github.com/devchuckcamp/goauthx/pkg/middleware"
	"github.com/devchuckcamp/goauthx/pkg/migrations"
	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/devchuckcamp/goauthx/pkg/rbac"
	"github.com/devchuckcamp/goauthx/pkg/store"
	"github.com/devchuckcamp/goauthx/pkg/store/sqlstore"
)

// Re-export commonly used types for convenience
type (
	Config            = config.Config
	DatabaseConfig    = config.DatabaseConfig
	JWTConfig         = config.JWTConfig
	PasswordConfig    = config.PasswordConfig
	TokenConfig       = config.TokenConfig
	RouteConfig       = config.RouteConfig
	DatabaseDriver    = config.DatabaseDriver
	OAuthConfig       = config.OAuthConfig
	GoogleOAuthConfig = config.GoogleOAuthConfig
	AdminRouteConfig  = config.AdminRouteConfig

	User              = models.User
	Role              = models.Role
	Permission        = models.Permission
	RefreshToken      = models.RefreshToken
	EmailVerification = models.EmailVerification
	PasswordReset     = models.PasswordReset
	OAuthAccount      = models.OAuthAccount
	OAuthProvider     = models.OAuthProvider
	GoogleUserInfo    = models.GoogleUserInfo

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

	AuthMiddleware = middleware.AuthMiddleware
	ContextKey     = middleware.ContextKey

	Handlers      = handlers.Handlers
	AdminHandlers = handlers.AdminHandlers

	Store    = store.Store
	Migrator = migrations.Migrator

	// RBAC types
	RoleName             = rbac.RoleName
	PermissionName       = rbac.PermissionName
	RoleDefinition       = rbac.RoleDefinition
	PermissionDefinition = rbac.PermissionDefinition
	Seeder               = rbac.Seeder
)

// Database drivers
const (
	MySQL     = config.MySQL
	Postgres  = config.Postgres
	SQLServer = config.SQLServer
)

// OAuth providers
const (
	OAuthProviderGoogle = models.OAuthProviderGoogle
)

// RBAC Role constants
const (
	RoleAdmin              = rbac.RoleAdmin
	RoleManager            = rbac.RoleManager
	RoleCustomerExperience = rbac.RoleCustomerExperience
	RoleCustomer           = rbac.RoleCustomer
)

// RBAC Permission constants - Product
const (
	PermProductCreate = rbac.PermProductCreate
	PermProductRead   = rbac.PermProductRead
	PermProductUpdate = rbac.PermProductUpdate
	PermProductDelete = rbac.PermProductDelete
)

// RBAC Permission constants - Order
const (
	PermOrderCreate  = rbac.PermOrderCreate
	PermOrderRead    = rbac.PermOrderRead
	PermOrderUpdate  = rbac.PermOrderUpdate
	PermOrderProcess = rbac.PermOrderProcess
)

// RBAC Permission constants - User
const (
	PermUserCreate    = rbac.PermUserCreate
	PermUserRead      = rbac.PermUserRead
	PermUserUpdate    = rbac.PermUserUpdate
	PermUserDelete    = rbac.PermUserDelete
	PermUserUpdateOwn = rbac.PermUserUpdateOwn
)

// RBAC Permission constants - Report
const (
	PermReportView = rbac.PermReportView
)

// RBAC Permission constants - Customer Support
const (
	PermCustomerView         = rbac.PermCustomerView
	PermCustomerOrderHistory = rbac.PermCustomerOrderHistory
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
	ErrInvalidCredentials  = auth.ErrInvalidCredentials
	ErrUserNotFound        = auth.ErrUserNotFound
	ErrUserInactive        = auth.ErrUserInactive
	ErrEmailAlreadyExists  = auth.ErrEmailAlreadyExists
	ErrInvalidRefreshToken = auth.ErrInvalidRefreshToken
	ErrPermissionDenied    = auth.ErrPermissionDenied
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

// DefaultAdminRouteConfig returns admin route configuration with sensible defaults
func DefaultAdminRouteConfig() *AdminRouteConfig {
	return config.DefaultAdminRouteConfig()
}

// NewSeeder creates a new RBAC seeder
func NewSeeder(store Store) *Seeder {
	return rbac.NewSeeder(store)
}

// NewAdminHandlers creates new admin HTTP handlers
func NewAdminHandlers(service *Service, store Store, cfg *handlers.AdminHandlersConfig) *AdminHandlers {
	return handlers.NewAdminHandlers(service, store, cfg)
}

// RBAC helper functions
var (
	DefaultRoles            = rbac.DefaultRoles
	DefaultPermissions      = rbac.DefaultPermissions
	DefaultRolePermissions  = rbac.DefaultRolePermissions
	AllRoleNames            = rbac.AllRoleNames
	AllPermissionNames      = rbac.AllPermissionNames
	IsValidRoleName         = rbac.IsValidRoleName
	IsValidPermissionName   = rbac.IsValidPermissionName
	GetRoleDescription      = rbac.GetRoleDescription
	GetPermissionDefinition = rbac.GetPermissionDefinition
	DefaultRole             = rbac.DefaultRole
)

// Helper functions from middleware package
var (
	GetUserID    = middleware.GetUserID
	GetUserEmail = middleware.GetUserEmail
	GetUserRoles = middleware.GetUserRoles
	GetClaims    = middleware.GetClaims
	Chain        = middleware.Chain
)
