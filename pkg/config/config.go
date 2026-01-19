package config

import (
	"fmt"
	"time"
)

// DatabaseDriver represents supported database drivers
type DatabaseDriver string

const (
	// MySQL driver
	MySQL DatabaseDriver = "mysql"
	// Postgres driver
	Postgres DatabaseDriver = "postgres"
	// SQLServer driver
	SQLServer DatabaseDriver = "sqlserver"
)

// Config holds the configuration for the auth library
type Config struct {
	// Database configuration
	Database DatabaseConfig

	// JWT configuration
	JWT JWTConfig

	// Password configuration
	Password PasswordConfig

	// Token configuration
	Token TokenConfig

	// OAuth configuration (optional)
	OAuth OAuthConfig
}

// OAuthConfig holds OAuth provider settings
type OAuthConfig struct {
	// Google OAuth settings
	Google GoogleOAuthConfig
}

// GoogleOAuthConfig holds Google OAuth2 settings
type GoogleOAuthConfig struct {
	//  is the OAuth2 client ID from Google
	ClientID string

	// ClientSecret is the OAuth2 client secret from Google
	ClientSecret string

	// RedirectURL is the callback URL after OAuth authentication
	RedirectURL string

	// Enabled indicates if Google OAuth is enabled
	Enabled bool
}

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	// Driver specifies the database driver (mysql, postgres, sqlserver)
	Driver DatabaseDriver

	// DSN is the data source name (connection string)
	DSN string

	// MaxOpenConns sets the maximum number of open connections to the database
	MaxOpenConns int

	// MaxIdleConns sets the maximum number of connections in the idle connection pool
	MaxIdleConns int

	// ConnMaxLifetime sets the maximum amount of time a connection may be reused
	ConnMaxLifetime time.Duration
}

// JWTConfig holds JWT token settings
type JWTConfig struct {
	// Secret is the secret key used to sign JWT tokens
	Secret string

	// AccessTokenExpiry is the duration for which access tokens are valid
	AccessTokenExpiry time.Duration

	// Issuer is the issuer claim for JWT tokens
	Issuer string

	// Audience is the audience claim for JWT tokens
	Audience string
}

// PasswordConfig holds password hashing settings
type PasswordConfig struct {
	// MinLength is the minimum password length
	MinLength int

	// BcryptCost is the cost parameter for bcrypt (4-31, default 12)
	BcryptCost int
}

// TokenConfig holds refresh token settings
type TokenConfig struct {
	// RefreshTokenExpiry is the duration for which refresh tokens are valid
	RefreshTokenExpiry time.Duration

	// RefreshTokenLength is the length of the random refresh token string
	RefreshTokenLength int
}

// RouteConfig holds HTTP route configuration
type RouteConfig struct {
	// RegisterPath is the path for user registration endpoint
	RegisterPath string

	// LoginPath is the path for user login endpoint
	LoginPath string

	// LogoutPath is the path for user logout endpoint
	LogoutPath string

	// RefreshPath is the path for token refresh endpoint
	RefreshPath string

	// ProfilePath is the path for user profile endpoint
	ProfilePath string

	// ChangePasswordPath is the path for changing password endpoint
	ChangePasswordPath string

	// RequestPasswordResetPath is the path for requesting password reset
	RequestPasswordResetPath string

	// ResetPasswordPath is the path for resetting password with token
	ResetPasswordPath string

	// VerifyEmailPath is the path for email verification endpoint
	VerifyEmailPath string

	// ResendVerificationPath is the path for resending verification email
	ResendVerificationPath string

	// GoogleOAuthPath is the path for initiating Google OAuth login
	GoogleOAuthPath string

	// GoogleOAuthCallbackPath is the path for Google OAuth callback
	GoogleOAuthCallbackPath string

	// UnlinkGoogleOAuthPath is the path for unlinking Google OAuth account
	UnlinkGoogleOAuthPath string
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if err := c.Database.Validate(); err != nil {
		return fmt.Errorf("database config: %w", err)
	}

	if err := c.JWT.Validate(); err != nil {
		return fmt.Errorf("jwt config: %w", err)
	}

	if err := c.Password.Validate(); err != nil {
		return fmt.Errorf("password config: %w", err)
	}

	if err := c.Token.Validate(); err != nil {
		return fmt.Errorf("token config: %w", err)
	}

	return nil
}

// Validate validates database configuration
func (dc *DatabaseConfig) Validate() error {
	if dc.Driver != MySQL && dc.Driver != Postgres && dc.Driver != SQLServer {
		return fmt.Errorf("invalid database driver: %s (must be mysql, postgres, or sqlserver)", dc.Driver)
	}

	if dc.DSN == "" {
		return fmt.Errorf("database DSN is required")
	}

	return nil
}

// Validate validates JWT configuration
func (jc *JWTConfig) Validate() error {
	if jc.Secret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if len(jc.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters")
	}

	if jc.AccessTokenExpiry <= 0 {
		return fmt.Errorf("access token expiry must be positive")
	}

	return nil
}

// Validate validates password configuration
func (pc *PasswordConfig) Validate() error {
	if pc.MinLength < 8 {
		return fmt.Errorf("minimum password length must be at least 8")
	}

	if pc.BcryptCost < 4 || pc.BcryptCost > 31 {
		return fmt.Errorf("bcrypt cost must be between 4 and 31")
	}

	return nil
}

// Validate validates token configuration
func (tc *TokenConfig) Validate() error {
	if tc.RefreshTokenExpiry <= 0 {
		return fmt.Errorf("refresh token expiry must be positive")
	}

	if tc.RefreshTokenLength < 32 {
		return fmt.Errorf("refresh token length must be at least 32")
	}

	return nil
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		JWT: JWTConfig{
			AccessTokenExpiry: 15 * time.Minute,
			Issuer:            "goauthx",
			Audience:          "goauthx-users",
		},
		Password: PasswordConfig{
			MinLength:  8,
			BcryptCost: 12,
		},
		Token: TokenConfig{
			RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
			RefreshTokenLength: 64,
		},
	}
}

// DefaultRouteConfig returns route configuration with sensible defaults
func DefaultRouteConfig() *RouteConfig {
	return &RouteConfig{
		RegisterPath:             "/auth/register",
		LoginPath:                "/auth/login",
		LogoutPath:               "/auth/logout",
		RefreshPath:              "/auth/refresh",
		ProfilePath:              "/auth/profile",
		ChangePasswordPath:       "/auth/change-password",
		RequestPasswordResetPath: "/auth/forgot-password",
		ResetPasswordPath:        "/auth/reset-password",
		VerifyEmailPath:          "/auth/verify-email",
		ResendVerificationPath:   "/auth/resend-verification",
		GoogleOAuthPath:          "/auth/google",
		GoogleOAuthCallbackPath:  "/auth/google/callback",
		UnlinkGoogleOAuthPath:    "/auth/google/unlink",
	}
}
