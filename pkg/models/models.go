package models

import "time"

// User represents an authenticated user in the system
type User struct {
	ID            string     `json:"id" db:"id"`
	Email         string     `json:"email" db:"email"`
	PasswordHash  string     `json:"-" db:"password_hash"`
	FirstName     string     `json:"first_name,omitempty" db:"first_name"`
	LastName      string     `json:"last_name,omitempty" db:"last_name"`
	Active        bool       `json:"active" db:"active"`
	EmailVerified bool       `json:"email_verified" db:"email_verified"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// Role represents a role that can be assigned to users
type Role struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Permission represents a specific permission that can be granted
type Permission struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Resource    string    `json:"resource" db:"resource"`
	Action      string    `json:"action" db:"action"`
	Description string    `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// UserRole represents the many-to-many relationship between users and roles
type UserRole struct {
	UserID     string    `json:"user_id" db:"user_id"`
	RoleID     string    `json:"role_id" db:"role_id"`
	AssignedAt time.Time `json:"assigned_at" db:"assigned_at"`
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	RoleID       string    `json:"role_id" db:"role_id"`
	PermissionID string    `json:"permission_id" db:"permission_id"`
	GrantedAt    time.Time `json:"granted_at" db:"granted_at"`
}

// RefreshToken represents a refresh token for maintaining sessions
type RefreshToken struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// IsRevoked checks if the refresh token has been revoked
func (rt *RefreshToken) IsRevoked() bool {
	return rt.RevokedAt != nil
}

// IsExpired checks if the refresh token has expired
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsValid checks if the refresh token is valid (not revoked and not expired)
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsRevoked() && !rt.IsExpired()
}

// EmailVerification represents an email verification token
type EmailVerification struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
}

// IsUsed checks if the verification token has been used
func (ev *EmailVerification) IsUsed() bool {
	return ev.UsedAt != nil
}

// IsExpired checks if the verification token has expired
func (ev *EmailVerification) IsExpired() bool {
	return time.Now().After(ev.ExpiresAt)
}

// IsValid checks if the verification token is valid (not used and not expired)
func (ev *EmailVerification) IsValid() bool {
	return !ev.IsUsed() && !ev.IsExpired()
}

// PasswordReset represents a password reset token
type PasswordReset struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
}

// IsUsed checks if the password reset token has been used
func (pr *PasswordReset) IsUsed() bool {
	return pr.UsedAt != nil
}

// IsExpired checks if the password reset token has expired
func (pr *PasswordReset) IsExpired() bool {
	return time.Now().After(pr.ExpiresAt)
}

// IsValid checks if the password reset token is valid (not used and not expired)
func (pr *PasswordReset) IsValid() bool {
	return !pr.IsUsed() && !pr.IsExpired()
}

// OAuthProvider represents the OAuth provider type
type OAuthProvider string

const (
	// OAuthProviderGoogle represents Google OAuth
	OAuthProviderGoogle OAuthProvider = "google"
)

// OAuthAccount represents a user's OAuth account linkage
type OAuthAccount struct {
	ID           string        `json:"id" db:"id"`
	UserID       string        `json:"user_id" db:"user_id"`
	Provider     OAuthProvider `json:"provider" db:"provider"`
	ProviderID   string        `json:"provider_id" db:"provider_id"`
	Email        string        `json:"email" db:"email"`
	Name         string        `json:"name,omitempty" db:"name"`
	Picture      string        `json:"picture,omitempty" db:"picture"`
	AccessToken  string        `json:"-" db:"access_token"`
	RefreshToken string        `json:"-" db:"refresh_token"`
	ExpiresAt    *time.Time    `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt    time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at" db:"updated_at"`
}

// GoogleUserInfo represents user information from Google OAuth
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}
