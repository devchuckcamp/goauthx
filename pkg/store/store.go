package store

import (
	"context"
	"database/sql"

	"github.com/devchuckcamp/goauthx/pkg/models"
)

// UserStore defines the interface for user data operations
type UserStore interface {
	// Create creates a new user
	Create(ctx context.Context, user *models.User) error

	// GetByID retrieves a user by their ID
	GetByID(ctx context.Context, id string) (*models.User, error)

	// GetByEmail retrieves a user by their email address
	GetByEmail(ctx context.Context, email string) (*models.User, error)

	// Update updates an existing user
	Update(ctx context.Context, user *models.User) error

	// Delete deletes a user (soft delete by setting Active = false)
	Delete(ctx context.Context, id string) error

	// List retrieves all users with pagination
	List(ctx context.Context, limit, offset int) ([]*models.User, error)
}

// RoleStore defines the interface for role data operations
type RoleStore interface {
	// Create creates a new role
	Create(ctx context.Context, role *models.Role) error

	// GetByID retrieves a role by its ID
	GetByID(ctx context.Context, id string) (*models.Role, error)

	// GetByName retrieves a role by its name
	GetByName(ctx context.Context, name string) (*models.Role, error)

	// List retrieves all roles
	List(ctx context.Context) ([]*models.Role, error)

	// Update updates an existing role
	Update(ctx context.Context, role *models.Role) error

	// Delete deletes a role
	Delete(ctx context.Context, id string) error
}

// PermissionStore defines the interface for permission data operations
type PermissionStore interface {
	// Create creates a new permission
	Create(ctx context.Context, permission *models.Permission) error

	// GetByID retrieves a permission by its ID
	GetByID(ctx context.Context, id string) (*models.Permission, error)

	// GetByName retrieves a permission by its name
	GetByName(ctx context.Context, name string) (*models.Permission, error)

	// GetByResourceAction retrieves a permission by resource and action
	GetByResourceAction(ctx context.Context, resource, action string) (*models.Permission, error)

	// List retrieves all permissions
	List(ctx context.Context) ([]*models.Permission, error)

	// Update updates an existing permission
	Update(ctx context.Context, permission *models.Permission) error

	// Delete deletes a permission
	Delete(ctx context.Context, id string) error
}

// UserRoleStore defines the interface for user-role relationship operations
type UserRoleStore interface {
	// AssignRole assigns a role to a user
	AssignRole(ctx context.Context, userID, roleID string) error

	// RemoveRole removes a role from a user
	RemoveRole(ctx context.Context, userID, roleID string) error

	// GetUserRoles retrieves all roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]*models.Role, error)

	// GetRoleUsers retrieves all users with a specific role
	GetRoleUsers(ctx context.Context, roleID string) ([]*models.User, error)

	// HasRole checks if a user has a specific role
	HasRole(ctx context.Context, userID, roleName string) (bool, error)
}

// RolePermissionStore defines the interface for role-permission relationship operations
type RolePermissionStore interface {
	// GrantPermission grants a permission to a role
	GrantPermission(ctx context.Context, roleID, permissionID string) error

	// RevokePermission revokes a permission from a role
	RevokePermission(ctx context.Context, roleID, permissionID string) error

	// GetRolePermissions retrieves all permissions for a role
	GetRolePermissions(ctx context.Context, roleID string) ([]*models.Permission, error)

	// GetPermissionRoles retrieves all roles that have a specific permission
	GetPermissionRoles(ctx context.Context, permissionID string) ([]*models.Role, error)

	// HasPermission checks if a role has a specific permission
	HasPermission(ctx context.Context, roleID, permissionID string) (bool, error)
}

// UserPermissionStore defines optional operations for user-permission relationships.
//
// This is intentionally NOT embedded into the main Store interface to avoid
// breaking existing consumers with custom Store implementations.
//
// Implementations may use this to support granting additional permissions
// directly to a user (beyond role-based defaults).
type UserPermissionStore interface {
	// GrantUserPermission grants a permission directly to a user
	GrantUserPermission(ctx context.Context, userID, permissionID string) error

	// RevokeUserPermission revokes a directly-granted permission from a user
	RevokeUserPermission(ctx context.Context, userID, permissionID string) error

	// GetUserDirectPermissions retrieves permissions granted directly to a user
	GetUserDirectPermissions(ctx context.Context, userID string) ([]*models.Permission, error)
}

// RefreshTokenStore defines the interface for refresh token operations
type RefreshTokenStore interface {
	// Create creates a new refresh token
	Create(ctx context.Context, token *models.RefreshToken) error

	// GetByToken retrieves a refresh token by its token string
	GetByToken(ctx context.Context, token string) (*models.RefreshToken, error)

	// GetByUserID retrieves all refresh tokens for a user
	GetByUserID(ctx context.Context, userID string) ([]*models.RefreshToken, error)

	// Revoke revokes a refresh token
	Revoke(ctx context.Context, token string) error

	// RevokeAllForUser revokes all refresh tokens for a user
	RevokeAllForUser(ctx context.Context, userID string) error

	// DeleteExpired deletes all expired refresh tokens
	DeleteExpired(ctx context.Context) error
}

// Store aggregates all store interfaces
type Store interface {
	// User operations
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error)

	// Role operations
	CreateRole(ctx context.Context, role *models.Role) error
	GetRoleByID(ctx context.Context, id string) (*models.Role, error)
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
	ListRoles(ctx context.Context) ([]*models.Role, error)
	UpdateRole(ctx context.Context, role *models.Role) error
	DeleteRole(ctx context.Context, id string) error

	// Permission operations
	CreatePermission(ctx context.Context, permission *models.Permission) error
	GetPermissionByID(ctx context.Context, id string) (*models.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*models.Permission, error)
	GetPermissionByResourceAction(ctx context.Context, resource, action string) (*models.Permission, error)
	ListPermissions(ctx context.Context) ([]*models.Permission, error)
	UpdatePermission(ctx context.Context, permission *models.Permission) error
	DeletePermission(ctx context.Context, id string) error

	// User-Role operations
	AssignRole(ctx context.Context, userID, roleID string) error
	RemoveRole(ctx context.Context, userID, roleID string) error
	GetUserRoles(ctx context.Context, userID string) ([]*models.Role, error)
	GetRoleUsers(ctx context.Context, roleID string) ([]*models.User, error)
	HasRole(ctx context.Context, userID, roleName string) (bool, error)

	// Role-Permission operations
	GrantPermission(ctx context.Context, roleID, permissionID string) error
	RevokePermission(ctx context.Context, roleID, permissionID string) error
	GetRolePermissions(ctx context.Context, roleID string) ([]*models.Permission, error)
	GetPermissionRoles(ctx context.Context, permissionID string) ([]*models.Role, error)
	HasRolePermission(ctx context.Context, roleID, permissionID string) (bool, error)
	HasPermissionByName(ctx context.Context, userID, permissionName string) (bool, error)

	// Refresh token operations
	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshTokenByToken(ctx context.Context, token string) (*models.RefreshToken, error)
	GetRefreshTokensByUserID(ctx context.Context, userID string) ([]*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error
	DeleteExpiredRefreshTokens(ctx context.Context) error

	// Email verification operations
	CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error
	GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id string) error
	DeleteExpiredEmailVerifications(ctx context.Context) error

	// Password reset operations
	CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error
	GetPasswordResetByToken(ctx context.Context, token string) (*models.PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id string) error
	DeleteExpiredPasswordResets(ctx context.Context) error

	// OAuth account operations
	CreateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error
	GetOAuthAccountByProviderID(ctx context.Context, provider models.OAuthProvider, providerID string) (*models.OAuthAccount, error)
	GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*models.OAuthAccount, error)
	UpdateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error
	DeleteOAuthAccount(ctx context.Context, id string) error

	// Transaction operations
	BeginTx(ctx context.Context) (Store, error)
	Commit() error
	Rollback() error

	// Connection operations
	Close() error
	DB() *sql.DB
}
