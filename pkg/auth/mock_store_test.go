package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/devchuckcamp/goauthx/pkg/store"
)

// MockStore implements the Store interface for testing
type MockStore struct {
	users              map[string]*models.User
	usersByEmail       map[string]*models.User
	refreshTokens      map[string]*models.RefreshToken
	roles              map[string]*models.Role
	rolesByName        map[string]*models.Role
	permissions        map[string]*models.Permission
	permissionsByName  map[string]*models.Permission
	userRoles          map[string][]string // userID -> roleIDs
	roleUsers          map[string][]string // roleID -> userIDs
	rolePermissions    map[string][]string // roleID -> permissionIDs
	emailVerifications map[string]*models.EmailVerification
	passwordResets     map[string]*models.PasswordReset
}

// NewMockStore creates a new mock store
func NewMockStore() *MockStore {
	return &MockStore{
		users:              make(map[string]*models.User),
		usersByEmail:       make(map[string]*models.User),
		refreshTokens:      make(map[string]*models.RefreshToken),
		roles:              make(map[string]*models.Role),
		rolesByName:        make(map[string]*models.Role),
		permissions:        make(map[string]*models.Permission),
		permissionsByName:  make(map[string]*models.Permission),
		userRoles:          make(map[string][]string),
		roleUsers:          make(map[string][]string),
		rolePermissions:    make(map[string][]string),
		emailVerifications: make(map[string]*models.EmailVerification),
		passwordResets:     make(map[string]*models.PasswordReset),
	}
}

// User operations
func (m *MockStore) CreateUser(ctx context.Context, user *models.User) error {
	if _, exists := m.usersByEmail[user.Email]; exists {
		return ErrEmailAlreadyExists
	}
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *MockStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	user, exists := m.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *MockStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, exists := m.usersByEmail[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *MockStore) UpdateUser(ctx context.Context, user *models.User) error {
	if _, exists := m.users[user.ID]; !exists {
		return ErrUserNotFound
	}
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *MockStore) DeleteUser(ctx context.Context, id string) error {
	user, exists := m.users[id]
	if !exists {
		return ErrUserNotFound
	}
	delete(m.usersByEmail, user.Email)
	delete(m.users, id)
	return nil
}

func (m *MockStore) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	var users []*models.User
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

// Role operations
func (m *MockStore) CreateRole(ctx context.Context, role *models.Role) error {
	m.roles[role.ID] = role
	m.rolesByName[role.Name] = role
	return nil
}

func (m *MockStore) GetRoleByID(ctx context.Context, id string) (*models.Role, error) {
	role, exists := m.roles[id]
	if !exists {
		return nil, fmt.Errorf("role not found")
	}
	return role, nil
}

func (m *MockStore) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	role, exists := m.rolesByName[name]
	if !exists {
		return nil, fmt.Errorf("role not found")
	}
	return role, nil
}

func (m *MockStore) ListRoles(ctx context.Context) ([]*models.Role, error) {
	var roles []*models.Role
	for _, role := range m.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

func (m *MockStore) UpdateRole(ctx context.Context, role *models.Role) error {
	if _, exists := m.roles[role.ID]; !exists {
		return fmt.Errorf("role not found")
	}
	m.roles[role.ID] = role
	m.rolesByName[role.Name] = role
	return nil
}

func (m *MockStore) DeleteRole(ctx context.Context, id string) error {
	role, exists := m.roles[id]
	if !exists {
		return fmt.Errorf("role not found")
	}
	delete(m.rolesByName, role.Name)
	delete(m.roles, id)
	return nil
}

// Permission operations
func (m *MockStore) CreatePermission(ctx context.Context, permission *models.Permission) error {
	m.permissions[permission.ID] = permission
	m.permissionsByName[permission.Name] = permission
	return nil
}

func (m *MockStore) GetPermissionByID(ctx context.Context, id string) (*models.Permission, error) {
	permission, exists := m.permissions[id]
	if !exists {
		return nil, fmt.Errorf("permission not found")
	}
	return permission, nil
}

func (m *MockStore) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	permission, exists := m.permissionsByName[name]
	if !exists {
		return nil, fmt.Errorf("permission not found")
	}
	return permission, nil
}

func (m *MockStore) GetPermissionByResourceAction(ctx context.Context, resource, action string) (*models.Permission, error) {
	for _, permission := range m.permissions {
		if permission.Resource == resource && permission.Action == action {
			return permission, nil
		}
	}
	return nil, fmt.Errorf("permission not found")
}

func (m *MockStore) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	var permissions []*models.Permission
	for _, permission := range m.permissions {
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func (m *MockStore) UpdatePermission(ctx context.Context, permission *models.Permission) error {
	if _, exists := m.permissions[permission.ID]; !exists {
		return fmt.Errorf("permission not found")
	}
	m.permissions[permission.ID] = permission
	m.permissionsByName[permission.Name] = permission
	return nil
}

func (m *MockStore) DeletePermission(ctx context.Context, id string) error {
	permission, exists := m.permissions[id]
	if !exists {
		return fmt.Errorf("permission not found")
	}
	delete(m.permissionsByName, permission.Name)
	delete(m.permissions, id)
	return nil
}

// User-Role operations
func (m *MockStore) AssignRole(ctx context.Context, userID, roleID string) error {
	m.userRoles[userID] = append(m.userRoles[userID], roleID)
	m.roleUsers[roleID] = append(m.roleUsers[roleID], userID)
	return nil
}

func (m *MockStore) RemoveRole(ctx context.Context, userID, roleID string) error {
	// Remove from userRoles
	roles := m.userRoles[userID]
	for i, id := range roles {
		if id == roleID {
			m.userRoles[userID] = append(roles[:i], roles[i+1:]...)
			break
		}
	}
	
	// Remove from roleUsers
	users := m.roleUsers[roleID]
	for i, id := range users {
		if id == userID {
			m.roleUsers[roleID] = append(users[:i], users[i+1:]...)
			break
		}
	}
	
	return nil
}

func (m *MockStore) GetUserRoles(ctx context.Context, userID string) ([]*models.Role, error) {
	roleIDs := m.userRoles[userID]
	var roles []*models.Role
	for _, roleID := range roleIDs {
		if role, exists := m.roles[roleID]; exists {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func (m *MockStore) GetRoleUsers(ctx context.Context, roleID string) ([]*models.User, error) {
	userIDs := m.roleUsers[roleID]
	var users []*models.User
	for _, userID := range userIDs {
		if user, exists := m.users[userID]; exists {
			users = append(users, user)
		}
	}
	return users, nil
}

func (m *MockStore) HasRole(ctx context.Context, userID, roleName string) (bool, error) {
	role, exists := m.rolesByName[roleName]
	if !exists {
		return false, nil
	}
	
	roleIDs := m.userRoles[userID]
	for _, roleID := range roleIDs {
		if roleID == role.ID {
			return true, nil
		}
	}
	return false, nil
}

// Role-Permission operations
func (m *MockStore) GrantPermission(ctx context.Context, roleID, permissionID string) error {
	m.rolePermissions[roleID] = append(m.rolePermissions[roleID], permissionID)
	return nil
}

func (m *MockStore) RevokePermission(ctx context.Context, roleID, permissionID string) error {
	perms := m.rolePermissions[roleID]
	for i, id := range perms {
		if id == permissionID {
			m.rolePermissions[roleID] = append(perms[:i], perms[i+1:]...)
			break
		}
	}
	return nil
}

func (m *MockStore) GetRolePermissions(ctx context.Context, roleID string) ([]*models.Permission, error) {
	permissionIDs := m.rolePermissions[roleID]
	var permissions []*models.Permission
	for _, permID := range permissionIDs {
		if perm, exists := m.permissions[permID]; exists {
			permissions = append(permissions, perm)
		}
	}
	return permissions, nil
}

func (m *MockStore) GetPermissionRoles(ctx context.Context, permissionID string) ([]*models.Role, error) {
	var roles []*models.Role
	for roleID, permIDs := range m.rolePermissions {
		for _, permID := range permIDs {
			if permID == permissionID {
				if role, exists := m.roles[roleID]; exists {
					roles = append(roles, role)
				}
				break
			}
		}
	}
	return roles, nil
}

func (m *MockStore) HasRolePermission(ctx context.Context, roleID, permissionID string) (bool, error) {
	permIDs := m.rolePermissions[roleID]
	for _, permID := range permIDs {
		if permID == permissionID {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockStore) HasPermissionByName(ctx context.Context, userID, permissionName string) (bool, error) {
	// Get user's roles
	roleIDs := m.userRoles[userID]

	// Check each role for the permission
	for _, roleID := range roleIDs {
		permIDs := m.rolePermissions[roleID]
		for _, permID := range permIDs {
			if perm, exists := m.permissions[permID]; exists {
				if perm.Name == permissionName {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Refresh token operations
func (m *MockStore) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	m.refreshTokens[token.Token] = token
	return nil
}

func (m *MockStore) GetRefreshTokenByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	rt, exists := m.refreshTokens[token]
	if !exists {
		return nil, ErrInvalidRefreshToken
	}
	return rt, nil
}

func (m *MockStore) GetRefreshTokensByUserID(ctx context.Context, userID string) ([]*models.RefreshToken, error) {
	var tokens []*models.RefreshToken
	for _, token := range m.refreshTokens {
		if token.UserID == userID {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

func (m *MockStore) RevokeRefreshToken(ctx context.Context, token string) error {
	rt, exists := m.refreshTokens[token]
	if !exists {
		return ErrInvalidRefreshToken
	}
	now := time.Now()
	rt.RevokedAt = &now
	return nil
}

func (m *MockStore) RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error {
	now := time.Now()
	for _, token := range m.refreshTokens {
		if token.UserID == userID && token.RevokedAt == nil {
			token.RevokedAt = &now
		}
	}
	return nil
}

func (m *MockStore) DeleteExpiredRefreshTokens(ctx context.Context) error {
	for token, rt := range m.refreshTokens {
		if rt.IsExpired() {
			delete(m.refreshTokens, token)
		}
	}
	return nil
}

// Email verification operations
func (m *MockStore) CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error {
	m.emailVerifications[verification.Token] = verification
	return nil
}

func (m *MockStore) GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error) {
	ev, exists := m.emailVerifications[token]
	if !exists {
		return nil, fmt.Errorf("email verification not found")
	}
	return ev, nil
}

func (m *MockStore) MarkEmailVerificationUsed(ctx context.Context, id string) error {
	for _, ev := range m.emailVerifications {
		if ev.ID == id {
			now := time.Now()
			ev.UsedAt = &now
			return nil
		}
	}
	return fmt.Errorf("email verification not found")
}

func (m *MockStore) DeleteExpiredEmailVerifications(ctx context.Context) error {
	for token, ev := range m.emailVerifications {
		if ev.IsExpired() {
			delete(m.emailVerifications, token)
		}
	}
	return nil
}

// Password reset operations
func (m *MockStore) CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error {
	m.passwordResets[reset.Token] = reset
	return nil
}

func (m *MockStore) GetPasswordResetByToken(ctx context.Context, token string) (*models.PasswordReset, error) {
	pr, exists := m.passwordResets[token]
	if !exists {
		return nil, fmt.Errorf("password reset not found")
	}
	return pr, nil
}

func (m *MockStore) MarkPasswordResetUsed(ctx context.Context, id string) error {
	for _, pr := range m.passwordResets {
		if pr.ID == id {
			now := time.Now()
			pr.UsedAt = &now
			return nil
		}
	}
	return fmt.Errorf("password reset not found")
}

func (m *MockStore) DeleteExpiredPasswordResets(ctx context.Context) error {
	for token, pr := range m.passwordResets {
		if pr.IsExpired() {
			delete(m.passwordResets, token)
		}
	}
	return nil
}

// Stub implementations for OAuth operations (to be overridden in tests)
func (m *MockStore) CreateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	return fmt.Errorf("not implemented in base mock store")
}

func (m *MockStore) GetOAuthAccountByProviderID(ctx context.Context, provider models.OAuthProvider, providerID string) (*models.OAuthAccount, error) {
	return nil, fmt.Errorf("not implemented in base mock store")
}

func (m *MockStore) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*models.OAuthAccount, error) {
	return nil, fmt.Errorf("not implemented in base mock store")
}

func (m *MockStore) UpdateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	return fmt.Errorf("not implemented in base mock store")
}

func (m *MockStore) DeleteOAuthAccount(ctx context.Context, id string) error {
	return fmt.Errorf("not implemented in base mock store")
}

// Transaction operations
func (m *MockStore) BeginTx(ctx context.Context) (store.Store, error) {
	return m, nil
}

func (m *MockStore) Commit() error {
	return nil
}

func (m *MockStore) Rollback() error {
	return nil
}

// Connection operations
func (m *MockStore) Close() error {
	return nil
}

func (m *MockStore) DB() *sql.DB {
	return nil
}

// Verify MockStore implements store.Store interface
var _ store.Store = (*MockStore)(nil)
