package rbac

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/devchuckcamp/goauthx/pkg/store"
)

// MockStore implements the Store interface for testing
type MockStore struct {
	users             map[string]*models.User
	roles             map[string]*models.Role
	rolesByName       map[string]*models.Role
	permissions       map[string]*models.Permission
	permissionsByName map[string]*models.Permission
	userRoles         map[string][]string // userID -> roleIDs
	rolePermissions   map[string][]string // roleID -> permissionIDs
}

// NewMockStore creates a new mock store
func NewMockStore() *MockStore {
	return &MockStore{
		users:             make(map[string]*models.User),
		roles:             make(map[string]*models.Role),
		rolesByName:       make(map[string]*models.Role),
		permissions:       make(map[string]*models.Permission),
		permissionsByName: make(map[string]*models.Permission),
		userRoles:         make(map[string][]string),
		rolePermissions:   make(map[string][]string),
	}
}

// User operations
func (m *MockStore) CreateUser(ctx context.Context, user *models.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *MockStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	user, exists := m.users[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func (m *MockStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockStore) UpdateUser(ctx context.Context, user *models.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *MockStore) DeleteUser(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}

func (m *MockStore) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	var users []*models.User
	i := 0
	for _, user := range m.users {
		if i >= offset && len(users) < limit {
			users = append(users, user)
		}
		i++
	}
	return users, nil
}

// Role operations
func (m *MockStore) CreateRole(ctx context.Context, role *models.Role) error {
	if role.ID == "" {
		role.ID = fmt.Sprintf("role-%d", len(m.roles)+1)
	}
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
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
	m.roles[role.ID] = role
	m.rolesByName[role.Name] = role
	return nil
}

func (m *MockStore) DeleteRole(ctx context.Context, id string) error {
	role := m.roles[id]
	if role != nil {
		delete(m.rolesByName, role.Name)
	}
	delete(m.roles, id)
	return nil
}

// Permission operations
func (m *MockStore) CreatePermission(ctx context.Context, permission *models.Permission) error {
	if permission.ID == "" {
		permission.ID = fmt.Sprintf("perm-%d", len(m.permissions)+1)
	}
	permission.CreatedAt = time.Now()
	permission.UpdatedAt = time.Now()
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
	m.permissions[permission.ID] = permission
	m.permissionsByName[permission.Name] = permission
	return nil
}

func (m *MockStore) DeletePermission(ctx context.Context, id string) error {
	permission := m.permissions[id]
	if permission != nil {
		delete(m.permissionsByName, permission.Name)
	}
	delete(m.permissions, id)
	return nil
}

// User-Role operations
func (m *MockStore) AssignRole(ctx context.Context, userID, roleID string) error {
	m.userRoles[userID] = append(m.userRoles[userID], roleID)
	return nil
}

func (m *MockStore) RemoveRole(ctx context.Context, userID, roleID string) error {
	roles := m.userRoles[userID]
	for i, id := range roles {
		if id == roleID {
			m.userRoles[userID] = append(roles[:i], roles[i+1:]...)
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
	var users []*models.User
	for userID, roleIDs := range m.userRoles {
		for _, id := range roleIDs {
			if id == roleID {
				if user, exists := m.users[userID]; exists {
					users = append(users, user)
				}
				break
			}
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
	permIDs := m.rolePermissions[roleID]
	var permissions []*models.Permission
	for _, permID := range permIDs {
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
	for _, id := range permIDs {
		if id == permissionID {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockStore) HasPermissionByName(ctx context.Context, userID, permissionName string) (bool, error) {
	roleIDs := m.userRoles[userID]
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

// Stub implementations for remaining interface methods
func (m *MockStore) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return nil
}
func (m *MockStore) GetRefreshTokenByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockStore) GetRefreshTokensByUserID(ctx context.Context, userID string) ([]*models.RefreshToken, error) {
	return nil, nil
}
func (m *MockStore) RevokeRefreshToken(ctx context.Context, token string) error { return nil }
func (m *MockStore) RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error {
	return nil
}
func (m *MockStore) DeleteExpiredRefreshTokens(ctx context.Context) error { return nil }

func (m *MockStore) CreateEmailVerification(ctx context.Context, v *models.EmailVerification) error {
	return nil
}
func (m *MockStore) GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockStore) MarkEmailVerificationUsed(ctx context.Context, id string) error { return nil }
func (m *MockStore) DeleteExpiredEmailVerifications(ctx context.Context) error      { return nil }

func (m *MockStore) CreatePasswordReset(ctx context.Context, r *models.PasswordReset) error {
	return nil
}
func (m *MockStore) GetPasswordResetByToken(ctx context.Context, token string) (*models.PasswordReset, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockStore) MarkPasswordResetUsed(ctx context.Context, id string) error { return nil }
func (m *MockStore) DeleteExpiredPasswordResets(ctx context.Context) error      { return nil }

func (m *MockStore) CreateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	return nil
}
func (m *MockStore) GetOAuthAccountByProviderID(ctx context.Context, provider models.OAuthProvider, providerID string) (*models.OAuthAccount, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockStore) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*models.OAuthAccount, error) {
	return nil, nil
}
func (m *MockStore) UpdateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	return nil
}
func (m *MockStore) DeleteOAuthAccount(ctx context.Context, id string) error { return nil }

func (m *MockStore) BeginTx(ctx context.Context) (store.Store, error) { return m, nil }
func (m *MockStore) Commit() error                                    { return nil }
func (m *MockStore) Rollback() error                                  { return nil }
func (m *MockStore) Close() error                                     { return nil }
func (m *MockStore) DB() *sql.DB                                      { return nil }

// Verify MockStore implements store.Store interface
var _ store.Store = (*MockStore)(nil)

// Tests

func TestNewSeeder(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)

	if seeder == nil {
		t.Fatal("NewSeeder returned nil")
	}
	if seeder.store != mockStore {
		t.Error("Seeder store not set correctly")
	}
}

func TestSeedRoles(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	err := seeder.SeedRoles(ctx)
	if err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}

	// Verify all roles were created
	expectedRoles := []string{"admin", "manager", "customer_experience", "customer"}
	for _, roleName := range expectedRoles {
		role, err := mockStore.GetRoleByName(ctx, roleName)
		if err != nil {
			t.Errorf("Role %s not found: %v", roleName, err)
			continue
		}
		if role.Description == "" {
			t.Errorf("Role %s has empty description", roleName)
		}
	}
}

func TestSeedRoles_Idempotent(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// Seed twice
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("First SeedRoles failed: %v", err)
	}
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("Second SeedRoles failed: %v", err)
	}

	// Should still have only 4 roles
	roles, _ := mockStore.ListRoles(ctx)
	if len(roles) != 4 {
		t.Errorf("Expected 4 roles after idempotent seeding, got %d", len(roles))
	}
}

func TestSeedPermissions(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	err := seeder.SeedPermissions(ctx)
	if err != nil {
		t.Fatalf("SeedPermissions failed: %v", err)
	}

	// Verify all permissions were created
	permissions, _ := mockStore.ListPermissions(ctx)
	if len(permissions) != 16 {
		t.Errorf("Expected 16 permissions, got %d", len(permissions))
	}

	// Check a specific permission
	perm, err := mockStore.GetPermissionByName(ctx, "product:create")
	if err != nil {
		t.Error("product:create permission not found")
	} else {
		if perm.Resource != "product" {
			t.Errorf("Expected resource 'product', got %s", perm.Resource)
		}
		if perm.Action != "create" {
			t.Errorf("Expected action 'create', got %s", perm.Action)
		}
	}
}

func TestSeedRolePermissions(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed roles and permissions
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}
	if err := seeder.SeedPermissions(ctx); err != nil {
		t.Fatalf("SeedPermissions failed: %v", err)
	}

	// Now seed role permissions
	if err := seeder.SeedRolePermissions(ctx); err != nil {
		t.Fatalf("SeedRolePermissions failed: %v", err)
	}

	// Check admin has all permissions
	adminRole, _ := mockStore.GetRoleByName(ctx, "admin")
	adminPerms, _ := mockStore.GetRolePermissions(ctx, adminRole.ID)
	if len(adminPerms) != 16 {
		t.Errorf("Admin should have 16 permissions, got %d", len(adminPerms))
	}

	// Check customer has limited permissions
	customerRole, _ := mockStore.GetRoleByName(ctx, "customer")
	customerPerms, _ := mockStore.GetRolePermissions(ctx, customerRole.ID)
	if len(customerPerms) != 4 {
		t.Errorf("Customer should have 4 permissions, got %d", len(customerPerms))
	}
}

func TestSeedAll(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	err := seeder.SeedAll(ctx)
	if err != nil {
		t.Fatalf("SeedAll failed: %v", err)
	}

	// Verify roles
	roles, _ := mockStore.ListRoles(ctx)
	if len(roles) != 4 {
		t.Errorf("Expected 4 roles, got %d", len(roles))
	}

	// Verify permissions
	permissions, _ := mockStore.ListPermissions(ctx)
	if len(permissions) != 16 {
		t.Errorf("Expected 16 permissions, got %d", len(permissions))
	}

	// Verify role-permission relationships
	adminRole, _ := mockStore.GetRoleByName(ctx, "admin")
	adminPerms, _ := mockStore.GetRolePermissions(ctx, adminRole.ID)
	if len(adminPerms) == 0 {
		t.Error("Admin role should have permissions after SeedAll")
	}
}

func TestAssignDefaultRoleToUser(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed roles
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}

	// Create a user
	user := &models.User{
		ID:    "user-1",
		Email: "test@example.com",
	}
	mockStore.CreateUser(ctx, user)

	// Assign default role
	err := seeder.AssignDefaultRoleToUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("AssignDefaultRoleToUser failed: %v", err)
	}

	// Verify user has customer role
	hasRole, _ := mockStore.HasRole(ctx, user.ID, "customer")
	if !hasRole {
		t.Error("User should have customer role")
	}
}

func TestAssignDefaultRoleToUser_AlreadyHasRole(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed roles
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}

	// Create a user with admin role
	user := &models.User{
		ID:    "user-1",
		Email: "admin@example.com",
	}
	mockStore.CreateUser(ctx, user)
	adminRole, _ := mockStore.GetRoleByName(ctx, "admin")
	mockStore.AssignRole(ctx, user.ID, adminRole.ID)

	// Try to assign default role (should not add customer role)
	err := seeder.AssignDefaultRoleToUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("AssignDefaultRoleToUser failed: %v", err)
	}

	// User should still have only admin role
	roles, _ := mockStore.GetUserRoles(ctx, user.ID)
	if len(roles) != 1 {
		t.Errorf("User should have 1 role, got %d", len(roles))
	}
	if roles[0].Name != "admin" {
		t.Error("User should have admin role, not customer")
	}
}

func TestAssignRoleToUser(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed roles
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}

	// Create a user
	user := &models.User{
		ID:    "user-1",
		Email: "test@example.com",
	}
	mockStore.CreateUser(ctx, user)

	// Assign manager role
	err := seeder.AssignRoleToUser(ctx, user.ID, RoleManager)
	if err != nil {
		t.Fatalf("AssignRoleToUser failed: %v", err)
	}

	// Verify user has manager role
	hasRole, _ := mockStore.HasRole(ctx, user.ID, "manager")
	if !hasRole {
		t.Error("User should have manager role")
	}
}

func TestRemoveRoleFromUser(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed roles
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}

	// Create a user and assign role
	user := &models.User{
		ID:    "user-1",
		Email: "test@example.com",
	}
	mockStore.CreateUser(ctx, user)
	seeder.AssignRoleToUser(ctx, user.ID, RoleManager)

	// Remove the role
	err := seeder.RemoveRoleFromUser(ctx, user.ID, RoleManager)
	if err != nil {
		t.Fatalf("RemoveRoleFromUser failed: %v", err)
	}

	// Verify user no longer has manager role
	hasRole, _ := mockStore.HasRole(ctx, user.ID, "manager")
	if hasRole {
		t.Error("User should not have manager role after removal")
	}
}

func TestGetRoleID(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed roles
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}

	// Get role ID
	roleID, err := seeder.GetRoleID(ctx, RoleAdmin)
	if err != nil {
		t.Fatalf("GetRoleID failed: %v", err)
	}
	if roleID == "" {
		t.Error("GetRoleID returned empty ID")
	}
}

func TestGetPermissionID(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed permissions
	if err := seeder.SeedPermissions(ctx); err != nil {
		t.Fatalf("SeedPermissions failed: %v", err)
	}

	// Get permission ID
	permID, err := seeder.GetPermissionID(ctx, PermProductCreate)
	if err != nil {
		t.Fatalf("GetPermissionID failed: %v", err)
	}
	if permID == "" {
		t.Error("GetPermissionID returned empty ID")
	}
}

func TestAssignDefaultRoleToUsersWithoutRoles(t *testing.T) {
	mockStore := NewMockStore()
	seeder := NewSeeder(mockStore)
	ctx := context.Background()

	// First seed roles
	if err := seeder.SeedRoles(ctx); err != nil {
		t.Fatalf("SeedRoles failed: %v", err)
	}

	// Create multiple users
	for i := 1; i <= 5; i++ {
		user := &models.User{
			ID:    fmt.Sprintf("user-%d", i),
			Email: fmt.Sprintf("user%d@example.com", i),
		}
		mockStore.CreateUser(ctx, user)
	}

	// Give one user a role already
	adminRole, _ := mockStore.GetRoleByName(ctx, "admin")
	mockStore.AssignRole(ctx, "user-1", adminRole.ID)

	// Assign default role to users without roles
	count, err := seeder.AssignDefaultRoleToUsersWithoutRoles(ctx)
	if err != nil {
		t.Fatalf("AssignDefaultRoleToUsersWithoutRoles failed: %v", err)
	}

	if count != 4 {
		t.Errorf("Expected 4 users to be updated, got %d", count)
	}

	// Verify user-1 still has admin role only
	user1Roles, _ := mockStore.GetUserRoles(ctx, "user-1")
	if len(user1Roles) != 1 || user1Roles[0].Name != "admin" {
		t.Error("User-1 should still have only admin role")
	}

	// Verify user-2 through user-5 have customer role
	for i := 2; i <= 5; i++ {
		hasRole, _ := mockStore.HasRole(ctx, fmt.Sprintf("user-%d", i), "customer")
		if !hasRole {
			t.Errorf("User-%d should have customer role", i)
		}
	}
}
