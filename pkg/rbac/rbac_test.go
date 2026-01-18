package rbac

import (
	"testing"
)

func TestRoleNameString(t *testing.T) {
	tests := []struct {
		role     RoleName
		expected string
	}{
		{RoleAdmin, "admin"},
		{RoleManager, "manager"},
		{RoleCustomerExperience, "customer_experience"},
		{RoleCustomer, "customer"},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			if got := tt.role.String(); got != tt.expected {
				t.Errorf("RoleName.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPermissionNameString(t *testing.T) {
	tests := []struct {
		perm     PermissionName
		expected string
	}{
		{PermProductCreate, "product:create"},
		{PermProductRead, "product:read"},
		{PermOrderCreate, "order:create"},
		{PermUserUpdateOwn, "user:update_own"},
		{PermReportView, "report:view"},
		{PermCustomerView, "customer:view"},
	}

	for _, tt := range tests {
		t.Run(string(tt.perm), func(t *testing.T) {
			if got := tt.perm.String(); got != tt.expected {
				t.Errorf("PermissionName.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDefaultRoles(t *testing.T) {
	roles := DefaultRoles()

	if len(roles) != 4 {
		t.Errorf("DefaultRoles() returned %d roles, want 4", len(roles))
	}

	// Check that all expected roles are present
	roleNames := make(map[RoleName]bool)
	for _, role := range roles {
		roleNames[role.Name] = true
		if role.Description == "" {
			t.Errorf("Role %s has empty description", role.Name)
		}
	}

	expectedRoles := []RoleName{RoleAdmin, RoleManager, RoleCustomerExperience, RoleCustomer}
	for _, expected := range expectedRoles {
		if !roleNames[expected] {
			t.Errorf("DefaultRoles() missing role %s", expected)
		}
	}
}

func TestDefaultPermissions(t *testing.T) {
	permissions := DefaultPermissions()

	if len(permissions) != 16 {
		t.Errorf("DefaultPermissions() returned %d permissions, want 16", len(permissions))
	}

	// Check that each permission has required fields
	for _, perm := range permissions {
		if perm.Name == "" {
			t.Error("Permission has empty name")
		}
		if perm.Resource == "" {
			t.Errorf("Permission %s has empty resource", perm.Name)
		}
		if perm.Action == "" {
			t.Errorf("Permission %s has empty action", perm.Name)
		}
		if perm.Description == "" {
			t.Errorf("Permission %s has empty description", perm.Name)
		}
	}
}

func TestDefaultRolePermissions(t *testing.T) {
	rolePerms := DefaultRolePermissions()

	// Check that all roles have permissions defined
	expectedRoles := []RoleName{RoleAdmin, RoleManager, RoleCustomerExperience, RoleCustomer}
	for _, role := range expectedRoles {
		perms, exists := rolePerms[role]
		if !exists {
			t.Errorf("DefaultRolePermissions() missing role %s", role)
			continue
		}
		if len(perms) == 0 {
			t.Errorf("Role %s has no permissions", role)
		}
	}

	// Admin should have more permissions than others
	adminPerms := rolePerms[RoleAdmin]
	customerPerms := rolePerms[RoleCustomer]
	if len(adminPerms) <= len(customerPerms) {
		t.Error("Admin should have more permissions than Customer")
	}
}

func TestAllRoleNames(t *testing.T) {
	roles := AllRoleNames()

	if len(roles) != 4 {
		t.Errorf("AllRoleNames() returned %d roles, want 4", len(roles))
	}

	// Verify uniqueness
	seen := make(map[RoleName]bool)
	for _, role := range roles {
		if seen[role] {
			t.Errorf("Duplicate role name: %s", role)
		}
		seen[role] = true
	}
}

func TestAllPermissionNames(t *testing.T) {
	permissions := AllPermissionNames()

	if len(permissions) != 16 {
		t.Errorf("AllPermissionNames() returned %d permissions, want 16", len(permissions))
	}

	// Verify uniqueness
	seen := make(map[PermissionName]bool)
	for _, perm := range permissions {
		if seen[perm] {
			t.Errorf("Duplicate permission name: %s", perm)
		}
		seen[perm] = true
	}
}

func TestIsValidRoleName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"admin", true},
		{"manager", true},
		{"customer_experience", true},
		{"customer", true},
		{"invalid", false},
		{"Admin", false}, // case-sensitive
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidRoleName(tt.name); got != tt.expected {
				t.Errorf("IsValidRoleName(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestIsValidPermissionName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"product:create", true},
		{"product:read", true},
		{"user:update_own", true},
		{"invalid:permission", false},
		{"Product:Create", false}, // case-sensitive
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidPermissionName(tt.name); got != tt.expected {
				t.Errorf("IsValidPermissionName(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestGetRoleDescription(t *testing.T) {
	tests := []struct {
		role            RoleName
		expectNonEmpty  bool
	}{
		{RoleAdmin, true},
		{RoleManager, true},
		{RoleCustomerExperience, true},
		{RoleCustomer, true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			desc := GetRoleDescription(tt.role)
			if tt.expectNonEmpty && desc == "" {
				t.Errorf("GetRoleDescription(%s) returned empty string, expected non-empty", tt.role)
			}
			if !tt.expectNonEmpty && desc != "" {
				t.Errorf("GetRoleDescription(%s) returned %q, expected empty string", tt.role, desc)
			}
		})
	}
}

func TestGetPermissionDefinition(t *testing.T) {
	// Valid permission
	def := GetPermissionDefinition(PermProductCreate)
	if def == nil {
		t.Fatal("GetPermissionDefinition(PermProductCreate) returned nil")
	}
	if def.Name != PermProductCreate {
		t.Errorf("Expected name %s, got %s", PermProductCreate, def.Name)
	}
	if def.Resource != "product" {
		t.Errorf("Expected resource 'product', got %s", def.Resource)
	}
	if def.Action != "create" {
		t.Errorf("Expected action 'create', got %s", def.Action)
	}

	// Invalid permission
	def = GetPermissionDefinition("invalid:permission")
	if def != nil {
		t.Error("GetPermissionDefinition(invalid) should return nil")
	}
}

func TestDefaultRole(t *testing.T) {
	defaultRole := DefaultRole()
	if defaultRole != RoleCustomer {
		t.Errorf("DefaultRole() = %s, want %s", defaultRole, RoleCustomer)
	}
}

func TestRolePermissionMatrix(t *testing.T) {
	rolePerms := DefaultRolePermissions()

	// Test specific permission assignments according to the matrix
	testCases := []struct {
		role       RoleName
		permission PermissionName
		shouldHave bool
	}{
		// Admin should have all permissions
		{RoleAdmin, PermProductCreate, true},
		{RoleAdmin, PermUserCreate, true},
		{RoleAdmin, PermReportView, true},

		// Manager should have product and order permissions, but not user:create
		{RoleManager, PermProductCreate, true},
		{RoleManager, PermOrderProcess, true},
		{RoleManager, PermUserCreate, false},
		{RoleManager, PermReportView, true},

		// Customer Experience should have specific permissions
		{RoleCustomerExperience, PermCustomerView, true},
		{RoleCustomerExperience, PermCustomerOrderHistory, true},
		{RoleCustomerExperience, PermProductCreate, false},

		// Customer should have limited permissions
		{RoleCustomer, PermProductRead, true},
		{RoleCustomer, PermOrderCreate, true},
		{RoleCustomer, PermUserUpdateOwn, true},
		{RoleCustomer, PermProductCreate, false},
		{RoleCustomer, PermUserCreate, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.role)+"_"+string(tc.permission), func(t *testing.T) {
			perms := rolePerms[tc.role]
			hasPermission := false
			for _, p := range perms {
				if p == tc.permission {
					hasPermission = true
					break
				}
			}
			if hasPermission != tc.shouldHave {
				t.Errorf("Role %s permission %s: got %v, want %v",
					tc.role, tc.permission, hasPermission, tc.shouldHave)
			}
		})
	}
}
