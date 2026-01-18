// Package rbac provides Role-Based Access Control (RBAC) constants, types, and utilities
package rbac

// RoleName represents a type-safe role name
type RoleName string

// Predefined role names
const (
	// RoleAdmin has full access to all resources
	RoleAdmin RoleName = "admin"

	// RoleManager has access to manage products, orders, and view reports
	RoleManager RoleName = "manager"

	// RoleCustomerExperience has access to view customer information and order history
	RoleCustomerExperience RoleName = "customer_experience"

	// RoleCustomer has access to their own resources and basic product/order operations
	RoleCustomer RoleName = "customer"
)

// String returns the string representation of the role name
func (r RoleName) String() string {
	return string(r)
}

// PermissionName represents a type-safe permission name
type PermissionName string

// Product permissions
const (
	PermProductCreate PermissionName = "product:create"
	PermProductRead   PermissionName = "product:read"
	PermProductUpdate PermissionName = "product:update"
	PermProductDelete PermissionName = "product:delete"
)

// Order permissions
const (
	PermOrderCreate  PermissionName = "order:create"
	PermOrderRead    PermissionName = "order:read"
	PermOrderUpdate  PermissionName = "order:update"
	PermOrderProcess PermissionName = "order:process"
)

// User permissions
const (
	PermUserCreate    PermissionName = "user:create"
	PermUserRead      PermissionName = "user:read"
	PermUserUpdate    PermissionName = "user:update"
	PermUserDelete    PermissionName = "user:delete"
	PermUserUpdateOwn PermissionName = "user:update_own"
)

// Report permissions
const (
	PermReportView PermissionName = "report:view"
)

// Customer support permissions
const (
	PermCustomerView         PermissionName = "customer:view"
	PermCustomerOrderHistory PermissionName = "customer:order_history"
)

// String returns the string representation of the permission name
func (p PermissionName) String() string {
	return string(p)
}

// RoleDefinition defines a role with its metadata
type RoleDefinition struct {
	Name        RoleName
	Description string
}

// PermissionDefinition defines a permission with its metadata
type PermissionDefinition struct {
	Name        PermissionName
	Resource    string
	Action      string
	Description string
}

// DefaultRoles returns the predefined roles for the system
func DefaultRoles() []RoleDefinition {
	return []RoleDefinition{
		{
			Name:        RoleAdmin,
			Description: "Administrator with full access to all resources",
		},
		{
			Name:        RoleManager,
			Description: "Manager with access to products, orders, and reports",
		},
		{
			Name:        RoleCustomerExperience,
			Description: "Customer experience representative with access to customer support",
		},
		{
			Name:        RoleCustomer,
			Description: "Regular customer with access to own resources",
		},
	}
}

// DefaultPermissions returns the predefined permissions for the system
func DefaultPermissions() []PermissionDefinition {
	return []PermissionDefinition{
		// Product permissions
		{Name: PermProductCreate, Resource: "product", Action: "create", Description: "Create new products"},
		{Name: PermProductRead, Resource: "product", Action: "read", Description: "View products"},
		{Name: PermProductUpdate, Resource: "product", Action: "update", Description: "Update products"},
		{Name: PermProductDelete, Resource: "product", Action: "delete", Description: "Delete products"},

		// Order permissions
		{Name: PermOrderCreate, Resource: "order", Action: "create", Description: "Create new orders"},
		{Name: PermOrderRead, Resource: "order", Action: "read", Description: "View orders"},
		{Name: PermOrderUpdate, Resource: "order", Action: "update", Description: "Update orders"},
		{Name: PermOrderProcess, Resource: "order", Action: "process", Description: "Process orders"},

		// User permissions
		{Name: PermUserCreate, Resource: "user", Action: "create", Description: "Create new users"},
		{Name: PermUserRead, Resource: "user", Action: "read", Description: "View users"},
		{Name: PermUserUpdate, Resource: "user", Action: "update", Description: "Update users"},
		{Name: PermUserDelete, Resource: "user", Action: "delete", Description: "Delete users"},
		{Name: PermUserUpdateOwn, Resource: "user", Action: "update_own", Description: "Update own profile"},

		// Report permissions
		{Name: PermReportView, Resource: "report", Action: "view", Description: "View reports"},

		// Customer support permissions
		{Name: PermCustomerView, Resource: "customer", Action: "view", Description: "View customer information"},
		{Name: PermCustomerOrderHistory, Resource: "customer", Action: "order_history", Description: "View customer order history"},
	}
}

// DefaultRolePermissions returns the default permission assignments for each role
func DefaultRolePermissions() map[RoleName][]PermissionName {
	return map[RoleName][]PermissionName{
		RoleAdmin: {
			// All product permissions
			PermProductCreate, PermProductRead, PermProductUpdate, PermProductDelete,
			// All order permissions
			PermOrderCreate, PermOrderRead, PermOrderUpdate, PermOrderProcess,
			// All user permissions
			PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete, PermUserUpdateOwn,
			// Report permissions
			PermReportView,
			// Customer support permissions
			PermCustomerView, PermCustomerOrderHistory,
		},
		RoleManager: {
			// Product permissions
			PermProductCreate, PermProductRead, PermProductUpdate, PermProductDelete,
			// Order permissions
			PermOrderCreate, PermOrderRead, PermOrderUpdate, PermOrderProcess,
			// User permissions (own profile only)
			PermUserUpdateOwn,
			// Report permissions
			PermReportView,
		},
		RoleCustomerExperience: {
			// Order permissions (read only)
			PermOrderRead,
			// User permissions (own profile only)
			PermUserUpdateOwn,
			// Customer support permissions
			PermCustomerView, PermCustomerOrderHistory,
		},
		RoleCustomer: {
			// Product permissions (read only)
			PermProductRead,
			// Order permissions (create and read own)
			PermOrderCreate, PermOrderRead,
			// User permissions (own profile only)
			PermUserUpdateOwn,
		},
	}
}

// AllRoleNames returns all predefined role names
func AllRoleNames() []RoleName {
	return []RoleName{
		RoleAdmin,
		RoleManager,
		RoleCustomerExperience,
		RoleCustomer,
	}
}

// AllPermissionNames returns all predefined permission names
func AllPermissionNames() []PermissionName {
	return []PermissionName{
		PermProductCreate, PermProductRead, PermProductUpdate, PermProductDelete,
		PermOrderCreate, PermOrderRead, PermOrderUpdate, PermOrderProcess,
		PermUserCreate, PermUserRead, PermUserUpdate, PermUserDelete, PermUserUpdateOwn,
		PermReportView,
		PermCustomerView, PermCustomerOrderHistory,
	}
}

// IsValidRoleName checks if a role name is a predefined role
func IsValidRoleName(name string) bool {
	for _, r := range AllRoleNames() {
		if string(r) == name {
			return true
		}
	}
	return false
}

// IsValidPermissionName checks if a permission name is a predefined permission
func IsValidPermissionName(name string) bool {
	for _, p := range AllPermissionNames() {
		if string(p) == name {
			return true
		}
	}
	return false
}

// GetRoleDescription returns the description for a predefined role
func GetRoleDescription(name RoleName) string {
	for _, r := range DefaultRoles() {
		if r.Name == name {
			return r.Description
		}
	}
	return ""
}

// GetPermissionDefinition returns the definition for a predefined permission
func GetPermissionDefinition(name PermissionName) *PermissionDefinition {
	for _, p := range DefaultPermissions() {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

// DefaultRole returns the default role to assign to new users
func DefaultRole() RoleName {
	return RoleCustomer
}
