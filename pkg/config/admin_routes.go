package config

// AdminRouteConfig holds HTTP route configuration for admin endpoints
type AdminRouteConfig struct {
	// Role management routes
	ListRolesPath  string
	CreateRolePath string
	GetRolePath    string
	UpdateRolePath string
	DeleteRolePath string

	// Permission management routes
	ListPermissionsPath  string
	CreatePermissionPath string
	GetPermissionPath    string
	UpdatePermissionPath string
	DeletePermissionPath string

	// User role management routes
	AssignUserRolePath string
	RemoveUserRolePath string
	GetUserRolesPath   string

	// User permission management routes
	GrantUserPermissionPath  string
	RevokeUserPermissionPath string
	GetUserPermissionsPath   string

	// Role permission management routes
	GrantRolePermissionPath  string
	RevokeRolePermissionPath string
	GetRolePermissionsPath   string
}

// DefaultAdminRouteConfig returns admin route configuration with sensible defaults
func DefaultAdminRouteConfig() *AdminRouteConfig {
	return &AdminRouteConfig{
		// Role management
		ListRolesPath:  "/admin/roles",
		CreateRolePath: "/admin/roles",
		GetRolePath:    "/admin/roles/", // + {id}
		UpdateRolePath: "/admin/roles/", // + {id}
		DeleteRolePath: "/admin/roles/", // + {id}

		// Permission management
		ListPermissionsPath:  "/admin/permissions",
		CreatePermissionPath: "/admin/permissions",
		GetPermissionPath:    "/admin/permissions/", // + {id}
		UpdatePermissionPath: "/admin/permissions/", // + {id}
		DeletePermissionPath: "/admin/permissions/", // + {id}

		// User role management
		AssignUserRolePath: "/admin/users/", // + {id}/roles
		RemoveUserRolePath: "/admin/users/", // + {id}/roles/{roleId}
		GetUserRolesPath:   "/admin/users/", // + {id}/roles

		// User permission management
		GrantUserPermissionPath:  "/admin/users/", // + {id}/permissions
		RevokeUserPermissionPath: "/admin/users/", // + {id}/permissions/{permId}
		GetUserPermissionsPath:   "/admin/users/", // + {id}/permissions

		// Role permission management
		GrantRolePermissionPath:  "/admin/roles/", // + {id}/permissions
		RevokeRolePermissionPath: "/admin/roles/", // + {id}/permissions/{permId}
		GetRolePermissionsPath:   "/admin/roles/", // + {id}/permissions
	}
}
