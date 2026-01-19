package rbac

import (
	"context"
	"fmt"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/devchuckcamp/goauthx/pkg/store"
)

// Seeder provides functionality to seed the database with predefined roles and permissions
type Seeder struct {
	store store.Store
}

// NewSeeder creates a new Seeder instance
func NewSeeder(store store.Store) *Seeder {
	return &Seeder{
		store: store,
	}
}

// SeedAll seeds all predefined roles, permissions, and their relationships
func (s *Seeder) SeedAll(ctx context.Context) error {
	// Seed roles first
	if err := s.SeedRoles(ctx); err != nil {
		return fmt.Errorf("failed to seed roles: %w", err)
	}

	// Seed permissions
	if err := s.SeedPermissions(ctx); err != nil {
		return fmt.Errorf("failed to seed permissions: %w", err)
	}

	// Seed role-permission relationships
	if err := s.SeedRolePermissions(ctx); err != nil {
		return fmt.Errorf("failed to seed role permissions: %w", err)
	}

	return nil
}

// SeedRoles seeds all predefined roles into the database
func (s *Seeder) SeedRoles(ctx context.Context) error {
	roles := DefaultRoles()

	for _, roleDef := range roles {
		// Check if role already exists
		_, err := s.store.GetRoleByName(ctx, string(roleDef.Name))
		if err == nil {
			// Role already exists, skip
			continue
		}

		// Create the role
		role := &models.Role{
			Name:        string(roleDef.Name),
			Description: roleDef.Description,
		}

		if err := s.store.CreateRole(ctx, role); err != nil {
			return fmt.Errorf("failed to create role %s: %w", roleDef.Name, err)
		}
	}

	return nil
}

// SeedPermissions seeds all predefined permissions into the database
func (s *Seeder) SeedPermissions(ctx context.Context) error {
	permissions := DefaultPermissions()

	for _, permDef := range permissions {
		// Check if permission already exists
		_, err := s.store.GetPermissionByName(ctx, string(permDef.Name))
		if err == nil {
			continue
		}

		// Create the permission
		permission := &models.Permission{
			Name:        string(permDef.Name),
			Resource:    permDef.Resource,
			Action:      permDef.Action,
			Description: permDef.Description,
		}

		if err := s.store.CreatePermission(ctx, permission); err != nil {
			return fmt.Errorf("failed to create permission %s: %w", permDef.Name, err)
		}
	}

	return nil
}

// SeedRolePermissions seeds the role-permission relationships
func (s *Seeder) SeedRolePermissions(ctx context.Context) error {
	rolePermissions := DefaultRolePermissions()

	for roleName, permissionNames := range rolePermissions {
		// Get the role
		role, err := s.store.GetRoleByName(ctx, string(roleName))
		if err != nil {
			return fmt.Errorf("failed to get role %s: %w", roleName, err)
		}

		// Get existing permissions for this role
		existingPerms, err := s.store.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return fmt.Errorf("failed to get existing permissions for role %s: %w", roleName, err)
		}

		// Create a map of existing permission names for quick lookup
		existingPermMap := make(map[string]bool)
		for _, perm := range existingPerms {
			existingPermMap[perm.Name] = true
		}

		// Grant each permission to the role if not already granted
		for _, permName := range permissionNames {
			// Skip if already granted
			if existingPermMap[string(permName)] {
				continue
			}

			// Get the permission
			permission, err := s.store.GetPermissionByName(ctx, string(permName))
			if err != nil {
				return fmt.Errorf("failed to get permission %s: %w", permName, err)
			}

			// Grant the permission to the role
			if err := s.store.GrantPermission(ctx, role.ID, permission.ID); err != nil {
				return fmt.Errorf("failed to grant permission %s to role %s: %w", permName, roleName, err)
			}
		}
	}

	return nil
}

// AssignDefaultRoleToUser assigns the default role (customer) to a user if they have no roles
func (s *Seeder) AssignDefaultRoleToUser(ctx context.Context, userID string) error {
	// Check if user already has roles
	roles, err := s.store.GetUserRoles(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user roles: %w", err)
	}

	// If user already has roles, don't assign default
	if len(roles) > 0 {
		return nil
	}

	// Get the default role
	defaultRoleName := DefaultRole()
	role, err := s.store.GetRoleByName(ctx, string(defaultRoleName))
	if err != nil {
		return fmt.Errorf("failed to get default role %s: %w", defaultRoleName, err)
	}

	// Assign the role to the user
	if err := s.store.AssignRole(ctx, userID, role.ID); err != nil {
		return fmt.Errorf("failed to assign default role to user: %w", err)
	}

	return nil
}

// AssignDefaultRoleToUsersWithoutRoles assigns the default role to all users who don't have any roles
// Returns the number of users updated
func (s *Seeder) AssignDefaultRoleToUsersWithoutRoles(ctx context.Context) (int, error) {
	// Get the default role
	defaultRoleName := DefaultRole()
	role, err := s.store.GetRoleByName(ctx, string(defaultRoleName))
	if err != nil {
		return 0, fmt.Errorf("failed to get default role %s: %w", defaultRoleName, err)
	}

	// Get all users (with pagination to handle large datasets)
	const batchSize = 100
	offset := 0
	updatedCount := 0

	for {
		users, err := s.store.ListUsers(ctx, batchSize, offset)
		if err != nil {
			return updatedCount, fmt.Errorf("failed to list users: %w", err)
		}

		if len(users) == 0 {
			break
		}

		for _, user := range users {
			// Check if user has any roles
			userRoles, err := s.store.GetUserRoles(ctx, user.ID)
			if err != nil {
				return updatedCount, fmt.Errorf("failed to get roles for user %s: %w", user.ID, err)
			}

			// If user has no roles, assign default
			if len(userRoles) == 0 {
				if err := s.store.AssignRole(ctx, user.ID, role.ID); err != nil {
					return updatedCount, fmt.Errorf("failed to assign role to user %s: %w", user.ID, err)
				}
				updatedCount++
			}
		}

		offset += batchSize

		// If we got fewer users than batch size, we've reached the end
		if len(users) < batchSize {
			break
		}
	}

	return updatedCount, nil
}

// AssignRoleToUser assigns a specific role to a user by role name
func (s *Seeder) AssignRoleToUser(ctx context.Context, userID string, roleName RoleName) error {
	// Get the role
	role, err := s.store.GetRoleByName(ctx, string(roleName))
	if err != nil {
		return fmt.Errorf("failed to get role %s: %w", roleName, err)
	}

	// Check if user already has this role
	hasRole, err := s.store.HasRole(ctx, userID, string(roleName))
	if err != nil {
		return fmt.Errorf("failed to check user role: %w", err)
	}

	if hasRole {
		return nil // Already has the role
	}

	// Assign the role
	if err := s.store.AssignRole(ctx, userID, role.ID); err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	return nil
}

// RemoveRoleFromUser removes a specific role from a user by role name
func (s *Seeder) RemoveRoleFromUser(ctx context.Context, userID string, roleName RoleName) error {
	// Get the role
	role, err := s.store.GetRoleByName(ctx, string(roleName))
	if err != nil {
		return fmt.Errorf("failed to get role %s: %w", roleName, err)
	}

	// Remove the role
	if err := s.store.RemoveRole(ctx, userID, role.ID); err != nil {
		return fmt.Errorf("failed to remove role from user: %w", err)
	}

	return nil
}

// GetRoleID returns the database ID for a role name
func (s *Seeder) GetRoleID(ctx context.Context, roleName RoleName) (string, error) {
	role, err := s.store.GetRoleByName(ctx, string(roleName))
	if err != nil {
		return "", fmt.Errorf("failed to get role %s: %w", roleName, err)
	}
	return role.ID, nil
}

// GetPermissionID returns the database ID for a permission name
func (s *Seeder) GetPermissionID(ctx context.Context, permName PermissionName) (string, error) {
	perm, err := s.store.GetPermissionByName(ctx, string(permName))
	if err != nil {
		return "", fmt.Errorf("failed to get permission %s: %w", permName, err)
	}
	return perm.ID, nil
}
