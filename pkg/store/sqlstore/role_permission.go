package sqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
)

// GrantPermission grants a permission to a role
func (s *SQLStore) GrantPermission(ctx context.Context, roleID, permissionID string) error {
	query := `INSERT INTO role_permissions (role_id, permission_id, granted_at) VALUES (?, ?, ?)`
	if s.driver == "postgres" {
		query = `INSERT INTO role_permissions (role_id, permission_id, granted_at) VALUES ($1, $2, $3)`
	}
	
	_, err := s.executor().ExecContext(ctx, query, roleID, permissionID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to grant permission: %w", err)
	}
	
	return nil
}

// RevokePermission revokes a permission from a role
func (s *SQLStore) RevokePermission(ctx context.Context, roleID, permissionID string) error {
	query := `DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?`
	if s.driver == "postgres" {
		query = `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	}
	
	_, err := s.executor().ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to revoke permission: %w", err)
	}
	
	return nil
}

// GetRolePermissions retrieves all permissions for a role
func (s *SQLStore) GetRolePermissions(ctx context.Context, roleID string) ([]*models.Permission, error) {
	query := `
		SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = ?
		ORDER BY p.name ASC
	`
	if s.driver == "postgres" {
		query = `
			SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at, p.updated_at
			FROM permissions p
			INNER JOIN role_permissions rp ON rp.permission_id = p.id
			WHERE rp.role_id = $1
			ORDER BY p.name ASC
		`
	}
	
	rows, err := s.executor().QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	defer rows.Close()
	
	var permissions []*models.Permission
	for rows.Next() {
		permission := &models.Permission{}
		if err := rows.Scan(&permission.ID, &permission.Name, &permission.Resource, &permission.Action, &permission.Description, &permission.CreatedAt, &permission.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, permission)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permissions: %w", err)
	}
	
	return permissions, nil
}

// GetPermissionRoles retrieves all roles that have a specific permission
func (s *SQLStore) GetPermissionRoles(ctx context.Context, permissionID string) ([]*models.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN role_permissions rp ON rp.role_id = r.id
		WHERE rp.permission_id = ?
		ORDER BY r.name ASC
	`
	if s.driver == "postgres" {
		query = `
			SELECT r.id, r.name, r.description, r.created_at, r.updated_at
			FROM roles r
			INNER JOIN role_permissions rp ON rp.role_id = r.id
			WHERE rp.permission_id = $1
			ORDER BY r.name ASC
		`
	}
	
	rows, err := s.executor().QueryContext(ctx, query, permissionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission roles: %w", err)
	}
	defer rows.Close()
	
	var roles []*models.Role
	for rows.Next() {
		role := &models.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}
	
	return roles, nil
}
