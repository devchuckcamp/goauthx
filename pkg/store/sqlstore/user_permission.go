package sqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
)

// GrantUserPermission grants a permission directly to a user
func (s *SQLStore) GrantUserPermission(ctx context.Context, userID, permissionID string) error {
	query := `INSERT INTO user_permissions (user_id, permission_id, granted_at) VALUES (?, ?, ?)`
	if s.driver == "postgres" {
		query = `INSERT INTO user_permissions (user_id, permission_id, granted_at) VALUES ($1, $2, $3)`
	}

	_, err := s.executor().ExecContext(ctx, query, userID, permissionID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to grant user permission: %w", err)
	}

	return nil
}

// RevokeUserPermission revokes a permission directly from a user
func (s *SQLStore) RevokeUserPermission(ctx context.Context, userID, permissionID string) error {
	query := `DELETE FROM user_permissions WHERE user_id = ? AND permission_id = ?`
	if s.driver == "postgres" {
		query = `DELETE FROM user_permissions WHERE user_id = $1 AND permission_id = $2`
	}

	_, err := s.executor().ExecContext(ctx, query, userID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to revoke user permission: %w", err)
	}

	return nil
}

// GetUserDirectPermissions retrieves all permissions granted directly to a user
func (s *SQLStore) GetUserDirectPermissions(ctx context.Context, userID string) ([]*models.Permission, error) {
	query := `
		SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN user_permissions up ON up.permission_id = p.id
		WHERE up.user_id = ?
		ORDER BY p.name ASC
	`
	if s.driver == "postgres" {
		query = `
			SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at, p.updated_at
			FROM permissions p
			INNER JOIN user_permissions up ON up.permission_id = p.id
			WHERE up.user_id = $1
			ORDER BY p.name ASC
		`
	}

	rows, err := s.executor().QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user direct permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		permission := &models.Permission{}
		if err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Resource,
			&permission.Action,
			&permission.Description,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permissions: %w", err)
	}

	return permissions, nil
}
