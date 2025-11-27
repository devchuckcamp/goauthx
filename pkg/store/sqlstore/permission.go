package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/google/uuid"
)

// CreatePermission creates a new permission
func (s *SQLStore) CreatePermission(ctx context.Context, permission *models.Permission) error {
	if permission.ID == "" {
		permission.ID = uuid.New().String()
	}
	
	now := time.Now()
	permission.CreatedAt = now
	permission.UpdatedAt = now
	
	query := `INSERT INTO permissions (id, name, resource, action, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		query = `INSERT INTO permissions (id, name, resource, action, description, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	}
	
	_, err := s.executor().ExecContext(ctx, query, permission.ID, permission.Name, permission.Resource, permission.Action, permission.Description, permission.CreatedAt, permission.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}
	
	return nil
}

// GetPermissionByID retrieves a permission by its ID
func (s *SQLStore) GetPermissionByID(ctx context.Context, id string) (*models.Permission, error) {
	query := `SELECT id, name, resource, action, description, created_at, updated_at FROM permissions WHERE id = ?`
	if s.driver == "postgres" {
		query = `SELECT id, name, resource, action, description, created_at, updated_at FROM permissions WHERE id = $1`
	}
	
	permission := &models.Permission{}
	err := s.executor().QueryRowContext(ctx, query, id).Scan(&permission.ID, &permission.Name, &permission.Resource, &permission.Action, &permission.Description, &permission.CreatedAt, &permission.UpdatedAt)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("permission not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	
	return permission, nil
}

// GetPermissionByName retrieves a permission by its name
func (s *SQLStore) GetPermissionByName(ctx context.Context, name string) (*models.Permission, error) {
	query := `SELECT id, name, resource, action, description, created_at, updated_at FROM permissions WHERE name = ?`
	if s.driver == "postgres" {
		query = `SELECT id, name, resource, action, description, created_at, updated_at FROM permissions WHERE name = $1`
	}
	
	permission := &models.Permission{}
	err := s.executor().QueryRowContext(ctx, query, name).Scan(&permission.ID, &permission.Name, &permission.Resource, &permission.Action, &permission.Description, &permission.CreatedAt, &permission.UpdatedAt)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("permission not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	
	return permission, nil
}

// ListPermissions retrieves all permissions
func (s *SQLStore) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	query := `SELECT id, name, resource, action, description, created_at, updated_at FROM permissions ORDER BY name ASC`
	
	rows, err := s.executor().QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
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

// UpdatePermission updates an existing permission
func (s *SQLStore) UpdatePermission(ctx context.Context, permission *models.Permission) error {
	permission.UpdatedAt = time.Now()
	
	query := `UPDATE permissions SET name = ?, resource = ?, action = ?, description = ?, updated_at = ? WHERE id = ?`
	if s.driver == "postgres" {
		query = `UPDATE permissions SET name = $1, resource = $2, action = $3, description = $4, updated_at = $5 WHERE id = $6`
	}
	
	_, err := s.executor().ExecContext(ctx, query, permission.Name, permission.Resource, permission.Action, permission.Description, permission.UpdatedAt, permission.ID)
	if err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}
	
	return nil
}

// DeletePermission deletes a permission
func (s *SQLStore) DeletePermission(ctx context.Context, id string) error {
	query := `DELETE FROM permissions WHERE id = ?`
	if s.driver == "postgres" {
		query = `DELETE FROM permissions WHERE id = $1`
	}
	
	_, err := s.executor().ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}
	
	return nil
}
