package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/google/uuid"
)

// CreateRole creates a new role
func (s *SQLStore) CreateRole(ctx context.Context, role *models.Role) error {
	if role.ID == "" {
		role.ID = uuid.New().String()
	}
	
	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now
	
	query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`
	
	if s.driver == "postgres" {
		query = `
			INSERT INTO roles (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5)
		`
	}
	
	_, err := s.executor().ExecContext(ctx, query,
		role.ID, role.Name, role.Description, role.CreatedAt, role.UpdatedAt,
	)
	
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	
	return nil
}

// GetRoleByID retrieves a role by its ID
func (s *SQLStore) GetRoleByID(ctx context.Context, id string) (*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = ?
	`
	
	if s.driver == "postgres" {
		query = `
			SELECT id, name, description, created_at, updated_at
			FROM roles
			WHERE id = $1
		`
	}
	
	role := &models.Role{}
	err := s.executor().QueryRowContext(ctx, query, id).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	
	return role, nil
}

// GetRoleByName retrieves a role by its name
func (s *SQLStore) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE name = ?
	`
	
	if s.driver == "postgres" {
		query = `
			SELECT id, name, description, created_at, updated_at
			FROM roles
			WHERE name = $1
		`
	}
	
	role := &models.Role{}
	err := s.executor().QueryRowContext(ctx, query, name).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	
	return role, nil
}

// ListRoles retrieves all roles
func (s *SQLStore) ListRoles(ctx context.Context) ([]*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		ORDER BY name ASC
	`
	
	rows, err := s.executor().QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()
	
	var roles []*models.Role
	for rows.Next() {
		role := &models.Role{}
		if err := rows.Scan(
			&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}
	
	return roles, nil
}

// UpdateRole updates an existing role
func (s *SQLStore) UpdateRole(ctx context.Context, role *models.Role) error {
	role.UpdatedAt = time.Now()
	
	query := `
		UPDATE roles
		SET name = ?, description = ?, updated_at = ?
		WHERE id = ?
	`
	
	if s.driver == "postgres" {
		query = `
			UPDATE roles
			SET name = $1, description = $2, updated_at = $3
			WHERE id = $4
		`
	}
	
	_, err := s.executor().ExecContext(ctx, query,
		role.Name, role.Description, role.UpdatedAt, role.ID,
	)
	
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	
	return nil
}

// DeleteRole deletes a role
func (s *SQLStore) DeleteRole(ctx context.Context, id string) error {
	query := `DELETE FROM roles WHERE id = ?`
	
	if s.driver == "postgres" {
		query = `DELETE FROM roles WHERE id = $1`
	}
	
	_, err := s.executor().ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	
	return nil
}
