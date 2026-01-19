package sqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
)

// AssignRole assigns a role to a user
func (s *SQLStore) AssignRole(ctx context.Context, userID, roleID string) error {
	query := `INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, ?)`
	if s.driver == "postgres" {
		query = `INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES ($1, $2, $3)`
	}

	_, err := s.executor().ExecContext(ctx, query, userID, roleID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// RemoveRole removes a role from a user
func (s *SQLStore) RemoveRole(ctx context.Context, userID, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = ? AND role_id = ?`
	if s.driver == "postgres" {
		query = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	}

	_, err := s.executor().ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	return nil
}

// GetUserRoles retrieves all roles for a user
func (s *SQLStore) GetUserRoles(ctx context.Context, userID string) ([]*models.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = ?
		ORDER BY r.name ASC
	`
	if s.driver == "postgres" {
		query = `
			SELECT r.id, r.name, r.description, r.created_at, r.updated_at
			FROM roles r
			INNER JOIN user_roles ur ON ur.role_id = r.id
			WHERE ur.user_id = $1
			ORDER BY r.name ASC
		`
	}

	rows, err := s.executor().QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
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

// GetRoleUsers retrieves all users with a specific role
func (s *SQLStore) GetRoleUsers(ctx context.Context, roleID string) ([]*models.User, error) {
	query := `
		SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.active, u.created_at, u.updated_at
		FROM users u
		INNER JOIN user_roles ur ON ur.user_id = u.id
		WHERE ur.role_id = ?
		ORDER BY u.email ASC
	`
	if s.driver == "postgres" {
		query = `
			SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.active, u.created_at, u.updated_at
			FROM users u
			INNER JOIN user_roles ur ON ur.user_id = u.id
			WHERE ur.role_id = $1
			ORDER BY u.email ASC
		`
	}

	rows, err := s.executor().QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		if err := rows.Scan(&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Active, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// HasRole checks if a user has a specific role
func (s *SQLStore) HasRole(ctx context.Context, userID, roleName string) (bool, error) {
	query := `
		SELECT COUNT(*)
		FROM user_roles ur
		INNER JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.name = ?
	`
	if s.driver == "postgres" {
		query = `
			SELECT COUNT(*)
			FROM user_roles ur
			INNER JOIN roles r ON r.id = ur.role_id
			WHERE ur.user_id = $1 AND r.name = $2
		`
	}

	var count int
	err := s.executor().QueryRowContext(ctx, query, userID, roleName).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check role: %w", err)
	}

	return count > 0, nil
}
