package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/google/uuid"
)

// CreateUser creates a new user
func (s *SQLStore) CreateUser(ctx context.Context, user *models.User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	
	query := `
		INSERT INTO users (id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	
	if s.driver == "postgres" {
		query = `
			INSERT INTO users (id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`
	}
	
	_, err := s.executor().ExecContext(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.FirstName, user.LastName, user.Active, user.EmailVerified, user.CreatedAt, user.UpdatedAt,
	)
	
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	
	return nil
}

// GetUserByID retrieves a user by their ID
func (s *SQLStore) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at
		FROM users
		WHERE id = ?
	`
	
	if s.driver == "postgres" {
		query = `
			SELECT id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at
			FROM users
			WHERE id = $1
		`
	}
	
	user := &models.User{}
	err := s.executor().QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Active, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	
	return user, nil
}

// GetUserByEmail retrieves a user by their email address
func (s *SQLStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at
		FROM users
		WHERE email = ?
	`
	
	if s.driver == "postgres" {
		query = `
			SELECT id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at
			FROM users
			WHERE email = $1
		`
	}
	
	user := &models.User{}
	err := s.executor().QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Active, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	
	return user, nil
}

// UpdateUser updates an existing user
func (s *SQLStore) UpdateUser(ctx context.Context, user *models.User) error {
	user.UpdatedAt = time.Now()
	
	query := `
		UPDATE users
		SET email = ?, password_hash = ?, first_name = ?, last_name = ?, active = ?, email_verified = ?, updated_at = ?
		WHERE id = ?
	`
	
	if s.driver == "postgres" {
		query = `
			UPDATE users
			SET email = $1, password_hash = $2, first_name = $3, last_name = $4, active = $5, email_verified = $6, updated_at = $7
			WHERE id = $8
		`
	}
	
	_, err := s.executor().ExecContext(ctx, query,
		user.Email, user.PasswordHash, user.FirstName, user.LastName, user.Active, user.EmailVerified, user.UpdatedAt, user.ID,
	)
	
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	
	return nil
}

// DeleteUser deletes a user (soft delete by setting Active = false)
func (s *SQLStore) DeleteUser(ctx context.Context, id string) error {
	query := `UPDATE users SET active = ? WHERE id = ?`
	
	if s.driver == "postgres" {
		query = `UPDATE users SET active = $1 WHERE id = $2`
	}
	
	_, err := s.executor().ExecContext(ctx, query, false, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	
	return nil
}

// ListUsers retrieves all users with pagination
func (s *SQLStore) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`
	
	if s.driver == "postgres" {
		query = `
			SELECT id, email, password_hash, first_name, last_name, active, email_verified, created_at, updated_at
			FROM users
			ORDER BY created_at DESC
			LIMIT $1 OFFSET $2
		`
	}
	
	rows, err := s.executor().QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()
	
	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		if err := rows.Scan(
			&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Active, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}
	
	return users, nil
}
