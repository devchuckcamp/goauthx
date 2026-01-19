package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/google/uuid"
)

// CreateEmailVerification creates a new email verification token
func (s *SQLStore) CreateEmailVerification(ctx context.Context, verification *models.EmailVerification) error {
	if verification.ID == "" {
		verification.ID = uuid.New().String()
	}

	verification.CreatedAt = time.Now()

	query := `
		INSERT INTO email_verifications (id, user_id, token, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	if s.driver == "postgres" {
		query = `
			INSERT INTO email_verifications (id, user_id, token, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5)
		`
	}

	_, err := s.executor().ExecContext(ctx, query,
		verification.ID, verification.UserID, verification.Token, verification.ExpiresAt, verification.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create email verification: %w", err)
	}

	return nil
}

// GetEmailVerificationByToken retrieves an email verification by token
func (s *SQLStore) GetEmailVerificationByToken(ctx context.Context, token string) (*models.EmailVerification, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at, used_at
		FROM email_verifications
		WHERE token = ?
	`

	if s.driver == "postgres" {
		query = `
			SELECT id, user_id, token, expires_at, created_at, used_at
			FROM email_verifications
			WHERE token = $1
		`
	}

	verification := &models.EmailVerification{}
	err := s.executor().QueryRowContext(ctx, query, token).Scan(
		&verification.ID, &verification.UserID, &verification.Token,
		&verification.ExpiresAt, &verification.CreatedAt, &verification.UsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("email verification not found")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get email verification: %w", err)
	}

	return verification, nil
}

// MarkEmailVerificationUsed marks an email verification as used
func (s *SQLStore) MarkEmailVerificationUsed(ctx context.Context, id string) error {
	now := time.Now()
	query := `UPDATE email_verifications SET used_at = ? WHERE id = ?`

	if s.driver == "postgres" {
		query = `UPDATE email_verifications SET used_at = $1 WHERE id = $2`
	}

	_, err := s.executor().ExecContext(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to mark email verification as used: %w", err)
	}

	return nil
}

// DeleteExpiredEmailVerifications deletes expired email verifications
func (s *SQLStore) DeleteExpiredEmailVerifications(ctx context.Context) error {
	query := `DELETE FROM email_verifications WHERE expires_at < ?`

	if s.driver == "postgres" {
		query = `DELETE FROM email_verifications WHERE expires_at < $1`
	}

	_, err := s.executor().ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired email verifications: %w", err)
	}

	return nil
}

// CreatePasswordReset creates a new password reset token
func (s *SQLStore) CreatePasswordReset(ctx context.Context, reset *models.PasswordReset) error {
	if reset.ID == "" {
		reset.ID = uuid.New().String()
	}

	reset.CreatedAt = time.Now()

	query := `
		INSERT INTO password_resets (id, user_id, token, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	if s.driver == "postgres" {
		query = `
			INSERT INTO password_resets (id, user_id, token, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5)
		`
	}

	_, err := s.executor().ExecContext(ctx, query,
		reset.ID, reset.UserID, reset.Token, reset.ExpiresAt, reset.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create password reset: %w", err)
	}

	return nil
}

// GetPasswordResetByToken retrieves a password reset by token
func (s *SQLStore) GetPasswordResetByToken(ctx context.Context, token string) (*models.PasswordReset, error) {
	query := `
		SELECT id, user_id, token, expires_at, created_at, used_at
		FROM password_resets
		WHERE token = ?
	`

	if s.driver == "postgres" {
		query = `
			SELECT id, user_id, token, expires_at, created_at, used_at
			FROM password_resets
			WHERE token = $1
		`
	}

	reset := &models.PasswordReset{}
	err := s.executor().QueryRowContext(ctx, query, token).Scan(
		&reset.ID, &reset.UserID, &reset.Token,
		&reset.ExpiresAt, &reset.CreatedAt, &reset.UsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("password reset not found")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get password reset: %w", err)
	}

	return reset, nil
}

// MarkPasswordResetUsed marks a password reset as used
func (s *SQLStore) MarkPasswordResetUsed(ctx context.Context, id string) error {
	now := time.Now()
	query := `UPDATE password_resets SET used_at = ? WHERE id = ?`

	if s.driver == "postgres" {
		query = `UPDATE password_resets SET used_at = $1 WHERE id = $2`
	}

	_, err := s.executor().ExecContext(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to mark password reset as used: %w", err)
	}

	return nil
}

// DeleteExpiredPasswordResets deletes expired password resets
func (s *SQLStore) DeleteExpiredPasswordResets(ctx context.Context) error {
	query := `DELETE FROM password_resets WHERE expires_at < ?`

	if s.driver == "postgres" {
		query = `DELETE FROM password_resets WHERE expires_at < $1`
	}

	_, err := s.executor().ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired password resets: %w", err)
	}

	return nil
}
