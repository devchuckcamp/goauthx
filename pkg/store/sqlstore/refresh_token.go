package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/google/uuid"
)

// CreateRefreshToken creates a new refresh token
func (s *SQLStore) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}

	token.CreatedAt = time.Now()

	query := `INSERT INTO refresh_tokens (id, user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		query = `INSERT INTO refresh_tokens (id, user_id, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)`
	}

	_, err := s.executor().ExecContext(ctx, query, token.ID, token.UserID, token.Token, token.ExpiresAt, token.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}

	return nil
}

// GetRefreshTokenByToken retrieves a refresh token by its token string
func (s *SQLStore) GetRefreshTokenByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	query := `SELECT id, user_id, token, expires_at, created_at, revoked_at FROM refresh_tokens WHERE token = ?`
	if s.driver == "postgres" {
		query = `SELECT id, user_id, token, expires_at, created_at, revoked_at FROM refresh_tokens WHERE token = $1`
	}

	rt := &models.RefreshToken{}
	err := s.executor().QueryRowContext(ctx, query, token).Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return rt, nil
}

// GetRefreshTokensByUserID retrieves all refresh tokens for a user
func (s *SQLStore) GetRefreshTokensByUserID(ctx context.Context, userID string) ([]*models.RefreshToken, error) {
	query := `SELECT id, user_id, token, expires_at, created_at, revoked_at FROM refresh_tokens WHERE user_id = ? ORDER BY created_at DESC`
	if s.driver == "postgres" {
		query = `SELECT id, user_id, token, expires_at, created_at, revoked_at FROM refresh_tokens WHERE user_id = $1 ORDER BY created_at DESC`
	}

	rows, err := s.executor().QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*models.RefreshToken
	for rows.Next() {
		rt := &models.RefreshToken{}
		if err := rows.Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt); err != nil {
			return nil, fmt.Errorf("failed to scan refresh token: %w", err)
		}
		tokens = append(tokens, rt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating refresh tokens: %w", err)
	}

	return tokens, nil
}

// RevokeRefreshToken revokes a refresh token
func (s *SQLStore) RevokeRefreshToken(ctx context.Context, token string) error {
	now := time.Now()
	query := `UPDATE refresh_tokens SET revoked_at = ? WHERE token = ?`
	if s.driver == "postgres" {
		query = `UPDATE refresh_tokens SET revoked_at = $1 WHERE token = $2`
	}

	_, err := s.executor().ExecContext(ctx, query, now, token)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

// RevokeAllRefreshTokensForUser revokes all refresh tokens for a user
func (s *SQLStore) RevokeAllRefreshTokensForUser(ctx context.Context, userID string) error {
	now := time.Now()
	query := `UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`
	if s.driver == "postgres" {
		query = `UPDATE refresh_tokens SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`
	}

	_, err := s.executor().ExecContext(ctx, query, now, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all refresh tokens: %w", err)
	}

	return nil
}

// DeleteExpiredRefreshTokens deletes all expired refresh tokens
func (s *SQLStore) DeleteExpiredRefreshTokens(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < ?`
	if s.driver == "postgres" {
		query = `DELETE FROM refresh_tokens WHERE expires_at < $1`
	}

	_, err := s.executor().ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}

	return nil
}
