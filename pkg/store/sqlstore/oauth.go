package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
)

// CreateOAuthAccount creates a new OAuth account
func (s *SQLStore) CreateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	now := time.Now()
	account.CreatedAt = now
	account.UpdatedAt = now

	query := `
		INSERT INTO oauth_accounts (
			id, user_id, provider, provider_id, email, name, picture,
			access_token, refresh_token, expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	if s.driver == "postgres" {
		query = `
			INSERT INTO oauth_accounts (
				id, user_id, provider, provider_id, email, name, picture,
				access_token, refresh_token, expires_at, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`
	}

	_, err := s.db.ExecContext(ctx, query,
		account.ID,
		account.UserID,
		account.Provider,
		account.ProviderID,
		account.Email,
		account.Name,
		account.Picture,
		account.AccessToken,
		account.RefreshToken,
		account.ExpiresAt,
		account.CreatedAt,
		account.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create oauth account: %w", err)
	}

	return nil
}

// GetOAuthAccountByProviderID retrieves an OAuth account by provider and provider ID
func (s *SQLStore) GetOAuthAccountByProviderID(ctx context.Context, provider models.OAuthProvider, providerID string) (*models.OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, email, name, picture,
			   access_token, refresh_token, expires_at, created_at, updated_at
		FROM oauth_accounts
		WHERE provider = ? AND provider_id = ?
	`

	if s.driver == "postgres" {
		query = `
			SELECT id, user_id, provider, provider_id, email, name, picture,
				   access_token, refresh_token, expires_at, created_at, updated_at
			FROM oauth_accounts
			WHERE provider = $1 AND provider_id = $2
		`
	}

	var account models.OAuthAccount
	err := s.db.QueryRowContext(ctx, query, provider, providerID).Scan(
		&account.ID,
		&account.UserID,
		&account.Provider,
		&account.ProviderID,
		&account.Email,
		&account.Name,
		&account.Picture,
		&account.AccessToken,
		&account.RefreshToken,
		&account.ExpiresAt,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("oauth account not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get oauth account: %w", err)
	}

	return &account, nil
}

// GetOAuthAccountsByUserID retrieves all OAuth accounts for a user
func (s *SQLStore) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*models.OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, email, name, picture,
			   access_token, refresh_token, expires_at, created_at, updated_at
		FROM oauth_accounts
		WHERE user_id = ?
		ORDER BY created_at DESC
	`

	if s.driver == "postgres" {
		query = `
			SELECT id, user_id, provider, provider_id, email, name, picture,
				   access_token, refresh_token, expires_at, created_at, updated_at
			FROM oauth_accounts
			WHERE user_id = $1
			ORDER BY created_at DESC
		`
	}

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query oauth accounts: %w", err)
	}
	defer rows.Close()

	var accounts []*models.OAuthAccount
	for rows.Next() {
		var account models.OAuthAccount
		err := rows.Scan(
			&account.ID,
			&account.UserID,
			&account.Provider,
			&account.ProviderID,
			&account.Email,
			&account.Name,
			&account.Picture,
			&account.AccessToken,
			&account.RefreshToken,
			&account.ExpiresAt,
			&account.CreatedAt,
			&account.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan oauth account: %w", err)
		}
		accounts = append(accounts, &account)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating oauth accounts: %w", err)
	}

	return accounts, nil
}

// UpdateOAuthAccount updates an existing OAuth account
func (s *SQLStore) UpdateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	account.UpdatedAt = time.Now()

	query := `
		UPDATE oauth_accounts
		SET email = ?, name = ?, picture = ?, access_token = ?,
			refresh_token = ?, expires_at = ?, updated_at = ?
		WHERE id = ?
	`

	if s.driver == "postgres" {
		query = `
			UPDATE oauth_accounts
			SET email = $1, name = $2, picture = $3, access_token = $4,
				refresh_token = $5, expires_at = $6, updated_at = $7
			WHERE id = $8
		`
	}

	result, err := s.db.ExecContext(ctx, query,
		account.Email,
		account.Name,
		account.Picture,
		account.AccessToken,
		account.RefreshToken,
		account.ExpiresAt,
		account.UpdatedAt,
		account.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update oauth account: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("oauth account not found")
	}

	return nil
}

// DeleteOAuthAccount deletes an OAuth account
func (s *SQLStore) DeleteOAuthAccount(ctx context.Context, id string) error {
	query := `DELETE FROM oauth_accounts WHERE id = ?`

	if s.driver == "postgres" {
		query = `DELETE FROM oauth_accounts WHERE id = $1`
	}

	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete oauth account: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("oauth account not found")
	}

	return nil
}
