package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// GoogleOAuthURLRequest contains parameters for generating OAuth URL
type GoogleOAuthURLRequest struct {
	State string // CSRF protection token
}

// GoogleOAuthCallbackRequest contains parameters from OAuth callback
type GoogleOAuthCallbackRequest struct {
	Code  string
	State string
}

// GetGoogleOAuthURL generates the Google OAuth authorization URL
func (s *Service) GetGoogleOAuthURL(req GoogleOAuthURLRequest) (string, error) {
	if !s.config.OAuth.Google.Enabled {
		return "", fmt.Errorf("google oauth is not enabled")
	}

	config := s.getGoogleOAuthConfig()
	url := config.AuthCodeURL(req.State, oauth2.AccessTypeOffline)
	return url, nil
}

// HandleGoogleOAuthCallback handles the OAuth callback and creates/logs in user
func (s *Service) HandleGoogleOAuthCallback(ctx context.Context, req GoogleOAuthCallbackRequest) (*AuthResponse, error) {
	if !s.config.OAuth.Google.Enabled {
		return nil, fmt.Errorf("google oauth is not enabled")
	}

	// Exchange code for token
	config := s.getGoogleOAuthConfig()
	token, err := config.Exchange(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from Google
	googleUser, err := s.getGoogleUserInfo(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Check if OAuth account already exists
	oauthAccount, err := s.store.GetOAuthAccountByProviderID(ctx, models.OAuthProviderGoogle, googleUser.ID)
	if err == nil {
		// Existing user - update tokens and login
		return s.loginExistingOAuthUser(ctx, oauthAccount, token, googleUser)
	}

	// Check if user exists with same email
	existingUser, err := s.store.GetUserByEmail(ctx, googleUser.Email)
	if err == nil {
		// Link OAuth account to existing user
		return s.linkOAuthToExistingUser(ctx, existingUser, token, googleUser)
	}

	// Create new user
	return s.createNewOAuthUser(ctx, token, googleUser)
}

// GetGoogleOAuthAccounts retrieves all Google OAuth accounts for a user
func (s *Service) GetGoogleOAuthAccounts(ctx context.Context, userID string) ([]*models.OAuthAccount, error) {
	accounts, err := s.store.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get oauth accounts: %w", err)
	}

	// Filter for Google accounts only
	var googleAccounts []*models.OAuthAccount
	for _, account := range accounts {
		if account.Provider == models.OAuthProviderGoogle {
			googleAccounts = append(googleAccounts, account)
		}
	}

	return googleAccounts, nil
}

// UnlinkGoogleOAuth unlinks a Google OAuth account from a user
func (s *Service) UnlinkGoogleOAuth(ctx context.Context, userID string, accountID string) error {
	// Get the account to verify it belongs to the user
	accounts, err := s.store.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get oauth accounts: %w", err)
	}

	var found bool
	for _, account := range accounts {
		if account.ID == accountID && account.Provider == models.OAuthProviderGoogle {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("oauth account not found or doesn't belong to user")
	}

	// Check if user has a password - can't unlink if it's their only auth method
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.PasswordHash == "" {
		// Check if user has other OAuth accounts
		if len(accounts) <= 1 {
			return fmt.Errorf("cannot unlink: this is your only authentication method")
		}
	}

	// Delete the OAuth account
	if err := s.store.DeleteOAuthAccount(ctx, accountID); err != nil {
		return fmt.Errorf("failed to delete oauth account: %w", err)
	}

	return nil
}

// Helper functions

func (s *Service) getGoogleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.config.OAuth.Google.ClientID,
		ClientSecret: s.config.OAuth.Google.ClientSecret,
		RedirectURL:  s.config.OAuth.Google.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func (s *Service) getGoogleUserInfo(ctx context.Context, accessToken string) (*models.GoogleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", googleUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google api error: %s - %s", resp.Status, string(body))
	}

	var googleUser models.GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &googleUser, nil
}

func (s *Service) loginExistingOAuthUser(ctx context.Context, oauthAccount *models.OAuthAccount, token *oauth2.Token, googleUser *models.GoogleUserInfo) (*AuthResponse, error) {
	// Update OAuth account tokens
	oauthAccount.AccessToken = token.AccessToken
	oauthAccount.RefreshToken = token.RefreshToken
	if !token.Expiry.IsZero() {
		oauthAccount.ExpiresAt = &token.Expiry
	}
	oauthAccount.Email = googleUser.Email
	oauthAccount.Name = googleUser.Name
	oauthAccount.Picture = googleUser.Picture

	if err := s.store.UpdateOAuthAccount(ctx, oauthAccount); err != nil {
		return nil, fmt.Errorf("failed to update oauth account: %w", err)
	}

	// Get user
	user, err := s.store.GetUserByID(ctx, oauthAccount.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate JWT tokens
	return s.generateAuthResponse(ctx, user)
}

func (s *Service) linkOAuthToExistingUser(ctx context.Context, user *models.User, token *oauth2.Token, googleUser *models.GoogleUserInfo) (*AuthResponse, error) {
	// Create OAuth account linked to existing user
	oauthAccount := &models.OAuthAccount{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     models.OAuthProviderGoogle,
		ProviderID:   googleUser.ID,
		Email:        googleUser.Email,
		Name:         googleUser.Name,
		Picture:      googleUser.Picture,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if !token.Expiry.IsZero() {
		oauthAccount.ExpiresAt = &token.Expiry
	}

	if err := s.store.CreateOAuthAccount(ctx, oauthAccount); err != nil {
		return nil, fmt.Errorf("failed to create oauth account: %w", err)
	}

	// If email is verified by Google, mark user's email as verified
	if googleUser.VerifiedEmail && !user.EmailVerified {
		user.EmailVerified = true
		if err := s.store.UpdateUser(ctx, user); err != nil {
			// Log error but don't fail the operation
			fmt.Printf("Warning: failed to update email verification status: %v\n", err)
		}
	}

	// Generate JWT tokens
	return s.generateAuthResponse(ctx, user)
}

func (s *Service) createNewOAuthUser(ctx context.Context, token *oauth2.Token, googleUser *models.GoogleUserInfo) (*AuthResponse, error) {
	// Create new user
	user := &models.User{
		ID:            uuid.New().String(),
		Email:         googleUser.Email,
		FirstName:     googleUser.GivenName,
		LastName:      googleUser.FamilyName,
		Active:        true,
		EmailVerified: googleUser.VerifiedEmail,
		PasswordHash:  "", // No password for OAuth-only users
	}

	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create OAuth account
	oauthAccount := &models.OAuthAccount{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     models.OAuthProviderGoogle,
		ProviderID:   googleUser.ID,
		Email:        googleUser.Email,
		Name:         googleUser.Name,
		Picture:      googleUser.Picture,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if !token.Expiry.IsZero() {
		oauthAccount.ExpiresAt = &token.Expiry
	}

	if err := s.store.CreateOAuthAccount(ctx, oauthAccount); err != nil {
		// Rollback user creation would require transaction support
		return nil, fmt.Errorf("failed to create oauth account: %w", err)
	}

	// Generate JWT tokens
	return s.generateAuthResponse(ctx, user)
}

// ParseGoogleOAuthCallback parses the OAuth callback parameters from URL
func ParseGoogleOAuthCallback(callbackURL string) (*GoogleOAuthCallbackRequest, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return nil, fmt.Errorf("invalid callback URL: %w", err)
	}

	query := u.Query()
	code := query.Get("code")
	state := query.Get("state")
	errorParam := query.Get("error")

	if errorParam != "" {
		errorDesc := query.Get("error_description")
		return nil, fmt.Errorf("oauth error: %s - %s", errorParam, errorDesc)
	}

	if code == "" {
		return nil, fmt.Errorf("missing authorization code")
	}

	return &GoogleOAuthCallbackRequest{
		Code:  code,
		State: state,
	}, nil
}

// ParseGoogleOAuthCallbackFromForm parses OAuth callback from form data
func ParseGoogleOAuthCallbackFromForm(form url.Values) (*GoogleOAuthCallbackRequest, error) {
	code := form.Get("code")
	state := form.Get("state")
	errorParam := form.Get("error")

	if errorParam != "" {
		errorDesc := form.Get("error_description")
		if errorDesc == "" {
			errorDesc = "unknown error"
		}
		return nil, fmt.Errorf("oauth error: %s - %s", errorParam, strings.ReplaceAll(errorDesc, "+", " "))
	}

	if code == "" {
		return nil, fmt.Errorf("missing authorization code")
	}

	return &GoogleOAuthCallbackRequest{
		Code:  code,
		State: state,
	}, nil
}
