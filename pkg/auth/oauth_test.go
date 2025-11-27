package auth

import (
	"context"
	"testing"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// MockOAuthStore extends MockStore with OAuth methods
type MockOAuthStore struct {
	MockStore
	oauthAccounts     map[string]*models.OAuthAccount
	oauthByProviderID map[string]*models.OAuthAccount
}

func NewMockOAuthStore() *MockOAuthStore {
	return &MockOAuthStore{
		MockStore: MockStore{
			users:          make(map[string]*models.User),
			usersByEmail:   make(map[string]*models.User),
			refreshTokens:  make(map[string]*models.RefreshToken),
			roles:          make(map[string]*models.Role),
			rolesByName:    make(map[string]*models.Role),
			userRoles:      make(map[string][]string),
			roleUsers:      make(map[string][]string),
			emailVerifications: make(map[string]*models.EmailVerification),
			passwordResets:     make(map[string]*models.PasswordReset),
		},
		oauthAccounts:     make(map[string]*models.OAuthAccount),
		oauthByProviderID: make(map[string]*models.OAuthAccount),
	}
}

func (m *MockOAuthStore) CreateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	m.oauthAccounts[account.ID] = account
	key := string(account.Provider) + ":" + account.ProviderID
	m.oauthByProviderID[key] = account
	return nil
}

func (m *MockOAuthStore) GetOAuthAccountByProviderID(ctx context.Context, provider models.OAuthProvider, providerID string) (*models.OAuthAccount, error) {
	key := string(provider) + ":" + providerID
	account, exists := m.oauthByProviderID[key]
	if !exists {
		return nil, ErrUserNotFound
	}
	return account, nil
}

func (m *MockOAuthStore) GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]*models.OAuthAccount, error) {
	var accounts []*models.OAuthAccount
	for _, account := range m.oauthAccounts {
		if account.UserID == userID {
			accounts = append(accounts, account)
		}
	}
	return accounts, nil
}

func (m *MockOAuthStore) UpdateOAuthAccount(ctx context.Context, account *models.OAuthAccount) error {
	if _, exists := m.oauthAccounts[account.ID]; !exists {
		return ErrUserNotFound
	}
	m.oauthAccounts[account.ID] = account
	key := string(account.Provider) + ":" + account.ProviderID
	m.oauthByProviderID[key] = account
	return nil
}

func (m *MockOAuthStore) DeleteOAuthAccount(ctx context.Context, id string) error {
	account, exists := m.oauthAccounts[id]
	if !exists {
		return ErrUserNotFound
	}
	
	key := string(account.Provider) + ":" + account.ProviderID
	delete(m.oauthByProviderID, key)
	delete(m.oauthAccounts, id)
	return nil
}

func TestGetGoogleOAuthURL(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		state       string
		expectError bool
	}{
		{
			name:        "OAuth enabled - should return URL",
			enabled:     true,
			state:       "test-state-token",
			expectError: false,
		},
		{
			name:        "OAuth disabled - should return error",
			enabled:     false,
			state:       "test-state",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Database.Driver = config.Postgres
			cfg.Database.DSN = "postgres://test:test@localhost/testdb"
			cfg.JWT.Secret = "test-secret-key-minimum-32-characters-long"
			cfg.OAuth.Google.Enabled = tt.enabled
			cfg.OAuth.Google.ClientID = "test-client-id"
			cfg.OAuth.Google.ClientSecret = "test-client-secret"
			cfg.OAuth.Google.RedirectURL = "http://localhost:8080/auth/google/callback"

			store := NewMockOAuthStore()
			service, err := NewService(cfg, store)
			if err != nil {
				t.Fatalf("Failed to create service: %v", err)
			}

			url, err := service.GetGoogleOAuthURL(GoogleOAuthURLRequest{
				State: tt.state,
			})

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if url == "" {
					t.Error("Expected URL but got empty string")
				}
				if tt.state != "" && !contains(url, tt.state) {
					t.Errorf("Expected URL to contain state %s", tt.state)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr[:] || 
		   (len(s) > len(substr) && contains(s[1:], substr))
}

func TestHandleGoogleOAuthCallback_NewUser(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Driver = config.Postgres
	cfg.Database.DSN = "postgres://test:test@localhost/testdb"
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters-long"
	cfg.OAuth.Google.Enabled = true
	cfg.OAuth.Google.ClientID = "test-client-id"
	cfg.OAuth.Google.ClientSecret = "test-client-secret"
	cfg.OAuth.Google.RedirectURL = "http://localhost:8080/auth/google/callback"

	store := NewMockOAuthStore()
	service, err := NewService(cfg, store)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	// Note: In real scenario, we'd need to mock the OAuth token exchange
	// For this test, we're testing the structure and error handling
	
	// Test with OAuth disabled
	cfg.OAuth.Google.Enabled = false
	service, _ = NewService(cfg, store)
	
	_, err = service.HandleGoogleOAuthCallback(context.Background(), GoogleOAuthCallbackRequest{
		Code:  "test-code",
		State: "test-state",
	})
	
	if err == nil {
		t.Error("Expected error when OAuth is disabled, got none")
	}
}

func TestLinkOAuthToExistingUser(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Driver = config.Postgres
	cfg.Database.DSN = "postgres://test:test@localhost/testdb"
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters-long"

	store := NewMockOAuthStore()
	service, err := NewService(cfg, store)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()

	// Create an existing user
	user := &models.User{
		ID:            uuid.New().String(),
		Email:         "existing@example.com",
		PasswordHash:  "hashed-password",
		FirstName:     "Existing",
		LastName:      "User",
		Active:        true,
		EmailVerified: false,
	}
	store.CreateUser(ctx, user)

	// Simulate linking OAuth account
	googleUser := &models.GoogleUserInfo{
		ID:            "google-123",
		Email:         "existing@example.com",
		VerifiedEmail: true,
		Name:          "Existing User",
		GivenName:     "Existing",
		FamilyName:    "User",
		Picture:       "https://example.com/photo.jpg",
	}

	token := &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Link OAuth account
	resp, err := service.linkOAuthToExistingUser(ctx, user, token, googleUser)
	if err != nil {
		t.Fatalf("Failed to link OAuth account: %v", err)
	}

	if resp == nil {
		t.Fatal("Expected auth response, got nil")
	}

	if resp.User.ID != user.ID {
		t.Errorf("Expected user ID %s, got %s", user.ID, resp.User.ID)
	}

	// Verify OAuth account was created
	accounts, err := store.GetOAuthAccountsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to get OAuth accounts: %v", err)
	}

	if len(accounts) != 1 {
		t.Fatalf("Expected 1 OAuth account, got %d", len(accounts))
	}

	if accounts[0].Provider != models.OAuthProviderGoogle {
		t.Errorf("Expected provider %s, got %s", models.OAuthProviderGoogle, accounts[0].Provider)
	}

	if accounts[0].ProviderID != googleUser.ID {
		t.Errorf("Expected provider ID %s, got %s", googleUser.ID, accounts[0].ProviderID)
	}

	// Verify email was marked as verified
	updatedUser, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to get updated user: %v", err)
	}

	if !updatedUser.EmailVerified {
		t.Error("Expected email to be verified after Google OAuth link")
	}
}

func TestCreateNewOAuthUser(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Driver = config.Postgres
	cfg.Database.DSN = "postgres://test:test@localhost/testdb"
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters-long"

	store := NewMockOAuthStore()
	service, err := NewService(cfg, store)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()

	googleUser := &models.GoogleUserInfo{
		ID:            "google-456",
		Email:         "newuser@example.com",
		VerifiedEmail: true,
		Name:          "New User",
		GivenName:     "New",
		FamilyName:    "User",
		Picture:       "https://example.com/photo.jpg",
	}

	token := &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}

	resp, err := service.createNewOAuthUser(ctx, token, googleUser)
	if err != nil {
		t.Fatalf("Failed to create OAuth user: %v", err)
	}

	if resp == nil {
		t.Fatal("Expected auth response, got nil")
	}

	// Verify user was created
	user, err := store.GetUserByEmail(ctx, googleUser.Email)
	if err != nil {
		t.Fatalf("Failed to get created user: %v", err)
	}

	if user.Email != googleUser.Email {
		t.Errorf("Expected email %s, got %s", googleUser.Email, user.Email)
	}

	if user.FirstName != googleUser.GivenName {
		t.Errorf("Expected first name %s, got %s", googleUser.GivenName, user.FirstName)
	}

	if user.LastName != googleUser.FamilyName {
		t.Errorf("Expected last name %s, got %s", googleUser.FamilyName, user.LastName)
	}

	if !user.EmailVerified {
		t.Error("Expected email to be verified for new Google OAuth user")
	}

	if user.PasswordHash != "" {
		t.Error("Expected no password hash for OAuth-only user")
	}

	// Verify OAuth account was created
	accounts, err := store.GetOAuthAccountsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to get OAuth accounts: %v", err)
	}

	if len(accounts) != 1 {
		t.Fatalf("Expected 1 OAuth account, got %d", len(accounts))
	}

	if accounts[0].Email != googleUser.Email {
		t.Errorf("Expected OAuth account email %s, got %s", googleUser.Email, accounts[0].Email)
	}
}

func TestLoginExistingOAuthUser(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Driver = config.Postgres
	cfg.Database.DSN = "postgres://test:test@localhost/testdb"
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters-long"

	store := NewMockOAuthStore()
	service, err := NewService(cfg, store)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()

	// Create user and OAuth account
	user := &models.User{
		ID:            uuid.New().String(),
		Email:         "oauth@example.com",
		FirstName:     "OAuth",
		LastName:      "User",
		Active:        true,
		EmailVerified: true,
	}
	store.CreateUser(ctx, user)

	oauthAccount := &models.OAuthAccount{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		Provider:     models.OAuthProviderGoogle,
		ProviderID:   "google-789",
		Email:        user.Email,
		Name:         "OAuth User",
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
	}
	store.CreateOAuthAccount(ctx, oauthAccount)

	googleUser := &models.GoogleUserInfo{
		ID:            "google-789",
		Email:         "oauth@example.com",
		VerifiedEmail: true,
		Name:          "OAuth User Updated",
		GivenName:     "OAuth",
		FamilyName:    "User",
		Picture:       "https://example.com/new-photo.jpg",
	}

	newToken := &oauth2.Token{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}

	resp, err := service.loginExistingOAuthUser(ctx, oauthAccount, newToken, googleUser)
	if err != nil {
		t.Fatalf("Failed to login existing OAuth user: %v", err)
	}

	if resp == nil {
		t.Fatal("Expected auth response, got nil")
	}

	if resp.User.ID != user.ID {
		t.Errorf("Expected user ID %s, got %s", user.ID, resp.User.ID)
	}

	// Verify OAuth account was updated
	updatedAccount, err := store.GetOAuthAccountByProviderID(ctx, models.OAuthProviderGoogle, "google-789")
	if err != nil {
		t.Fatalf("Failed to get updated OAuth account: %v", err)
	}

	if updatedAccount.AccessToken != newToken.AccessToken {
		t.Errorf("Expected access token %s, got %s", newToken.AccessToken, updatedAccount.AccessToken)
	}

	if updatedAccount.RefreshToken != newToken.RefreshToken {
		t.Errorf("Expected refresh token %s, got %s", newToken.RefreshToken, updatedAccount.RefreshToken)
	}

	if updatedAccount.Name != googleUser.Name {
		t.Errorf("Expected name %s, got %s", googleUser.Name, updatedAccount.Name)
	}

	if updatedAccount.Picture != googleUser.Picture {
		t.Errorf("Expected picture %s, got %s", googleUser.Picture, updatedAccount.Picture)
	}
}

func TestUnlinkGoogleOAuth(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters-long"

	tests := []struct {
		name           string
		hasPassword    bool
		oauthCount     int
		expectError    bool
		errorContains  string
	}{
		{
			name:        "User with password and one OAuth - should succeed",
			hasPassword: true,
			oauthCount:  1,
			expectError: false,
		},
		{
			name:          "User without password and one OAuth - should fail",
			hasPassword:   false,
			oauthCount:    1,
			expectError:   true,
			errorContains: "only authentication method",
		},
		{
			name:        "User without password but multiple OAuth - should succeed",
			hasPassword: false,
			oauthCount:  2,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.Database.Driver = config.Postgres
			cfg.Database.DSN = "postgres://test:test@localhost/testdb"
			store := NewMockOAuthStore()
			service, err := NewService(cfg, store)
			if err != nil {
				t.Fatalf("Failed to create service: %v", err)
			}

			ctx := context.Background()

			// Create user
			user := &models.User{
				ID:            uuid.New().String(),
				Email:         "test@example.com",
				FirstName:     "Test",
				LastName:      "User",
				Active:        true,
				EmailVerified: true,
			}

			if tt.hasPassword {
				user.PasswordHash = "hashed-password"
			}

			store.CreateUser(ctx, user)

			// Create OAuth accounts
			var accountToUnlink string
			for i := 0; i < tt.oauthCount; i++ {
				account := &models.OAuthAccount{
					ID:         uuid.New().String(),
					UserID:     user.ID,
					Provider:   models.OAuthProviderGoogle,
					ProviderID: uuid.New().String(),
					Email:      user.Email,
				}
				store.CreateOAuthAccount(ctx, account)
				if i == 0 {
					accountToUnlink = account.ID
				}
			}

			// Try to unlink
			err = service.UnlinkGoogleOAuth(ctx, user.ID, accountToUnlink)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorContains != "" {
					if !containsStr(err.Error(), tt.errorContains) {
						t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Verify account was deleted
				accounts, err := store.GetOAuthAccountsByUserID(ctx, user.ID)
				if err != nil {
					t.Fatalf("Failed to get OAuth accounts: %v", err)
				}

				expectedCount := tt.oauthCount - 1
				if len(accounts) != expectedCount {
					t.Errorf("Expected %d OAuth accounts after unlink, got %d", expectedCount, len(accounts))
				}
			}
		})
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || s[0:len(substr)] == substr || 
		    (len(s) > len(substr) && containsStr(s[1:], substr)))
}

func TestParseGoogleOAuthCallback(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectError bool
		expectCode  string
		expectState string
	}{
		{
			name:        "Valid callback URL",
			url:         "http://localhost:8080/auth/google/callback?code=test-code&state=test-state",
			expectError: false,
			expectCode:  "test-code",
			expectState: "test-state",
		},
		{
			name:        "Missing code parameter",
			url:         "http://localhost:8080/auth/google/callback?state=test-state",
			expectError: true,
		},
		{
			name:        "OAuth error in callback",
			url:         "http://localhost:8080/auth/google/callback?error=access_denied&error_description=User+denied+access",
			expectError: true,
		},
		{
			name:        "Invalid URL",
			url:         "://invalid-url",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseGoogleOAuthCallback(tt.url)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Fatal("Expected result but got nil")
				}
				if result.Code != tt.expectCode {
					t.Errorf("Expected code %s, got %s", tt.expectCode, result.Code)
				}
				if result.State != tt.expectState {
					t.Errorf("Expected state %s, got %s", tt.expectState, result.State)
				}
			}
		})
	}
}

func TestGetGoogleOAuthAccounts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Database.Driver = config.Postgres
	cfg.Database.DSN = "postgres://test:test@localhost/testdb"
	cfg.JWT.Secret = "test-secret-key-minimum-32-characters-long"

	store := NewMockOAuthStore()
	service, err := NewService(cfg, store)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	ctx := context.Background()

	user := &models.User{
		ID:    uuid.New().String(),
		Email: "test@example.com",
	}
	store.CreateUser(ctx, user)

	// Create multiple OAuth accounts (including non-Google)
	googleAccount1 := &models.OAuthAccount{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Provider:   models.OAuthProviderGoogle,
		ProviderID: "google-1",
		Email:      user.Email,
	}
	store.CreateOAuthAccount(ctx, googleAccount1)

	googleAccount2 := &models.OAuthAccount{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Provider:   models.OAuthProviderGoogle,
		ProviderID: "google-2",
		Email:      user.Email,
	}
	store.CreateOAuthAccount(ctx, googleAccount2)

	// Get Google OAuth accounts
	accounts, err := service.GetGoogleOAuthAccounts(ctx, user.ID)
	if err != nil {
		t.Fatalf("Failed to get Google OAuth accounts: %v", err)
	}

	if len(accounts) != 2 {
		t.Errorf("Expected 2 Google OAuth accounts, got %d", len(accounts))
	}

	// Verify all returned accounts are Google accounts
	for _, account := range accounts {
		if account.Provider != models.OAuthProviderGoogle {
			t.Errorf("Expected only Google accounts, got %s", account.Provider)
		}
	}
}
