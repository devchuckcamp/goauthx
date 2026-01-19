package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/devchuckcamp/goauthx/pkg/password"
	"github.com/devchuckcamp/goauthx/pkg/store"
	"github.com/devchuckcamp/goauthx/pkg/tokens"
)

var (
	// ErrInvalidCredentials is returned when credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")

	// ErrUserInactive is returned when a user account is inactive
	ErrUserInactive = errors.New("user account is inactive")

	// ErrEmailAlreadyExists is returned when an email is already registered
	ErrEmailAlreadyExists = errors.New("email already exists")

	// ErrInvalidRefreshToken is returned when a refresh token is invalid
	ErrInvalidRefreshToken = errors.New("invalid refresh token")

	// ErrPermissionDenied is returned when a user lacks required permissions
	ErrPermissionDenied = errors.New("permission denied")
)

// Service provides authentication and authorization functionality
type Service struct {
	store          store.Store
	tokenManager   *tokens.TokenManager
	passwordHasher *password.Hasher
	config         *config.Config
}

// NewService creates a new authentication service
func NewService(cfg *config.Config, store store.Store) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	tokenManager := tokens.NewTokenManager(
		cfg.JWT.Secret,
		cfg.JWT.AccessTokenExpiry,
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
	)

	passwordHasher := password.NewHasher(cfg.Password.BcryptCost)

	return &Service{
		store:          store,
		tokenManager:   tokenManager,
		passwordHasher: passwordHasher,
		config:         cfg,
	}, nil
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// LoginRequest represents a user login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	User         *models.User
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// RequestPasswordResetRequest represents a password reset request
type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

// ResetPasswordRequest represents a password reset with token
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// VerifyEmailRequest represents an email verification request
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// Register registers a new user
func (s *Service) Register(ctx context.Context, req RegisterRequest) (*AuthResponse, error) {
	// Validate password
	if err := password.IsValidPassword(req.Password, s.config.Password.MinLength); err != nil {
		return nil, err
	}

	// Check if email already exists
	existingUser, err := s.store.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, ErrEmailAlreadyExists
	}

	// Hash password
	hashedPassword, err := s.passwordHasher.Hash(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		Email:        req.Email,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Active:       true,
	}

	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// Login authenticates a user with email and password
func (s *Service) Login(ctx context.Context, req LoginRequest) (*AuthResponse, error) {
	// Get user by email
	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check if user is active
	if !user.Active {
		return nil, ErrUserInactive
	}

	// Verify password
	if err := s.passwordHasher.Verify(req.Password, user.PasswordHash); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Generate tokens
	return s.generateAuthResponse(ctx, user)
}

// Logout revokes all refresh tokens for a user
func (s *Service) Logout(ctx context.Context, userID string) error {
	return s.store.RevokeAllRefreshTokensForUser(ctx, userID)
}

// RefreshAccessToken generates a new access token using a refresh token
func (s *Service) RefreshAccessToken(ctx context.Context, refreshTokenString string) (*AuthResponse, error) {
	// Get refresh token
	refreshToken, err := s.store.GetRefreshTokenByToken(ctx, refreshTokenString)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	// Validate refresh token
	if !refreshToken.IsValid() {
		return nil, ErrInvalidRefreshToken
	}

	// Get user
	user, err := s.store.GetUserByID(ctx, refreshToken.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check if user is active
	if !user.Active {
		return nil, ErrUserInactive
	}

	// Generate new tokens
	return s.generateAuthResponse(ctx, user)
}

// ValidateToken validates an access token and returns the claims
func (s *Service) ValidateToken(tokenString string) (*tokens.Claims, error) {
	return s.tokenManager.ValidateAccessToken(tokenString)
}

// HasRole checks if a user has a specific role
func (s *Service) HasRole(ctx context.Context, userID, roleName string) (bool, error) {
	return s.store.HasRole(ctx, userID, roleName)
}

// HasPermission checks if a user has a specific permission
func (s *Service) HasPermission(ctx context.Context, userID, permissionName string) (bool, error) {
	return s.store.HasPermissionByName(ctx, userID, permissionName)
}

// GetUserPermissions retrieves all permissions for a user
func (s *Service) GetUserPermissions(ctx context.Context, userID string) ([]*models.Permission, error) {
	// Get user roles
	roles, err := s.store.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Collect all permissions from all roles
	permMap := make(map[string]*models.Permission)
	for _, role := range roles {
		permissions, err := s.store.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return nil, err
		}

		for _, perm := range permissions {
			permMap[perm.ID] = perm
		}
	}

	// Also include permissions granted directly to the user (if supported by the store)
	type userDirectPermissionReader interface {
		GetUserDirectPermissions(ctx context.Context, userID string) ([]*models.Permission, error)
	}
	if reader, ok := s.store.(userDirectPermissionReader); ok {
		directPerms, err := reader.GetUserDirectPermissions(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, perm := range directPerms {
			permMap[perm.ID] = perm
		}
	}

	// Convert map to slice
	permissions := make([]*models.Permission, 0, len(permMap))
	for _, perm := range permMap {
		permissions = append(permissions, perm)
	}

	return permissions, nil
}

// GetUserRoles retrieves all roles for a user
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]*models.Role, error) {
	return s.store.GetUserRoles(ctx, userID)
}

// AssignRole assigns a role to a user by role name
func (s *Service) AssignRole(ctx context.Context, userID, roleName string) error {
	// Get the role by name
	role, err := s.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Check if user exists
	_, err = s.store.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Check if user already has this role
	hasRole, err := s.store.HasRole(ctx, userID, roleName)
	if err != nil {
		return fmt.Errorf("failed to check role: %w", err)
	}
	if hasRole {
		return nil // Already has the role
	}

	// Assign the role
	return s.store.AssignRole(ctx, userID, role.ID)
}

// AssignRoleByID assigns a role to a user by role ID
func (s *Service) AssignRoleByID(ctx context.Context, userID, roleID string) error {
	// Check if role exists
	_, err := s.store.GetRoleByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Check if user exists
	_, err = s.store.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Assign the role
	return s.store.AssignRole(ctx, userID, roleID)
}

// RemoveRole removes a role from a user by role name
func (s *Service) RemoveRole(ctx context.Context, userID, roleName string) error {
	// Get the role by name
	role, err := s.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Check if user exists
	_, err = s.store.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Remove the role
	return s.store.RemoveRole(ctx, userID, role.ID)
}

// RemoveRoleByID removes a role from a user by role ID
func (s *Service) RemoveRoleByID(ctx context.Context, userID, roleID string) error {
	// Check if role exists
	_, err := s.store.GetRoleByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Check if user exists
	_, err = s.store.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Remove the role
	return s.store.RemoveRole(ctx, userID, roleID)
}

// HasAnyPermission checks if a user has any of the specified permissions
func (s *Service) HasAnyPermission(ctx context.Context, userID string, permissionNames []string) (bool, error) {
	for _, permName := range permissionNames {
		hasPerm, err := s.HasPermission(ctx, userID, permName)
		if err != nil {
			return false, err
		}
		if hasPerm {
			return true, nil
		}
	}
	return false, nil
}

// HasAllPermissions checks if a user has all of the specified permissions
func (s *Service) HasAllPermissions(ctx context.Context, userID string, permissionNames []string) (bool, error) {
	for _, permName := range permissionNames {
		hasPerm, err := s.HasPermission(ctx, userID, permName)
		if err != nil {
			return false, err
		}
		if !hasPerm {
			return false, nil
		}
	}
	return true, nil
}

// HasAnyRole checks if a user has any of the specified roles
func (s *Service) HasAnyRole(ctx context.Context, userID string, roleNames []string) (bool, error) {
	for _, roleName := range roleNames {
		hasRole, err := s.HasRole(ctx, userID, roleName)
		if err != nil {
			return false, err
		}
		if hasRole {
			return true, nil
		}
	}
	return false, nil
}

// HasAllRoles checks if a user has all of the specified roles
func (s *Service) HasAllRoles(ctx context.Context, userID string, roleNames []string) (bool, error) {
	for _, roleName := range roleNames {
		hasRole, err := s.HasRole(ctx, userID, roleName)
		if err != nil {
			return false, err
		}
		if !hasRole {
			return false, nil
		}
	}
	return true, nil
}

// generateAuthResponse generates an authentication response with tokens
func (s *Service) generateAuthResponse(ctx context.Context, user *models.User) (*AuthResponse, error) {
	// Get user roles for JWT claims
	roles, err := s.store.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	// Generate access token
	accessToken, expiresAt, err := s.tokenManager.GenerateAccessToken(user.ID, user.Email, roleNames)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshTokenString, err := tokens.GenerateRefreshToken(s.config.Token.RefreshTokenLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Save refresh token
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshTokenString,
		ExpiresAt: time.Now().Add(s.config.Token.RefreshTokenExpiry),
	}

	if err := s.store.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		ExpiresAt:    expiresAt,
	}, nil
}

// GetUserByID retrieves a user by their ID
func (s *Service) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	return s.store.GetUserByID(ctx, userID)
}

// ChangePassword changes a user's password
func (s *Service) ChangePassword(ctx context.Context, userID string, req ChangePasswordRequest) error {
	// Get user
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify old password
	if err := s.passwordHasher.Verify(req.OldPassword, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}

	// Validate new password
	if err := password.IsValidPassword(req.NewPassword, s.config.Password.MinLength); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := s.passwordHasher.Hash(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = hashedPassword
	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke all refresh tokens for security
	if err := s.store.RevokeAllRefreshTokensForUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}

	return nil
}

// RequestPasswordReset creates a password reset token
func (s *Service) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	// Get user by email
	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		// Don't reveal if email exists
		return "", ErrUserNotFound
	}

	// Generate reset token
	resetToken, err := tokens.GenerateRefreshToken(64)
	if err != nil {
		return "", fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Save password reset
	passwordReset := &models.PasswordReset{
		UserID:    user.ID,
		Token:     resetToken,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiry
	}

	if err := s.store.CreatePasswordReset(ctx, passwordReset); err != nil {
		return "", fmt.Errorf("failed to save password reset: %w", err)
	}

	// In production, send email here
	// emailService.SendPasswordResetEmail(user.Email, resetToken)

	return resetToken, nil
}

// ResetPassword resets a user's password using a reset token
func (s *Service) ResetPassword(ctx context.Context, req ResetPasswordRequest) error {
	// Get password reset by token
	passwordReset, err := s.store.GetPasswordResetByToken(ctx, req.Token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Validate token
	if !passwordReset.IsValid() {
		return errors.New("invalid or expired reset token")
	}

	// Validate new password
	if err := password.IsValidPassword(req.NewPassword, s.config.Password.MinLength); err != nil {
		return err
	}

	// Get user
	user, err := s.store.GetUserByID(ctx, passwordReset.UserID)
	if err != nil {
		return ErrUserNotFound
	}

	// Hash new password
	hashedPassword, err := s.passwordHasher.Hash(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = hashedPassword
	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used
	if err := s.store.MarkPasswordResetUsed(ctx, passwordReset.ID); err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	// Revoke all refresh tokens for security
	if err := s.store.RevokeAllRefreshTokensForUser(ctx, passwordReset.UserID); err != nil {
		return fmt.Errorf("failed to revoke tokens: %w", err)
	}

	return nil
}

// VerifyEmail verifies a user's email using a verification token
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	// Get email verification by token
	verification, err := s.store.GetEmailVerificationByToken(ctx, token)
	if err != nil {
		return errors.New("invalid or expired verification token")
	}

	// Validate token
	if !verification.IsValid() {
		return errors.New("invalid or expired verification token")
	}

	// Get user
	user, err := s.store.GetUserByID(ctx, verification.UserID)
	if err != nil {
		return ErrUserNotFound
	}

	// Mark email as verified
	user.EmailVerified = true
	if err := s.store.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	// Mark token as used
	if err := s.store.MarkEmailVerificationUsed(ctx, verification.ID); err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	return nil
}

// ResendVerificationEmail creates a new verification token and sends email
func (s *Service) ResendVerificationEmail(ctx context.Context, userID string) (string, error) {
	// Get user
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return "", ErrUserNotFound
	}

	// Check if already verified
	if user.EmailVerified {
		return "", errors.New("email already verified")
	}

	// Generate verification token
	verificationToken, err := tokens.GenerateRefreshToken(64)
	if err != nil {
		return "", fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Save email verification
	emailVerification := &models.EmailVerification{
		UserID:    user.ID,
		Token:     verificationToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour expiry
	}

	if err := s.store.CreateEmailVerification(ctx, emailVerification); err != nil {
		return "", fmt.Errorf("failed to save email verification: %w", err)
	}

	// In production, send email here
	// emailService.SendVerificationEmail(user.Email, verificationToken)

	return verificationToken, nil
}
