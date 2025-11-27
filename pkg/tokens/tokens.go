package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// TokenPair represents an access token and refresh token pair
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// TokenManager handles JWT token operations
type TokenManager struct {
	secret            []byte
	accessTokenExpiry time.Duration
	issuer            string
	audience          string
}

// NewTokenManager creates a new TokenManager
func NewTokenManager(secret string, accessTokenExpiry time.Duration, issuer, audience string) *TokenManager {
	return &TokenManager{
		secret:            []byte(secret),
		accessTokenExpiry: accessTokenExpiry,
		issuer:            issuer,
		audience:          audience,
	}
}

// GenerateAccessToken generates a new JWT access token
func (tm *TokenManager) GenerateAccessToken(userID, email string, roles []string) (string, time.Time, error) {
	expiresAt := time.Now().Add(tm.accessTokenExpiry)
	
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    tm.issuer,
			Audience:  jwt.ClaimStrings{tm.audience},
			Subject:   userID,
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(tm.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}
	
	return tokenString, expiresAt, nil
}

// ValidateAccessToken validates and parses a JWT access token
func (tm *TokenManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	
	return claims, nil
}

// GenerateRefreshToken generates a cryptographically secure random refresh token
func GenerateRefreshToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	
	return base64.URLEncoding.EncodeToString(b), nil
}

// ExtractToken extracts the token from an Authorization header
// Expects format: "Bearer <token>"
func ExtractToken(authHeader string) (string, error) {
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", fmt.Errorf("invalid authorization header format")
	}
	return authHeader[7:], nil
}
