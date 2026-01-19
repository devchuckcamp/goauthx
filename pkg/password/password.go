package password

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Hasher handles password hashing and verification
type Hasher struct {
	cost int
}

// NewHasher creates a new password hasher
func NewHasher(cost int) *Hasher {
	return &Hasher{
		cost: cost,
	}
}

// Hash hashes a password using bcrypt
func (h *Hasher) Hash(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedBytes), nil
}

// Verify verifies a password against its hash
func (h *Hasher) Verify(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// IsValidPassword checks if a password meets minimum requirements
func IsValidPassword(password string, minLength int) error {
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters", minLength)
	}
	return nil
}
