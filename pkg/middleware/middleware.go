package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/devchuckcamp/goauthx/pkg/auth"
	"github.com/devchuckcamp/goauthx/pkg/tokens"
)

// ContextKey is the type for context keys
type ContextKey string

const (
	// UserIDKey is the context key for user ID
	UserIDKey ContextKey = "user_id"
	
	// UserEmailKey is the context key for user email
	UserEmailKey ContextKey = "user_email"
	
	// UserRolesKey is the context key for user roles
	UserRolesKey ContextKey = "user_roles"
	
	// ClaimsKey is the context key for JWT claims
	ClaimsKey ContextKey = "claims"
)

// AuthMiddleware is a middleware that validates JWT tokens
type AuthMiddleware struct {
	service *auth.Service
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(service *auth.Service) *AuthMiddleware {
	return &AuthMiddleware{
		service: service,
	}
}

// Authenticate returns a middleware that validates JWT tokens
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}
		
		tokenString, err := tokens.ExtractToken(authHeader)
		if err != nil {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}
		
		// Validate token
		claims, err := m.service.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		
		// Add claims to context
		ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, UserEmailKey, claims.Email)
		ctx = context.WithValue(ctx, UserRolesKey, claims.Roles)
		ctx = context.WithValue(ctx, ClaimsKey, claims)
		
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns a middleware that checks if the user has a specific role
func (m *AuthMiddleware) RequireRole(roleName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user roles from context
			roles, ok := r.Context().Value(UserRolesKey).([]string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			
			// Check if user has the required role
			hasRole := false
			for _, role := range roles {
				if role == roleName {
					hasRole = true
					break
				}
			}
			
			if !hasRole {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole returns a middleware that checks if the user has any of the specified roles
func (m *AuthMiddleware) RequireAnyRole(roleNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user roles from context
			userRoles, ok := r.Context().Value(UserRolesKey).([]string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			
			// Check if user has any of the required roles
			hasRole := false
			for _, userRole := range userRoles {
				for _, requiredRole := range roleNames {
					if userRole == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}
			
			if !hasRole {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns a middleware that checks if the user has a specific permission
func (m *AuthMiddleware) RequirePermission(permissionName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context
			userID, ok := r.Context().Value(UserIDKey).(string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user has the required permission
			hasPermission, err := m.service.HasPermission(r.Context(), userID, permissionName)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllRoles returns a middleware that checks if the user has all of the specified roles
func (m *AuthMiddleware) RequireAllRoles(roleNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user roles from context
			userRoles, ok := r.Context().Value(UserRolesKey).([]string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Create a map for quick lookup
			userRoleMap := make(map[string]bool)
			for _, role := range userRoles {
				userRoleMap[role] = true
			}

			// Check if user has all required roles
			for _, requiredRole := range roleNames {
				if !userRoleMap[requiredRole] {
					http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission returns a middleware that checks if the user has any of the specified permissions
func (m *AuthMiddleware) RequireAnyPermission(permissionNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context
			userID, ok := r.Context().Value(UserIDKey).(string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user has any of the required permissions
			hasAnyPermission, err := m.service.HasAnyPermission(r.Context(), userID, permissionNames)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !hasAnyPermission {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllPermissions returns a middleware that checks if the user has all of the specified permissions
func (m *AuthMiddleware) RequireAllPermissions(permissionNames ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context
			userID, ok := r.Context().Value(UserIDKey).(string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user has all of the required permissions
			hasAllPermissions, err := m.service.HasAllPermissions(r.Context(), userID, permissionNames)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !hasAllPermissions {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwnerOrPermission returns a middleware that allows access if:
// 1. The authenticated user is the owner of the resource (userID matches the resource owner), OR
// 2. The authenticated user has the specified permission
//
// getUserIDFromRequest is a function that extracts the resource owner's user ID from the request
// (e.g., from URL parameters like /users/:id)
func (m *AuthMiddleware) RequireOwnerOrPermission(
	getUserIDFromRequest func(*http.Request) string,
	permissionName string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get authenticated user ID from context
			authenticatedUserID, ok := r.Context().Value(UserIDKey).(string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get resource owner ID from request
			resourceOwnerID := getUserIDFromRequest(r)

			// Check if user is the owner
			if authenticatedUserID == resourceOwnerID {
				next.ServeHTTP(w, r)
				return
			}

			// If not owner, check if user has the required permission
			hasPermission, err := m.service.HasPermission(r.Context(), authenticatedUserID, permissionName)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwnerOrRole returns a middleware that allows access if:
// 1. The authenticated user is the owner of the resource, OR
// 2. The authenticated user has any of the specified roles
func (m *AuthMiddleware) RequireOwnerOrRole(
	getUserIDFromRequest func(*http.Request) string,
	roleNames ...string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get authenticated user ID from context
			authenticatedUserID, ok := r.Context().Value(UserIDKey).(string)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get resource owner ID from request
			resourceOwnerID := getUserIDFromRequest(r)

			// Check if user is the owner
			if authenticatedUserID == resourceOwnerID {
				next.ServeHTTP(w, r)
				return
			}

			// If not owner, check if user has any of the required roles
			userRoles, ok := r.Context().Value(UserRolesKey).([]string)
			if !ok {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			hasRole := false
			for _, userRole := range userRoles {
				for _, requiredRole := range roleNames {
					if userRole == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserID extracts the user ID from the request context
func GetUserID(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDKey).(string)
	return userID, ok
}

// GetUserEmail extracts the user email from the request context
func GetUserEmail(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(UserEmailKey).(string)
	return email, ok
}

// GetUserRoles extracts the user roles from the request context
func GetUserRoles(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(UserRolesKey).([]string)
	return roles, ok
}

// GetClaims extracts the JWT claims from the request context
func GetClaims(ctx context.Context) (*tokens.Claims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(*tokens.Claims)
	return claims, ok
}

// Chain chains multiple middleware functions
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// ExtractBearerToken extracts the bearer token from the Authorization header
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", auth.ErrInvalidCredentials
	}
	
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", auth.ErrInvalidCredentials
	}
	
	return parts[1], nil
}
