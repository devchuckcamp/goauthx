package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devchuckcamp/goauthx/pkg/tokens"
)

func TestRequireAllRoles(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		userRoles      []string
		requiredRoles  []string
		expectedStatus int
	}{
		{
			name:           "has all roles",
			userRoles:      []string{"admin", "manager"},
			requiredRoles:  []string{"admin", "manager"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "has more roles than required",
			userRoles:      []string{"admin", "manager", "customer"},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing one role",
			userRoles:      []string{"admin"},
			requiredRoles:  []string{"admin", "manager"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "no roles",
			userRoles:      []string{},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := &AuthMiddleware{}
			wrapped := middleware.RequireAllRoles(tt.requiredRoles...)(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			ctx := context.WithValue(req.Context(), UserRolesKey, tt.userRoles)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestRequireAllRoles_NoRolesInContext(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := &AuthMiddleware{}
	wrapped := middleware.RequireAllRoles("admin")(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	// No roles in context
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestRequireOwnerOrRole(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	getUserIDFromRequest := func(r *http.Request) string {
		return r.URL.Query().Get("user_id")
	}

	tests := []struct {
		name           string
		authUserID     string
		resourceUserID string
		userRoles      []string
		requiredRoles  []string
		expectedStatus int
	}{
		{
			name:           "user is owner",
			authUserID:     "user-123",
			resourceUserID: "user-123",
			userRoles:      []string{"customer"},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "not owner but has required role",
			authUserID:     "user-456",
			resourceUserID: "user-123",
			userRoles:      []string{"admin"},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "not owner and no required role",
			authUserID:     "user-456",
			resourceUserID: "user-123",
			userRoles:      []string{"customer"},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := &AuthMiddleware{}
			wrapped := middleware.RequireOwnerOrRole(getUserIDFromRequest, tt.requiredRoles...)(handler)

			req := httptest.NewRequest("GET", "/test?user_id="+tt.resourceUserID, nil)
			ctx := context.WithValue(req.Context(), UserIDKey, tt.authUserID)
			ctx = context.WithValue(ctx, UserRolesKey, tt.userRoles)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestChain(t *testing.T) {
	callOrder := []string{}

	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callOrder = append(callOrder, "m1-before")
			next.ServeHTTP(w, r)
			callOrder = append(callOrder, "m1-after")
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callOrder = append(callOrder, "m2-before")
			next.ServeHTTP(w, r)
			callOrder = append(callOrder, "m2-after")
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callOrder = append(callOrder, "handler")
		w.WriteHeader(http.StatusOK)
	})

	chained := Chain(middleware1, middleware2)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	chained.ServeHTTP(rr, req)

	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(callOrder) != len(expected) {
		t.Fatalf("Expected %d calls, got %d", len(expected), len(callOrder))
	}

	for i, call := range expected {
		if callOrder[i] != call {
			t.Errorf("At index %d, expected %s, got %s", i, call, callOrder[i])
		}
	}
}

func TestGetUserID(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserIDKey, "user-123")
	userID, ok := GetUserID(ctx)

	if !ok {
		t.Error("Expected ok to be true")
	}
	if userID != "user-123" {
		t.Errorf("Expected user-123, got %s", userID)
	}
}

func TestGetUserID_NotSet(t *testing.T) {
	ctx := context.Background()
	_, ok := GetUserID(ctx)

	if ok {
		t.Error("Expected ok to be false when user ID not set")
	}
}

func TestGetUserEmail(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserEmailKey, "test@example.com")
	email, ok := GetUserEmail(ctx)

	if !ok {
		t.Error("Expected ok to be true")
	}
	if email != "test@example.com" {
		t.Errorf("Expected test@example.com, got %s", email)
	}
}

func TestGetUserRoles(t *testing.T) {
	roles := []string{"admin", "manager"}
	ctx := context.WithValue(context.Background(), UserRolesKey, roles)
	gotRoles, ok := GetUserRoles(ctx)

	if !ok {
		t.Error("Expected ok to be true")
	}
	if len(gotRoles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(gotRoles))
	}
}

func TestGetClaims(t *testing.T) {
	claims := &tokens.Claims{
		UserID: "user-123",
		Email:  "test@example.com",
		Roles:  []string{"admin"},
	}
	ctx := context.WithValue(context.Background(), ClaimsKey, claims)
	gotClaims, ok := GetClaims(ctx)

	if !ok {
		t.Error("Expected ok to be true")
	}
	if gotClaims.UserID != "user-123" {
		t.Errorf("Expected user-123, got %s", gotClaims.UserID)
	}
}

func TestRequireRole(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		userRoles      []string
		requiredRole   string
		expectedStatus int
	}{
		{
			name:           "has required role",
			userRoles:      []string{"admin"},
			requiredRole:   "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "has role among others",
			userRoles:      []string{"customer", "admin"},
			requiredRole:   "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing required role",
			userRoles:      []string{"customer"},
			requiredRole:   "admin",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := &AuthMiddleware{}
			wrapped := middleware.RequireRole(tt.requiredRole)(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			ctx := context.WithValue(req.Context(), UserRolesKey, tt.userRoles)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestRequireAnyRole(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name           string
		userRoles      []string
		requiredRoles  []string
		expectedStatus int
	}{
		{
			name:           "has first required role",
			userRoles:      []string{"admin"},
			requiredRoles:  []string{"admin", "manager"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "has second required role",
			userRoles:      []string{"manager"},
			requiredRoles:  []string{"admin", "manager"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "has no required roles",
			userRoles:      []string{"customer"},
			requiredRoles:  []string{"admin", "manager"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := &AuthMiddleware{}
			wrapped := middleware.RequireAnyRole(tt.requiredRoles...)(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			ctx := context.WithValue(req.Context(), UserRolesKey, tt.userRoles)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expected    string
		expectError bool
	}{
		{
			name:        "valid bearer token",
			authHeader:  "Bearer mytoken123",
			expected:    "mytoken123",
			expectError: false,
		},
		{
			name:        "missing header",
			authHeader:  "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "wrong format",
			authHeader:  "Token mytoken123",
			expected:    "",
			expectError: true,
		},
		{
			name:        "only bearer",
			authHeader:  "Bearer",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			token, err := ExtractBearerToken(req)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if token != tt.expected {
				t.Errorf("Expected token %s, got %s", tt.expected, token)
			}
		})
	}
}
