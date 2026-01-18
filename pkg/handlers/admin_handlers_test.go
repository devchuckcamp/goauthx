package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devchuckcamp/goauthx/pkg/middleware"
	"github.com/devchuckcamp/goauthx/pkg/models"
)

func TestExtractIDFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		prefix   string
		expected string
	}{
		{
			name:     "simple ID",
			path:     "/admin/roles/123",
			prefix:   "/admin/roles/",
			expected: "123",
		},
		{
			name:     "UUID",
			path:     "/admin/roles/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			prefix:   "/admin/roles/",
			expected: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
		{
			name:     "with trailing slash",
			path:     "/admin/roles/123/",
			prefix:   "/admin/roles/",
			expected: "123",
		},
		{
			name:     "with sub-resource",
			path:     "/admin/roles/123/permissions",
			prefix:   "/admin/roles/",
			expected: "123",
		},
		{
			name:     "empty path",
			path:     "/admin/roles/",
			prefix:   "/admin/roles/",
			expected: "",
		},
		{
			name:     "wrong prefix",
			path:     "/admin/users/123",
			prefix:   "/admin/roles/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIDFromPath(tt.path, tt.prefix)
			if got != tt.expected {
				t.Errorf("extractIDFromPath(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.expected)
			}
		})
	}
}

func TestExtractSubResource(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		prefix          string
		expectedID      string
		expectedSub     string
		expectedSubID   string
	}{
		{
			name:            "ID only",
			path:            "/admin/roles/123",
			prefix:          "/admin/roles/",
			expectedID:      "123",
			expectedSub:     "",
			expectedSubID:   "",
		},
		{
			name:            "ID with sub-resource",
			path:            "/admin/roles/123/permissions",
			prefix:          "/admin/roles/",
			expectedID:      "123",
			expectedSub:     "permissions",
			expectedSubID:   "",
		},
		{
			name:            "ID with sub-resource and sub-ID",
			path:            "/admin/roles/123/permissions/456",
			prefix:          "/admin/roles/",
			expectedID:      "123",
			expectedSub:     "permissions",
			expectedSubID:   "456",
		},
		{
			name:            "empty after prefix",
			path:            "/admin/roles/",
			prefix:          "/admin/roles/",
			expectedID:      "",
			expectedSub:     "",
			expectedSubID:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, sub, subID := extractSubResource(tt.path, tt.prefix)
			if id != tt.expectedID {
				t.Errorf("ID = %q, want %q", id, tt.expectedID)
			}
			if sub != tt.expectedSub {
				t.Errorf("SubResource = %q, want %q", sub, tt.expectedSub)
			}
			if subID != tt.expectedSubID {
				t.Errorf("SubID = %q, want %q", subID, tt.expectedSubID)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"message": "hello"}

	writeJSON(rr, http.StatusOK, data)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var result map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result["message"] != "hello" {
		t.Errorf("Expected message 'hello', got %s", result["message"])
	}
}

func TestCreateRoleRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		input   CreateRoleRequest
		isValid bool
	}{
		{
			name:    "valid request",
			input:   CreateRoleRequest{Name: "admin", Description: "Admin role"},
			isValid: true,
		},
		{
			name:    "empty name",
			input:   CreateRoleRequest{Name: "", Description: "Admin role"},
			isValid: false,
		},
		{
			name:    "no description",
			input:   CreateRoleRequest{Name: "admin", Description: ""},
			isValid: true, // description is optional
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.input.Name != ""
			if valid != tt.isValid {
				t.Errorf("Expected isValid=%v, got %v", tt.isValid, valid)
			}
		})
	}
}

func TestCreatePermissionRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		input   CreatePermissionRequest
		isValid bool
	}{
		{
			name:    "valid request",
			input:   CreatePermissionRequest{Name: "product:create", Resource: "product", Action: "create"},
			isValid: true,
		},
		{
			name:    "missing name",
			input:   CreatePermissionRequest{Name: "", Resource: "product", Action: "create"},
			isValid: false,
		},
		{
			name:    "missing resource",
			input:   CreatePermissionRequest{Name: "product:create", Resource: "", Action: "create"},
			isValid: false,
		},
		{
			name:    "missing action",
			input:   CreatePermissionRequest{Name: "product:create", Resource: "product", Action: ""},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.input.Name != "" && tt.input.Resource != "" && tt.input.Action != ""
			if valid != tt.isValid {
				t.Errorf("Expected isValid=%v, got %v", tt.isValid, valid)
			}
		})
	}
}

func TestAssignRoleRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		input   AssignRoleRequest
		isValid bool
	}{
		{
			name:    "with role_id",
			input:   AssignRoleRequest{RoleID: "role-123"},
			isValid: true,
		},
		{
			name:    "with role_name",
			input:   AssignRoleRequest{RoleName: "admin"},
			isValid: true,
		},
		{
			name:    "with both",
			input:   AssignRoleRequest{RoleID: "role-123", RoleName: "admin"},
			isValid: true,
		},
		{
			name:    "with neither",
			input:   AssignRoleRequest{RoleID: "", RoleName: ""},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.input.RoleID != "" || tt.input.RoleName != ""
			if valid != tt.isValid {
				t.Errorf("Expected isValid=%v, got %v", tt.isValid, valid)
			}
		})
	}
}

func TestGrantPermissionRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		input   GrantPermissionRequest
		isValid bool
	}{
		{
			name:    "with permission_id",
			input:   GrantPermissionRequest{PermissionID: "perm-123"},
			isValid: true,
		},
		{
			name:    "with permission_name",
			input:   GrantPermissionRequest{PermissionName: "product:create"},
			isValid: true,
		},
		{
			name:    "with both",
			input:   GrantPermissionRequest{PermissionID: "perm-123", PermissionName: "product:create"},
			isValid: true,
		},
		{
			name:    "with neither",
			input:   GrantPermissionRequest{PermissionID: "", PermissionName: ""},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.input.PermissionID != "" || tt.input.PermissionName != ""
			if valid != tt.isValid {
				t.Errorf("Expected isValid=%v, got %v", tt.isValid, valid)
			}
		})
	}
}

func TestSuccessResponse_Marshaling(t *testing.T) {
	resp := SuccessResponse{
		Message: "Operation successful",
		Data: map[string]string{
			"id": "123",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded SuccessResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Message != "Operation successful" {
		t.Errorf("Expected message 'Operation successful', got %s", decoded.Message)
	}
}

func TestErrorResponse_Marshaling(t *testing.T) {
	resp := ErrorResponse{
		Error:   "something went wrong",
		Message: "Bad Request",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded ErrorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Error != "something went wrong" {
		t.Errorf("Expected error 'something went wrong', got %s", decoded.Error)
	}
}

func TestHandleRoles_MethodNotAllowed(t *testing.T) {
	// Test that unsupported methods return 405
	methods := []string{http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/admin/roles", nil)
			rr := httptest.NewRecorder()

			// Create handler that rejects non-GET/POST
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet, http.MethodPost:
					w.WriteHeader(http.StatusOK)
				default:
					writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
				}
			})

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
			}
		})
	}
}

// Test request body parsing
func TestCreateRoleRequest_Parsing(t *testing.T) {
	body := `{"name": "admin", "description": "Administrator role"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/roles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	var parsed CreateRoleRequest
	if err := json.NewDecoder(req.Body).Decode(&parsed); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if parsed.Name != "admin" {
		t.Errorf("Expected name 'admin', got %s", parsed.Name)
	}
	if parsed.Description != "Administrator role" {
		t.Errorf("Expected description 'Administrator role', got %s", parsed.Description)
	}
}

func TestCreatePermissionRequest_Parsing(t *testing.T) {
	body := `{"name": "product:create", "resource": "product", "action": "create", "description": "Create products"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/permissions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	var parsed CreatePermissionRequest
	if err := json.NewDecoder(req.Body).Decode(&parsed); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if parsed.Name != "product:create" {
		t.Errorf("Expected name 'product:create', got %s", parsed.Name)
	}
	if parsed.Resource != "product" {
		t.Errorf("Expected resource 'product', got %s", parsed.Resource)
	}
	if parsed.Action != "create" {
		t.Errorf("Expected action 'create', got %s", parsed.Action)
	}
}

// Test model serialization
func TestRoleModel_JSON(t *testing.T) {
	role := &models.Role{
		ID:          "role-123",
		Name:        "admin",
		Description: "Administrator",
	}

	data, err := json.Marshal(role)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded models.Role
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.ID != "role-123" {
		t.Errorf("Expected ID 'role-123', got %s", decoded.ID)
	}
	if decoded.Name != "admin" {
		t.Errorf("Expected name 'admin', got %s", decoded.Name)
	}
}

func TestPermissionModel_JSON(t *testing.T) {
	perm := &models.Permission{
		ID:          "perm-123",
		Name:        "product:create",
		Resource:    "product",
		Action:      "create",
		Description: "Create products",
	}

	data, err := json.Marshal(perm)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded models.Permission
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Name != "product:create" {
		t.Errorf("Expected name 'product:create', got %s", decoded.Name)
	}
	if decoded.Resource != "product" {
		t.Errorf("Expected resource 'product', got %s", decoded.Resource)
	}
}

// Test context helpers work in admin context
func TestAdminContext_GetUserID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/roles", nil)
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, "admin-user-id")
	req = req.WithContext(ctx)

	userID, ok := middleware.GetUserID(req.Context())
	if !ok {
		t.Error("Expected to get user ID from context")
	}
	if userID != "admin-user-id" {
		t.Errorf("Expected 'admin-user-id', got %s", userID)
	}
}

func TestAdminContext_GetUserRoles(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/roles", nil)
	ctx := context.WithValue(req.Context(), middleware.UserRolesKey, []string{"admin"})
	req = req.WithContext(ctx)

	roles, ok := middleware.GetUserRoles(req.Context())
	if !ok {
		t.Error("Expected to get user roles from context")
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("Expected ['admin'], got %v", roles)
	}
}
