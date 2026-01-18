package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/devchuckcamp/goauthx/pkg/auth"
	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/middleware"
	"github.com/devchuckcamp/goauthx/pkg/models"
	"github.com/devchuckcamp/goauthx/pkg/store"
)

// AdminHandlers provides pre-built HTTP handlers for admin operations
type AdminHandlers struct {
	service    *auth.Service
	store      store.Store
	middleware *middleware.AuthMiddleware
	routes     *config.AdminRouteConfig
	adminRole  string
}

// AdminHandlersConfig holds configuration for admin handlers
type AdminHandlersConfig struct {
	// AdminRole is the role name required to access admin endpoints (default: "admin")
	AdminRole string
	// RouteConfig is the admin route configuration
	RouteConfig *config.AdminRouteConfig
}

// NewAdminHandlers creates a new AdminHandlers instance
func NewAdminHandlers(service *auth.Service, store store.Store, cfg *AdminHandlersConfig) *AdminHandlers {
	if cfg == nil {
		cfg = &AdminHandlersConfig{}
	}

	if cfg.RouteConfig == nil {
		cfg.RouteConfig = config.DefaultAdminRouteConfig()
	}

	if cfg.AdminRole == "" {
		cfg.AdminRole = "admin"
	}

	return &AdminHandlers{
		service:    service,
		store:      store,
		middleware: middleware.NewAuthMiddleware(service),
		routes:     cfg.RouteConfig,
		adminRole:  cfg.AdminRole,
	}
}

// RegisterRoutes registers all admin routes on the provided mux
func (h *AdminHandlers) RegisterRoutes(mux *http.ServeMux) {
	// Apply authentication and admin role check to all admin routes
	adminMiddleware := middleware.Chain(
		h.middleware.Authenticate,
		h.middleware.RequireRole(h.adminRole),
	)

	// Role management routes
	mux.Handle(h.routes.ListRolesPath, adminMiddleware(http.HandlerFunc(h.handleRoles)))
	mux.Handle(h.routes.GetRolePath, adminMiddleware(http.HandlerFunc(h.handleRoleByID)))

	// Permission management routes
	mux.Handle(h.routes.ListPermissionsPath, adminMiddleware(http.HandlerFunc(h.handlePermissions)))
	mux.Handle(h.routes.GetPermissionPath, adminMiddleware(http.HandlerFunc(h.handlePermissionByID)))

	// User role management routes
	mux.Handle(h.routes.GetUserRolesPath, adminMiddleware(http.HandlerFunc(h.handleUserRoles)))

	// Role permission management routes
	mux.Handle(h.routes.GetRolePermissionsPath, adminMiddleware(http.HandlerFunc(h.handleRolePermissions)))
}

// extractIDFromPath extracts an ID from a URL path like "/admin/roles/{id}"
func extractIDFromPath(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(path, prefix)
	// Remove trailing slash if present
	rest = strings.TrimSuffix(rest, "/")
	// If there's a / in the rest, take only the first part
	if idx := strings.Index(rest, "/"); idx != -1 {
		return rest[:idx]
	}
	return rest
}

// extractSubResource extracts sub-resource from path like "/admin/roles/{id}/permissions"
func extractSubResource(path, prefix string) (id string, subResource string, subID string) {
	if !strings.HasPrefix(path, prefix) {
		return "", "", ""
	}
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimSuffix(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) >= 1 {
		id = parts[0]
	}
	if len(parts) >= 2 {
		subResource = parts[1]
	}
	if len(parts) >= 3 {
		subID = parts[2]
	}
	return
}

// handleRoles handles GET /admin/roles and POST /admin/roles
func (h *AdminHandlers) handleRoles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listRoles(w, r)
	case http.MethodPost:
		h.createRole(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
	}
}

// handleRoleByID handles GET/PUT/DELETE /admin/roles/{id}
func (h *AdminHandlers) handleRoleByID(w http.ResponseWriter, r *http.Request) {
	id, subResource, subID := extractSubResource(r.URL.Path, h.routes.GetRolePath)
	if id == "" {
		writeError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
		return
	}

	// Handle sub-resources like /admin/roles/{id}/permissions
	if subResource == "permissions" {
		h.handleRolePermissionsSub(w, r, id, subID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getRole(w, r, id)
	case http.MethodPut:
		h.updateRole(w, r, id)
	case http.MethodDelete:
		h.deleteRole(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
	}
}

// listRoles returns all roles
func (h *AdminHandlers) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.store.ListRoles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"roles": roles,
		"count": len(roles),
	})
}

// CreateRoleRequest represents a request to create a role
type CreateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// createRole creates a new role
func (h *AdminHandlers) createRole(w http.ResponseWriter, r *http.Request) {
	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error:   "name is required",
			Message: "Bad Request",
		})
		return
	}

	role := &models.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := h.store.CreateRole(r.Context(), role); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, role)
}

// getRole returns a role by ID
func (h *AdminHandlers) getRole(w http.ResponseWriter, r *http.Request, id string) {
	role, err := h.store.GetRoleByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	writeJSON(w, http.StatusOK, role)
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// updateRole updates a role
func (h *AdminHandlers) updateRole(w http.ResponseWriter, r *http.Request, id string) {
	role, err := h.store.GetRoleByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Name != "" {
		role.Name = req.Name
	}
	if req.Description != "" {
		role.Description = req.Description
	}

	if err := h.store.UpdateRole(r.Context(), role); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, role)
}

// deleteRole deletes a role
func (h *AdminHandlers) deleteRole(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.store.DeleteRole(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Role deleted successfully",
	})
}

// handlePermissions handles GET /admin/permissions and POST /admin/permissions
func (h *AdminHandlers) handlePermissions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listPermissions(w, r)
	case http.MethodPost:
		h.createPermission(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
	}
}

// handlePermissionByID handles GET/PUT/DELETE /admin/permissions/{id}
func (h *AdminHandlers) handlePermissionByID(w http.ResponseWriter, r *http.Request) {
	id := extractIDFromPath(r.URL.Path, h.routes.GetPermissionPath)
	if id == "" {
		writeError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getPermission(w, r, id)
	case http.MethodPut:
		h.updatePermission(w, r, id)
	case http.MethodDelete:
		h.deletePermission(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
	}
}

// listPermissions returns all permissions
func (h *AdminHandlers) listPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.store.ListPermissions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"permissions": permissions,
		"count":       len(permissions),
	})
}

// CreatePermissionRequest represents a request to create a permission
type CreatePermissionRequest struct {
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// createPermission creates a new permission
func (h *AdminHandlers) createPermission(w http.ResponseWriter, r *http.Request) {
	var req CreatePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Name == "" || req.Resource == "" || req.Action == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error:   "name, resource, and action are required",
			Message: "Bad Request",
		})
		return
	}

	permission := &models.Permission{
		Name:        req.Name,
		Resource:    req.Resource,
		Action:      req.Action,
		Description: req.Description,
	}

	if err := h.store.CreatePermission(r.Context(), permission); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, permission)
}

// getPermission returns a permission by ID
func (h *AdminHandlers) getPermission(w http.ResponseWriter, r *http.Request, id string) {
	permission, err := h.store.GetPermissionByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	writeJSON(w, http.StatusOK, permission)
}

// UpdatePermissionRequest represents a request to update a permission
type UpdatePermissionRequest struct {
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// updatePermission updates a permission
func (h *AdminHandlers) updatePermission(w http.ResponseWriter, r *http.Request, id string) {
	permission, err := h.store.GetPermissionByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	var req UpdatePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Name != "" {
		permission.Name = req.Name
	}
	if req.Resource != "" {
		permission.Resource = req.Resource
	}
	if req.Action != "" {
		permission.Action = req.Action
	}
	if req.Description != "" {
		permission.Description = req.Description
	}

	if err := h.store.UpdatePermission(r.Context(), permission); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, permission)
}

// deletePermission deletes a permission
func (h *AdminHandlers) deletePermission(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.store.DeletePermission(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Permission deleted successfully",
	})
}

// handleUserRoles handles user role management endpoints
func (h *AdminHandlers) handleUserRoles(w http.ResponseWriter, r *http.Request) {
	userID, subResource, roleID := extractSubResource(r.URL.Path, h.routes.GetUserRolesPath)
	if userID == "" {
		writeError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
		return
	}

	if subResource != "roles" {
		writeError(w, http.StatusNotFound, http.ErrNotSupported)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getUserRoles(w, r, userID)
	case http.MethodPost:
		h.assignUserRole(w, r, userID)
	case http.MethodDelete:
		if roleID == "" {
			writeError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
			return
		}
		h.removeUserRole(w, r, userID, roleID)
	default:
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
	}
}

// getUserRoles returns all roles for a user
func (h *AdminHandlers) getUserRoles(w http.ResponseWriter, r *http.Request, userID string) {
	roles, err := h.store.GetUserRoles(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id": userID,
		"roles":   roles,
		"count":   len(roles),
	})
}

// AssignRoleRequest represents a request to assign a role to a user
type AssignRoleRequest struct {
	RoleID   string `json:"role_id"`
	RoleName string `json:"role_name"`
}

// assignUserRole assigns a role to a user
func (h *AdminHandlers) assignUserRole(w http.ResponseWriter, r *http.Request, userID string) {
	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var err error
	if req.RoleID != "" {
		err = h.service.AssignRoleByID(r.Context(), userID, req.RoleID)
	} else if req.RoleName != "" {
		err = h.service.AssignRole(r.Context(), userID, req.RoleName)
	} else {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error:   "role_id or role_name is required",
			Message: "Bad Request",
		})
		return
	}

	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Role assigned successfully",
	})
}

// removeUserRole removes a role from a user
func (h *AdminHandlers) removeUserRole(w http.ResponseWriter, r *http.Request, userID, roleID string) {
	if err := h.service.RemoveRoleByID(r.Context(), userID, roleID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Role removed successfully",
	})
}

// handleRolePermissions handles role permission management endpoints
func (h *AdminHandlers) handleRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleID, subResource, permID := extractSubResource(r.URL.Path, h.routes.GetRolePermissionsPath)
	if roleID == "" {
		writeError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
		return
	}

	if subResource != "permissions" {
		// Just return the role
		h.handleRoleByID(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getRolePermissions(w, r, roleID)
	case http.MethodPost:
		h.grantRolePermission(w, r, roleID)
	case http.MethodDelete:
		if permID == "" {
			writeError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
			return
		}
		h.revokeRolePermission(w, r, roleID, permID)
	default:
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
	}
}

// handleRolePermissionsSub handles /admin/roles/{id}/permissions endpoints
func (h *AdminHandlers) handleRolePermissionsSub(w http.ResponseWriter, r *http.Request, roleID, permID string) {
	switch r.Method {
	case http.MethodGet:
		h.getRolePermissions(w, r, roleID)
	case http.MethodPost:
		h.grantRolePermission(w, r, roleID)
	case http.MethodDelete:
		if permID == "" {
			writeError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
			return
		}
		h.revokeRolePermission(w, r, roleID, permID)
	default:
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
	}
}

// getRolePermissions returns all permissions for a role
func (h *AdminHandlers) getRolePermissions(w http.ResponseWriter, r *http.Request, roleID string) {
	permissions, err := h.store.GetRolePermissions(r.Context(), roleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"role_id":     roleID,
		"permissions": permissions,
		"count":       len(permissions),
	})
}

// GrantPermissionRequest represents a request to grant a permission to a role
type GrantPermissionRequest struct {
	PermissionID   string `json:"permission_id"`
	PermissionName string `json:"permission_name"`
}

// grantRolePermission grants a permission to a role
func (h *AdminHandlers) grantRolePermission(w http.ResponseWriter, r *http.Request, roleID string) {
	var req GrantPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	var permissionID string
	if req.PermissionID != "" {
		permissionID = req.PermissionID
	} else if req.PermissionName != "" {
		perm, err := h.store.GetPermissionByName(r.Context(), req.PermissionName)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		permissionID = perm.ID
	} else {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error:   "permission_id or permission_name is required",
			Message: "Bad Request",
		})
		return
	}

	if err := h.store.GrantPermission(r.Context(), roleID, permissionID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Permission granted successfully",
	})
}

// revokeRolePermission revokes a permission from a role
func (h *AdminHandlers) revokeRolePermission(w http.ResponseWriter, r *http.Request, roleID, permID string) {
	if err := h.store.RevokePermission(r.Context(), roleID, permID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Permission revoked successfully",
	})
}
