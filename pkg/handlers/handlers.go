package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/devchuckcamp/goauthx/pkg/auth"
	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/middleware"
)

// Handlers provides pre-built HTTP handlers for authentication
type Handlers struct {
	service    *auth.Service
	middleware *middleware.AuthMiddleware
	routes     *config.RouteConfig
}

// NewHandlers creates a new Handlers instance
func NewHandlers(service *auth.Service, routeConfig *config.RouteConfig) *Handlers {
	if routeConfig == nil {
		routeConfig = config.DefaultRouteConfig()
	}

	return &Handlers{
		service:    service,
		middleware: middleware.NewAuthMiddleware(service),
		routes:     routeConfig,
	}
}

// RegisterRoutes registers all authentication routes on the provided mux
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	// Public routes
	mux.HandleFunc(h.routes.RegisterPath, h.Register)
	mux.HandleFunc(h.routes.LoginPath, h.Login)
	mux.HandleFunc(h.routes.RefreshPath, h.RefreshToken)
	mux.HandleFunc(h.routes.RequestPasswordResetPath, h.RequestPasswordReset)
	mux.HandleFunc(h.routes.ResetPasswordPath, h.ResetPassword)
	mux.HandleFunc(h.routes.VerifyEmailPath, h.VerifyEmail)

	// OAuth routes
	mux.HandleFunc(h.routes.GoogleOAuthPath, h.GoogleOAuthLogin)
	mux.HandleFunc(h.routes.GoogleOAuthCallbackPath, h.GoogleOAuthCallback)

	// Protected routes (require authentication)
	mux.Handle(h.routes.LogoutPath, h.middleware.Authenticate(http.HandlerFunc(h.Logout)))
	mux.Handle(h.routes.ProfilePath, h.middleware.Authenticate(http.HandlerFunc(h.Profile)))
	mux.Handle(h.routes.ChangePasswordPath, h.middleware.Authenticate(http.HandlerFunc(h.ChangePassword)))
	mux.Handle(h.routes.ResendVerificationPath, h.middleware.Authenticate(http.HandlerFunc(h.ResendVerification)))
	mux.Handle(h.routes.UnlinkGoogleOAuthPath, h.middleware.Authenticate(http.HandlerFunc(h.UnlinkGoogleOAuth)))
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// SuccessResponse represents a success response
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error JSON response
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{
		Error:   err.Error(),
		Message: http.StatusText(status),
	})
}

// Register handles user registration
func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	resp, err := h.service.Register(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// Login handles user authentication
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	resp, err := h.service.Login(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Logout handles user logout (requires authentication)
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, auth.ErrInvalidCredentials)
		return
	}

	if err := h.service.Logout(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Successfully logged out",
	})
}

// RefreshToken handles token refresh
func (h *Handlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	var req auth.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	resp, err := h.service.RefreshAccessToken(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Profile handles retrieving user profile (requires authentication)
func (h *Handlers) Profile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, auth.ErrInvalidCredentials)
		return
	}

	user, err := h.service.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}

	roles, _ := middleware.GetUserRoles(r.Context())

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":  user,
		"roles": roles,
	})
}

// ChangePassword handles changing user password (requires authentication)
func (h *Handlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, auth.ErrInvalidCredentials)
		return
	}

	var req auth.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.service.ChangePassword(r.Context(), userID, req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Password changed successfully",
	})
}

// RequestPasswordReset handles password reset requests
func (h *Handlers) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	var req auth.RequestPasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	token, err := h.service.RequestPasswordReset(r.Context(), req.Email)
	if err != nil {
		// Don't reveal if email exists for security
		writeJSON(w, http.StatusOK, SuccessResponse{
			Message: "If the email exists, a password reset link has been sent",
		})
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Password reset link has been sent",
		Data: map[string]string{
			"reset_token": token, // In production, this should be sent via email only
		},
	})
}

// ResetPassword handles password reset with token
func (h *Handlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	var req auth.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.service.ResetPassword(r.Context(), req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Password reset successfully",
	})
}

// VerifyEmail handles email verification
func (h *Handlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" && r.Method == http.MethodPost {
		var req auth.VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		token = req.Token
	}

	if token == "" {
		writeError(w, http.StatusBadRequest, http.ErrMissingContentLength)
		return
	}

	if err := h.service.VerifyEmail(r.Context(), token); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Email verified successfully",
	})
}

// ResendVerification handles resending verification email (requires authentication)
func (h *Handlers) ResendVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, auth.ErrInvalidCredentials)
		return
	}

	token, err := h.service.ResendVerificationEmail(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Verification email has been sent",
		Data: map[string]string{
			"verification_token": token, // In production, this should be sent via email only
		},
	})
}

// GoogleOAuthLogin initiates Google OAuth login flow
func (h *Handlers) GoogleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	// Generate state token for CSRF protection
	state := r.URL.Query().Get("state")
	if state == "" {
		// In production, generate a secure random state and store it in session
		state = "random-state-token"
	}

	url, err := h.service.GetGoogleOAuthURL(auth.GoogleOAuthURLRequest{
		State: state,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// Redirect to Google OAuth URL
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GoogleOAuthCallback handles the Google OAuth callback
func (h *Handlers) GoogleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	// Parse callback parameters
	req, err := auth.ParseGoogleOAuthCallbackFromForm(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// In production, verify state token matches the one stored in session

	// Handle OAuth callback
	resp, err := h.service.HandleGoogleOAuthCallback(r.Context(), *req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// UnlinkGoogleOAuth handles unlinking a Google OAuth account (requires authentication)
func (h *Handlers) UnlinkGoogleOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, auth.ErrInvalidCredentials)
		return
	}

	var req struct {
		AccountID string `json:"account_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.service.UnlinkGoogleOAuth(r.Context(), userID, req.AccountID); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	writeJSON(w, http.StatusOK, SuccessResponse{
		Message: "Google account unlinked successfully",
	})
}
