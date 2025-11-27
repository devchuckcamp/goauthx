# Google OAuth Integration Guide

This guide explains how to integrate Google OAuth authentication with goauthx.

## Table of Contents

1. [Setup Google OAuth Credentials](#setup-google-oauth-credentials)
2. [Configuration](#configuration)
3. [Implementation](#implementation)
4. [Usage Examples](#usage-examples)
5. [Security Considerations](#security-considerations)
6. [Testing](#testing)

## Setup Google OAuth Credentials

### 1. Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Google+ API** for your project

### 2. Configure OAuth Consent Screen

1. Navigate to **APIs & Services > OAuth consent screen**
2. Choose **External** user type (or Internal for Google Workspace)
3. Fill in the required application information:
   - App name
   - User support email
   - Developer contact information
4. Add scopes:
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
5. Add test users (for development)

### 3. Create OAuth 2.0 Credentials

1. Navigate to **APIs & Services > Credentials**
2. Click **Create Credentials > OAuth client ID**
3. Choose **Web application**
4. Add authorized redirect URIs:
   - Development: `http://localhost:8080/auth/google/callback`
   - Production: `https://yourdomain.com/auth/google/callback`
5. Save your **Client ID** and **Client Secret**

## Configuration

### Enable Google OAuth in goauthx

```go
package main

import (
	"github.com/devchuckcamp/goauthx"
)

func main() {
	cfg := goauthx.DefaultConfig()
	
	// Configure database
	cfg.Database.Driver = goauthx.Postgres
	cfg.Database.DSN = "postgres://user:password@localhost:5432/authdb"
	
	// Configure JWT
	cfg.JWT.Secret = "your-super-secret-jwt-key-min-32-chars"
	
	// Configure Google OAuth
	cfg.OAuth.Google.Enabled = true
	cfg.OAuth.Google.ClientID = "your-google-client-id"
	cfg.OAuth.Google.ClientSecret = "your-google-client-secret"
	cfg.OAuth.Google.RedirectURL = "http://localhost:8080/auth/google/callback"
	
	// Create store and run migrations
	store, _ := goauthx.NewStore(cfg.Database)
	defer store.Close()
	
	migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
	migrator.Up(context.Background())
	
	// Create auth service
	authService, _ := goauthx.NewService(cfg, store)
	
	// Setup HTTP handlers with OAuth support
	mux := http.NewServeMux()
	handlers := goauthx.NewHandlers(authService, nil)
	handlers.RegisterRoutes(mux)
	
	// Server now includes OAuth endpoints:
	// GET  /auth/google - Initiates Google OAuth login
	// GET  /auth/google/callback - Handles OAuth callback
	// POST /auth/google/unlink - Unlinks Google account (authenticated)
	
	http.ListenAndServe(":8080", mux)
}
```

### Environment Variables (Recommended)

Store sensitive credentials in environment variables:

```bash
export GOOGLE_OAUTH_CLIENT_ID="your-client-id"
export GOOGLE_OAUTH_CLIENT_SECRET="your-client-secret"
export GOOGLE_OAUTH_REDIRECT_URL="http://localhost:8080/auth/google/callback"
```

```go
cfg.OAuth.Google.ClientID = os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
cfg.OAuth.Google.ClientSecret = os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")
cfg.OAuth.Google.RedirectURL = os.Getenv("GOOGLE_OAUTH_REDIRECT_URL")
```

## Implementation

### Using Pre-built Handlers (Recommended)

The easiest way is to use the pre-built handlers:

```go
handlers := goauthx.NewHandlers(authService, nil)
handlers.RegisterRoutes(mux)

// OAuth endpoints are automatically registered:
// GET /auth/google
// GET /auth/google/callback
// POST /auth/google/unlink
```

### Custom Implementation

If you need custom behavior, you can use the service methods directly:

```go
// Initiate Google OAuth flow
func googleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state token for CSRF protection
	state := generateRandomString(32) // You implement this
	
	// Store state in session
	session.Set("oauth_state", state)
	
	// Get OAuth URL
	url, err := authService.GetGoogleOAuthURL(goauthx.GoogleOAuthURLRequest{
		State: state,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Redirect to Google
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Handle OAuth callback
func googleCallback(w http.ResponseWriter, r *http.Request) {
	// Parse callback parameters
	req, err := goauthx.ParseGoogleOAuthCallbackFromForm(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	// Verify state token
	storedState := session.Get("oauth_state")
	if req.State != storedState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	
	// Handle OAuth callback
	resp, err := authService.HandleGoogleOAuthCallback(r.Context(), *req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Set auth cookies or return tokens
	setAuthCookies(w, resp.AccessToken, resp.RefreshToken)
	
	// Redirect to dashboard
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

## Usage Examples

### Frontend Integration

#### HTML Button

```html
<a href="/auth/google" class="btn btn-google">
	<img src="google-icon.svg" alt="Google" />
	Sign in with Google
</a>
```

#### JavaScript (SPA)

```javascript
// Initiate Google OAuth
function loginWithGoogle() {
	// Add state parameter for CSRF protection
	const state = generateRandomString();
	sessionStorage.setItem('oauth_state', state);
	
	window.location.href = `/auth/google?state=${state}`;
}

// Handle callback (if using client-side routing)
async function handleGoogleCallback() {
	const urlParams = new URLSearchParams(window.location.search);
	const code = urlParams.get('code');
	const state = urlParams.get('state');
	
	// Verify state
	const storedState = sessionStorage.getItem('oauth_state');
	if (state !== storedState) {
		throw new Error('Invalid state parameter');
	}
	
	// Exchange code for tokens (server handles this)
	const response = await fetch('/auth/google/callback', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ code, state })
	});
	
	const data = await response.json();
	
	// Store tokens
	localStorage.setItem('access_token', data.access_token);
	localStorage.setItem('refresh_token', data.refresh_token);
	
	// Redirect to dashboard
	window.location.href = '/dashboard';
}
```

### Account Linking

Users with existing accounts can link their Google account:

```bash
# User is already logged in with email/password
# They click "Link Google Account"
# After OAuth flow completes, Google account is linked to existing user

curl -X GET "http://localhost:8080/auth/google" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

The system automatically:
- Detects existing user by email
- Links OAuth account to existing user
- Marks email as verified if Google has verified it

### Unlinking Google Account

```bash
# Get OAuth account ID first
curl -X GET "http://localhost:8080/auth/profile" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"

# Unlink Google account
curl -X POST "http://localhost:8080/auth/google/unlink" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "oauth-account-id"
  }'
```

**Note**: You cannot unlink your only authentication method. Users must either:
- Have a password set, OR
- Have another OAuth account linked

## Security Considerations

### State Parameter (CSRF Protection)

Always use the state parameter to prevent CSRF attacks:

```go
// Generate a cryptographically secure random string
state := generateSecureRandomString(32)

// Store in session (server-side)
session.Set("oauth_state", state)

// Verify on callback
if callbackState != session.Get("oauth_state") {
	return errors.New("invalid state parameter")
}

// Clear state after use
session.Delete("oauth_state")
```

### HTTPS in Production

**Never use HTTP in production!** OAuth requires HTTPS:

```go
// Production configuration
cfg.OAuth.Google.RedirectURL = "https://yourdomain.com/auth/google/callback"
```

### Token Storage

- **Server-side**: Store OAuth tokens securely in database
- **Client-side**: Use HttpOnly cookies for JWT tokens
- Never expose OAuth tokens to client-side JavaScript

### Scopes

Request only the scopes you need:

```go
// Default scopes (email and profile)
// These are automatically set by goauthx

// If you need additional scopes, use custom implementation:
config := &oauth2.Config{
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
		// Add more if needed
	},
}
```

## Testing

### Unit Tests

```go
func TestGoogleOAuthIntegration(t *testing.T) {
	cfg := goauthx.DefaultConfig()
	cfg.Database.Driver = goauthx.Postgres
	cfg.Database.DSN = "postgres://test:test@localhost/testdb"
	cfg.JWT.Secret = "test-secret-min-32-chars-long"
	cfg.OAuth.Google.Enabled = true
	cfg.OAuth.Google.ClientID = "test-client-id"
	cfg.OAuth.Google.ClientSecret = "test-client-secret"
	cfg.OAuth.Google.RedirectURL = "http://localhost:8080/callback"
	
	store := NewMockStore()
	service, err := goauthx.NewService(cfg, store)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	
	// Test OAuth URL generation
	url, err := service.GetGoogleOAuthURL(goauthx.GoogleOAuthURLRequest{
		State: "test-state",
	})
	if err != nil {
		t.Fatalf("Failed to get OAuth URL: %v", err)
	}
	
	if url == "" {
		t.Error("Expected OAuth URL, got empty string")
	}
}
```

### Integration Testing

For integration tests with real Google OAuth:

1. Create a test Google account
2. Use Google's OAuth playground for manual testing
3. Test the complete flow:
   - New user registration via OAuth
   - Existing user login via OAuth
   - Account linking
   - Account unlinking

### Manual Testing

```bash
# 1. Start your server
go run main.go

# 2. Open browser to
http://localhost:8080/auth/google

# 3. Complete Google authentication

# 4. Verify user was created/logged in
curl -X GET "http://localhost:8080/auth/profile" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

## Troubleshooting

### "redirect_uri_mismatch" Error

- Ensure redirect URI in code exactly matches Google Console
- Include the protocol (http/https)
- Check for trailing slashes
- Verify the port number

### "access_denied" Error

- User cancelled the OAuth flow
- User doesn't have permission (for Workspace apps)
- App is not approved (if consent screen is in review)

### "invalid_client" Error

- Client ID or Client Secret is incorrect
- OAuth credentials were deleted/revoked
- Check environment variables

### Token Refresh Issues

goauthx automatically stores and updates OAuth tokens. If you encounter refresh issues:

```go
// Manually check OAuth account
accounts, err := service.GetGoogleOAuthAccounts(ctx, userID)
for _, account := range accounts {
	log.Printf("Account: %s, Expires: %v", account.ProviderID, account.ExpiresAt)
}
```

## Additional Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/rfc6749#section-10)
- [OpenID Connect](https://openid.net/connect/)

## Support

For issues and questions:
- GitHub Issues: [github.com/devchuckcamp/goauthx/issues](https://github.com/devchuckcamp/goauthx/issues)
- Documentation: [github.com/devchuckcamp/goauthx/docs](https://github.com/devchuckcamp/goauthx/tree/main/docs)
