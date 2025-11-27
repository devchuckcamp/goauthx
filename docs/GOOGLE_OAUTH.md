# Google OAuth Integration Guide

This guide explains how to integrate Google OAuth authentication into your application using goauthx.

## Table of Contents

- [Overview](#overview)
- [Setup Instructions](#setup-instructions)
- [Configuration](#configuration)
- [Usage](#usage)
- [User Flows](#user-flows)
- [API Endpoints](#api-endpoints)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

goauthx provides built-in Google OAuth 2.0 integration, allowing users to:
- Sign up using their Google account
- Sign in with their Google account
- Link Google account to existing account
- Unlink Google account (with safety checks)

### Key Features

- **Automatic Account Creation**: New users are automatically registered when signing in with Google
- **Account Linking**: Existing users can link their Google account
- **Email Verification**: Emails verified by Google are automatically marked as verified
- **Password Optional**: Users can sign up with only Google (no password required)
- **Safe Unlinking**: Prevents users from unlinking their last authentication method
- **Token Management**: Automatically handles OAuth token storage and refresh

## Setup Instructions

### 1. Get Google OAuth Credentials

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API:
   - Go to "APIs & Services" → "Library"
   - Search for "Google+ API"
   - Click "Enable"
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth 2.0 Client ID"
   - Select "Web application"
   - Add authorized redirect URIs:
     - For development: `http://localhost:8080/auth/google/callback`
     - For production: `https://yourdomain.com/auth/google/callback`
5. Copy the Client ID and Client Secret

### 2. Configure goauthx

Add Google OAuth configuration to your goauthx setup:

```go
cfg := goauthx.DefaultConfig()

// Configure database and JWT as usual...

// Add Google OAuth configuration
cfg.OAuth = goauthx.OAuthConfig{
    Google: goauthx.GoogleOAuthConfig{
        ClientID:     "your-google-client-id.apps.googleusercontent.com",
        ClientSecret: "your-google-client-secret",
        RedirectURL:  "http://localhost:8080/auth/google/callback",
        Enabled:      true,
    },
}
```

### 3. Register Handlers

If using pre-built handlers (recommended):

```go
handlers := goauthx.NewHandlers(authService, nil)
handlers.RegisterRoutes(mux)

// OAuth endpoints are automatically available:
// GET  /auth/google - Initiates OAuth flow
// GET  /auth/google/callback - Handles OAuth callback
// POST /auth/google/unlink - Unlinks Google account
```

## Configuration

### Complete Configuration Example

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"
    
    "github.com/devchuckcamp/goauthx"
)

func main() {
    cfg := goauthx.DefaultConfig()
    
    // Database configuration
    cfg.Database = goauthx.DatabaseConfig{
        Driver:          goauthx.Postgres,
        DSN:             "postgres://user:pass@localhost:5432/authdb?sslmode=disable",
        MaxOpenConns:    25,
        MaxIdleConns:    5,
        ConnMaxLifetime: 5 * time.Minute,
    }
    
    // JWT configuration
    cfg.JWT = goauthx.JWTConfig{
        Secret:            "your-super-secret-jwt-key-min-32-chars-long",
        AccessTokenExpiry: 15 * time.Minute,
        Issuer:            "my-app",
        Audience:          "my-app-users",
    }
    
    // Google OAuth configuration
    cfg.OAuth = goauthx.OAuthConfig{
        Google: goauthx.GoogleOAuthConfig{
            ClientId:     "<GOOGLE_ACCOUNT_CLIENT_ID>",
            ClientSecret: "<GOOGLE_ACCOUNT_Secret>",
            RedirectURL:  "http://localhost:8080/auth/google/callback",
            Enabled:      true,
        },
    }
    
    // Create store and service
    store, err := goauthx.NewStore(cfg.Database)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()
    
    // Run migrations
    migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
    if err := migrator.Up(context.Background()); err != nil {
        log.Fatal(err)
    }
    
    authService, err := goauthx.NewService(cfg, store)
    if err != nil {
        log.Fatal(err)
    }
    
    // Register handlers
    mux := http.NewServeMux()
    handlers := goauthx.NewHandlers(authService, nil)
    handlers.RegisterRoutes(mux)
    
    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", mux)
}
```

### Custom Route Configuration

```go
routeConfig := goauthx.DefaultRouteConfig()
routeConfig.GoogleOAuthPath = "/api/auth/google"
routeConfig.GoogleOAuthCallbackPath = "/api/auth/google/callback"
routeConfig.UnlinkGoogleOAuthPath = "/api/auth/google/unlink"

handlers := goauthx.NewHandlers(authService, routeConfig)
handlers.RegisterRoutes(mux)
```

## Usage

### Programmatic Usage

#### Initiate OAuth Flow

```go
// Generate OAuth URL
url, err := authService.GetGoogleOAuthURL(auth.GoogleOAuthURLRequest{
    State: "random-csrf-token", // Generate secure random token
})
if err != nil {
    // Handle error
}

// Redirect user to OAuth URL
http.Redirect(w, r, url, http.StatusTemporaryRedirect)
```

#### Handle OAuth Callback

```go
// Parse callback parameters
req, err := auth.ParseGoogleOAuthCallbackFromForm(r.URL.Query())
if err != nil {
    // Handle error
}

// Verify state token matches what you sent
// ... CSRF verification ...

// Process OAuth callback
resp, err := authService.HandleGoogleOAuthCallback(ctx, *req)
if err != nil {
    // Handle error
}

// resp contains:
// - resp.User: User information
// - resp.AccessToken: JWT access token
// - resp.RefreshToken: JWT refresh token
// - resp.ExpiresAt: Token expiration time
```

#### Get Linked Google Accounts

```go
accounts, err := authService.GetGoogleOAuthAccounts(ctx, userID)
if err != nil {
    // Handle error
}

for _, account := range accounts {
    fmt.Printf("Google Account: %s (%s)\n", account.Name, account.Email)
    fmt.Printf("Provider ID: %s\n", account.ProviderID)
    fmt.Printf("Picture: %s\n", account.Picture)
}
```

#### Unlink Google Account

```go
err := authService.UnlinkGoogleOAuth(ctx, userID, accountID)
if err != nil {
    // Handle error (e.g., "cannot unlink: this is your only authentication method")
}
```

## User Flows

### Flow 1: New User Registration via Google

```
1. User clicks "Sign in with Google" button
2. Frontend redirects to: GET /auth/google
3. User is redirected to Google login page
4. User authenticates with Google
5. Google redirects to: GET /auth/google/callback?code=xxx&state=xxx
6. Backend:
   - Exchanges code for OAuth tokens
   - Retrieves user info from Google
   - Creates new user account
   - Creates OAuth account record
   - Marks email as verified (if Google verified)
   - Generates JWT tokens
7. User receives access token and refresh token
8. User is now logged in
```

### Flow 2: Existing User Login via Google

```
1. User (already registered) clicks "Sign in with Google"
2. Frontend redirects to: GET /auth/google
3. User authenticates with Google
4. Google redirects to: GET /auth/google/callback?code=xxx&state=xxx
5. Backend:
   - Exchanges code for OAuth tokens
   - Retrieves user info from Google
   - Finds existing user by email
   - Links Google account to user
   - Updates OAuth account tokens
   - Generates JWT tokens
6. User receives access token and refresh token
7. User is now logged in
```

### Flow 3: Linking Google to Existing Account

```
1. User is already logged in (has password-based account)
2. User clicks "Link Google Account"
3. Frontend redirects to: GET /auth/google
4. User authenticates with Google
5. Google redirects to callback
6. Backend:
   - Verifies email matches logged-in user
   - Creates OAuth account record
   - Marks email as verified
7. Google account is now linked
```

### Flow 4: Unlinking Google Account

```
1. User (authenticated) wants to unlink Google
2. Frontend sends: POST /auth/google/unlink
   Headers: Authorization: Bearer <access_token>
   Body: {"account_id": "oauth-account-id"}
3. Backend:
   - Verifies account belongs to user
   - Checks if user has other auth methods (password or other OAuth)
   - If last auth method, returns error
   - Otherwise, deletes OAuth account record
4. Google account is unlinked
```

## API Endpoints

### Initiate Google OAuth Login

**Endpoint:** `GET /auth/google`

**Query Parameters:**
- `state` (optional): CSRF protection token

**Response:** Redirects to Google OAuth consent page

**Example:**
```bash
curl -L http://localhost:8080/auth/google
# User will be redirected to Google
```

---

### Google OAuth Callback

**Endpoint:** `GET /auth/google/callback`

**Query Parameters:**
- `code`: Authorization code from Google
- `state`: CSRF token

**Response:** `200 OK`
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@gmail.com",
    "first_name": "John",
    "last_name": "Doe",
    "active": true,
    "email_verified": true,
    "created_at": "2025-11-27T10:30:00Z",
    "updated_at": "2025-11-27T10:30:00Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "550e8400-e29b-41d4-a716-446655440001",
  "expires_at": "2025-11-27T10:45:00Z"
}
```

**Errors:**
- `400 Bad Request` - Invalid code or state
- `400 Bad Request` - Google OAuth is not enabled

---

### Unlink Google OAuth Account

**Endpoint:** `POST /auth/google/unlink`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "account_id": "oauth-account-id"
}
```

**Response:** `200 OK`
```json
{
  "message": "Google account unlinked successfully"
}
```

**Errors:**
- `401 Unauthorized` - Missing or invalid access token
- `400 Bad Request` - Cannot unlink only authentication method
- `404 Not Found` - OAuth account not found

**Example:**
```bash
curl -X POST http://localhost:8080/auth/google/unlink \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "oauth-account-id"}'
```

## Security Considerations

### CSRF Protection

Always use the `state` parameter for CSRF protection:

```go
// Generate secure random state token
state := generateSecureRandomString(32)

// Store in session or cookie
http.SetCookie(w, &http.Cookie{
    Name:     "oauth_state",
    Value:    state,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
    MaxAge:   600, // 10 minutes
})

// Generate OAuth URL with state
url, _ := authService.GetGoogleOAuthURL(auth.GoogleOAuthURLRequest{
    State: state,
})
```

Verify state on callback:

```go
// Get state from callback
callbackState := r.URL.Query().Get("state")

// Get state from cookie
cookie, _ := r.Cookie("oauth_state")
expectedState := cookie.Value

// Verify they match
if callbackState != expectedState {
    http.Error(w, "Invalid state parameter", http.StatusBadRequest)
    return
}
```

### Token Storage

- Store OAuth tokens securely in database
- Use HTTPS in production
- Don't expose OAuth access tokens to client
- JWT tokens should be stored securely on client side

### Account Security

- Users with only OAuth (no password) can't be locked out if OAuth provider has issues
- Recommend users to set a password as backup authentication method
- Implement account recovery mechanism

## Testing

### Manual Testing

1. **Start your server:**
```bash
go run main.go
```

2. **Open browser and navigate to:**
```
http://localhost:8080/auth/google
```

3. **You'll be redirected to Google login page**

4. **After authentication, you'll be redirected back with tokens**

### Automated Testing

The library includes comprehensive unit tests for OAuth functionality:

```bash
# Run OAuth tests
go test ./pkg/auth -v -run OAuth

# Run all tests
go test ./... -v
```

### Test Coverage

- ✅ OAuth URL generation
- ✅ New user registration via OAuth
- ✅ Existing user login via OAuth
- ✅ Account linking
- ✅ Token update on login
- ✅ Safe account unlinking
- ✅ Callback parsing
- ✅ Error handling

## Troubleshooting

### "Google OAuth is not enabled"

**Problem:** Getting error when trying to access OAuth endpoints

**Solution:** Make sure OAuth is enabled in configuration:
```go
cfg.OAuth.Google.Enabled = true
```

### "Redirect URI mismatch"

**Problem:** Google shows error about redirect URI mismatch

**Solution:** 
1. Check that `RedirectURL` in config matches exactly what's in Google Console
2. Include protocol (`http://` or `https://`)
3. Include port if not standard (`:8080`)
4. Path must match exactly (case-sensitive)

### "Cannot unlink: this is your only authentication method"

**Problem:** Can't unlink Google account

**Solution:** User must either:
1. Set a password first, then unlink Google
2. Link another OAuth provider, then unlink Google

### "Invalid state parameter"

**Problem:** CSRF validation failing

**Solution:**
1. Ensure state parameter is generated and stored
2. Verify state matches on callback
3. Check cookie settings (SameSite, Secure, etc.)
4. Make sure state doesn't expire before callback

### "User not found after OAuth"

**Problem:** User created but can't login

**Solution:**
1. Check migration 10 was applied (`oauth_accounts` table exists)
2. Verify store methods are implemented correctly
3. Check database constraints and foreign keys

### Database Schema

The `oauth_accounts` table structure:

```sql
CREATE TABLE oauth_accounts (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    provider_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    picture VARCHAR(512),
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, provider_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## Additional Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [goauthx API Reference](./api-reference.md)
- [Database Schema Documentation](./database.md)
- [Usage Examples](./usage-examples.md)

## Support

For issues and questions:
- Open an issue on [GitHub](https://github.com/devchuckcamp/goauthx/issues)
- Check existing documentation
- Review test files for implementation examples
