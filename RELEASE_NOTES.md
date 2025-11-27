# goauthx v1.1.0 - Feature Summary

## Overview

This update significantly enhances goauthx with pre-built HTTP handlers, email verification, password reset, and configurable routes - making it production-ready out of the box.

## Major New Features

### 1. Pre-built HTTP Handlers 🎯

The biggest improvement! No need to write your own handlers anymore.

**Before (v1.0):**
```go
// You had to write all handlers manually
func registerHandler(service *goauthx.Service) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 30+ lines of boilerplate code...
    }
}
```

**After (v1.1):**
```go
// One line to get all endpoints!
handlers := goauthx.NewHandlers(authService, nil)
handlers.RegisterRoutes(mux)
// Done! All 10 endpoints are ready to use
```

**Available Endpoints:**
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - Logout (authenticated)
- `POST /auth/refresh` - Refresh access token
- `GET /auth/profile` - Get user profile (authenticated)
- `POST /auth/change-password` - Change password (authenticated)
- `POST /auth/forgot-password` - Request password reset
- `POST /auth/reset-password` - Reset password with token
- `POST /auth/verify-email` - Verify email address
- `POST /auth/resend-verification` - Resend verification (authenticated)

### 2. Configurable Routes 🛣️

Customize all endpoint paths to match your API design.

```go
routeConfig := goauthx.DefaultRouteConfig()
routeConfig.RegisterPath = "/api/v1/auth/signup"
routeConfig.LoginPath = "/api/v1/auth/signin"
routeConfig.ProfilePath = "/api/v1/users/me"

handlers := goauthx.NewHandlers(authService, routeConfig)
```

### 3. Email Verification 📧

Complete email verification system with secure tokens.

**Features:**
- Automatic token generation
- 24-hour token expiration
- One-time use tokens
- Resend verification support
- Email verified status tracking

**Usage:**
```go
// After registration
token, _ := service.ResendVerificationEmail(ctx, userID)
// Send token via email

// User verifies
err := service.VerifyEmail(ctx, token)
```

### 4. Password Reset 🔑

Secure password reset flow with time-limited tokens.

**Features:**
- Secure token generation
- 1-hour token expiration
- One-time use tokens
- Automatic session invalidation
- Security-first design (no email enumeration)

**Usage:**
```go
// Request reset
token, _ := service.RequestPasswordReset(ctx, "user@example.com")
// Send token via email

// Reset password
err := service.ResetPassword(ctx, goauthx.ResetPasswordRequest{
    Token:       token,
    NewPassword: "NewSecure123!",
})
```

### 5. Change Password 🔐

Authenticated users can change their password securely.

**Features:**
- Requires current password
- Password strength validation
- Automatic session invalidation
- All tokens revoked after change

**Usage:**
```go
err := service.ChangePassword(ctx, userID, goauthx.ChangePasswordRequest{
    OldPassword: "Current123",
    NewPassword: "NewSecure456!",
})
```

## Database Changes

### New Tables

**`email_verifications`**
- Stores email verification tokens
- Tracks usage and expiration
- Auto-cleanup of expired tokens

**`password_resets`**
- Stores password reset tokens
- One-time use with expiration
- Secure token storage

### Modified Tables

**`users`**
- Added `email_verified` field (BOOLEAN)
- Defaults to `false`
- Updated all queries to include this field

## New Migrations

- **Migration 7**: Create `email_verifications` table
- **Migration 8**: Create `password_resets` table

All existing databases can safely upgrade with `migrator.Up()`.

## Documentation Updates

### New Documentation
- **`docs/api-reference.md`** - Complete REST API documentation
  - All endpoints documented
  - Request/response examples
  - Error codes and messages
  - cURL examples

### Updated Documentation
- **`README.md`**
  - New features highlighted
  - Pre-built handlers section
  - Updated examples
  - Testing guide expanded
  
- **`docs/database.md`**
  - New tables documented
  - Updated ER diagram
  - Index documentation
  
- **`docs/usage-examples.md`**
  - Password management examples
  - Email verification examples
  - Handler usage examples

## Breaking Changes

**None!** This is a backwards-compatible release.

- Existing code continues to work
- New features are opt-in
- Database migrations are additive
- Old examples still work

## Migration Guide

### From v1.0 to v1.1

**Step 1: Update dependency**
```bash
go get github.com/devchuckcamp/goauthx@v1.1.0
```

**Step 2: Run migrations**
```bash
# Migrations are automatic
migrator := goauthx.NewMigrator(store, driver)
migrator.Up(context.Background())
```

**Step 3 (Optional): Use new handlers**
```go
// Replace your manual handlers with:
handlers := goauthx.NewHandlers(authService, nil)
handlers.RegisterRoutes(mux)
```

## Performance Considerations

- **No performance impact** on existing functionality
- New tables are indexed for optimal query performance
- Token cleanup can be automated (see docs)
- All queries use prepared statements

## Security Enhancements

1. **Email Verification**
   - Prevents spam registrations
   - Confirms email ownership
   - Required for production use

2. **Password Reset**
   - Time-limited tokens (1 hour)
   - One-time use only
   - No email enumeration
   - All sessions invalidated

3. **Password Change**
   - Requires current password
   - Automatic session invalidation
   - Strength validation

## Examples

### Quick Start (10 lines!)

```go
cfg := goauthx.DefaultConfig()
cfg.Database.Driver = goauthx.Postgres
cfg.Database.DSN = "postgres://..."
cfg.JWT.Secret = "your-secret-key-min-32-chars"

store, _ := goauthx.NewStore(cfg.Database)
migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
migrator.Up(context.Background())

authService, _ := goauthx.NewService(cfg, store)
handlers := goauthx.NewHandlers(authService, nil)
handlers.RegisterRoutes(http.NewServeMux())
```

### Testing with Docker

```bash
# Start PostgreSQL
docker-compose up -d

# Run example
cd examples/with-handlers
go run main.go

# Test registration
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"secure123","first_name":"Test","last_name":"User"}'

# Test all other endpoints...
```

## What's Next?

### Planned Features (v1.2)
- Rate limiting middleware
- OAuth2/Social login support
- Multi-factor authentication (MFA)
- Session management UI
- Audit logging

### Community Feedback Welcome!
- Open issues for bugs or feature requests
- Pull requests are welcome
- Star the repository if you find it useful

## Comparison: v1.0 vs v1.1

| Feature | v1.0 | v1.1 |
|---------|------|------|
| HTTP Handlers | Manual | Pre-built ✨ |
| Routes | Fixed | Configurable ✨ |
| Email Verification | ❌ | ✅ ✨ |
| Password Reset | ❌ | ✅ ✨ |
| Change Password | ❌ | ✅ ✨ |
| API Documentation | Basic | Complete ✨ |
| Database Tables | 6 | 8 |
| REST Endpoints | 4 | 10 |
| Examples | 1 | 2 |
| Lines of Code (saved) | 0 | 300+ |

## Conclusion

Version 1.1.0 transforms goauthx from a library that requires significant boilerplate into a **production-ready, plug-and-play authentication system**. The pre-built handlers alone save hundreds of lines of code, while email verification and password reset make it suitable for real-world applications.

**Upgrade today and simplify your authentication!**

---

For detailed documentation, visit the `docs/` directory or read the README.md.
