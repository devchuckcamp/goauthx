# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-11-27

### Added
- **Google OAuth Integration**: Sign in with Google support
  - `oauth_accounts` table for storing OAuth account linkages
  - `GetGoogleOAuthURL()` - Generate OAuth authorization URL
  - `HandleGoogleOAuthCallback()` - Process OAuth callback and create/login user
  - `GetGoogleOAuthAccounts()` - Get linked OAuth accounts for a user
  - `UnlinkGoogleOAuth()` - Safely unlink Google account
  - GET `/auth/google` - Initiate Google OAuth flow
  - GET `/auth/google/callback` - OAuth callback endpoint
  - POST `/auth/google/unlink` - Unlink Google account (authenticated)
  - Automatic account linking for existing users
  - Email verification via Google OAuth
  - Support for OAuth-only users (no password required)
  - CSRF protection with state parameter
  - Safe unlinking (prevents removing last auth method)
  - Comprehensive unit tests for all OAuth flows

- **OAuth Configuration**:
  - `OAuthConfig` struct with Google settings
  - `GoogleOAuthConfig` for client credentials and redirect URL
  - OAuth enabled/disabled toggle
  - Route configuration for OAuth endpoints

### Changed
- Database migrations updated to v10 (added oauth_accounts table)
- Store interface extended with OAuth account methods
- Service extended with OAuth methods
- Handlers updated to include OAuth endpoints
- Example updated with Google OAuth credentials
- Documentation updated with OAuth integration guide

### Technical Details
- 1 new database table (migration 10: oauth_accounts)
- 5 new service methods for OAuth
- 3 new REST endpoints
- OAuth token management and refresh
- Support for multiple OAuth providers (extensible design)
- Comprehensive OAuth unit tests (9 test cases)

## [1.1.0] - 2025-11-27

### Added
- **Pre-built HTTP Handlers**: Complete REST API handlers for all authentication operations
  - `NewHandlers()` function creates handlers with all endpoints configured
  - `RegisterRoutes()` method auto-registers all routes on a ServeMux
  - Includes proper error handling and JSON responses
  
- **Configurable Routes**: Customize all API endpoint paths
  - `RouteConfig` struct allows full route customization
  - `DefaultRouteConfig()` provides sensible defaults
  - All 13 endpoints can be configured independently (including OAuth)
  
- **Email Verification System**:
  - `email_verifications` table for storing verification tokens
  - `VerifyEmail()` service method
  - `ResendVerificationEmail()` service method
  - `email_verified` field added to users table
  - POST `/auth/verify-email` endpoint
  - GET `/auth/verify-email?token=xyz` endpoint support
  - POST `/auth/resend-verification` endpoint
  - Tokens expire after 24 hours
  - One-time use tokens with `used_at` tracking
  
- **Password Reset System**:
  - `password_resets` table for storing reset tokens
  - `RequestPasswordReset()` service method
  - `ResetPassword()` service method
  - POST `/auth/forgot-password` endpoint
  - POST `/auth/reset-password` endpoint
  - Tokens expire after 1 hour
  - One-time use tokens with automatic cleanup
  - All refresh tokens revoked after password reset
  
- **Change Password Feature**:
  - `ChangePassword()` service method
  - Requires current password for security
  - POST `/auth/change-password` endpoint (authenticated)
  - All refresh tokens revoked after password change
  
- **New Service Methods**:
  - `GetUserByID()` - Retrieve user by ID
  - Store methods for email verification and password reset operations
  
- **New Examples**:
  - `examples/with-handlers/` - Complete example using pre-built handlers
  - Demonstrates all new features
  
- **Enhanced Documentation**:
  - `docs/api-reference.md` - Complete REST API documentation
  - Updated `README.md` with new features and usage examples
  - Updated `docs/database.md` with new tables
  - Updated `docs/usage-examples.md` with password and email examples
  - Added cURL examples for all endpoints

### Changed
- User model now includes `email_verified` boolean field
- All SQL queries updated to include `email_verified` field
- Database migrations updated to v8 (added 2 new tables)
- Examples updated to demonstrate new features
- README reorganized for better clarity

### Technical Details
- 2 new database tables (migrations 7 and 8)
- 1 new package (`pkg/handlers`)
- 4 new model types
- 10+ new service methods
- 5 new REST endpoints
- JSON struct tags added to all request types
- Comprehensive error handling in handlers

## [1.0.0] - 2025-11-27

### Added
- Initial release
- User authentication (register, login, logout)
- JWT access tokens with refresh token support
- Role-Based Access Control (RBAC)
- Permission system
- Multi-database support (PostgreSQL, MySQL, SQL Server)
- HTTP middleware for authentication and authorization
- Database migration system
- CLI migration tool
- Comprehensive documentation
- Basic examples

### Features
- **Authentication**: Register, login, logout, token refresh
- **Authorization**: Roles and permissions with granular control
- **Security**: Bcrypt password hashing, JWT tokens, refresh tokens
- **Database**: 6 core tables with proper relationships and indexes
- **Middleware**: Ready-to-use HTTP middleware for net/http
- **Framework Agnostic**: Works with any Go HTTP framework
- **Production Ready**: Error handling, validation, transactions

### Security
- Bcrypt password hashing (cost 12 by default)
- JWT HS256 token signing
- Refresh token rotation
- Prepared statements (SQL injection protection)
- Foreign key constraints
- Soft deletes for users

### Database Support
- PostgreSQL (primary)
- MySQL
- Microsoft SQL Server

### Documentation
- Complete README with quick start
- Database schema documentation
- Migration guide
- Usage examples
- API overview

[1.1.0]: https://github.com/devchuckcamp/goauthx/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/devchuckcamp/goauthx/releases/tag/v1.0.0
