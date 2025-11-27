# Architecture Overview

## Introduction

`goauthx` is designed as a modular, framework-agnostic authentication and authorization library for Go. It follows clean architecture principles with clear separation of concerns.

## Design Principles

### 1. Framework Agnostic
The core library doesn't depend on any specific web framework. HTTP middleware is provided as helpers that can be adapted to any framework (net/http, Gin, Echo, Fiber, etc.).

### 2. Database Agnostic (within SQL)
While focused on SQL databases, the library abstracts database operations through interfaces, making it easy to support different SQL dialects (MySQL, PostgreSQL, SQL Server).

### 3. Production Ready
- Comprehensive error handling
- Transaction support
- Connection pooling
- Password hashing with bcrypt
- Secure JWT token generation
- Token refresh mechanism

### 4. Clean Architecture
The project follows a layered architecture:

```
┌─────────────────────────────────────┐
│     HTTP Layer (Middleware)         │  ← Framework integration
├─────────────────────────────────────┤
│     Service Layer (Auth)             │  ← Business logic
├─────────────────────────────────────┤
│     Store Layer (SQL)                │  ← Data access
├─────────────────────────────────────┤
│     Database (MySQL/Postgres/MSSQL)  │  ← Persistence
└─────────────────────────────────────┘
```

## Project Structure

```
goauthx/
├── cmd/
│   └── goauthx-migrate/        # Migration CLI tool
│       └── main.go
├── pkg/
│   ├── auth/                    # Authentication service
│   │   └── auth.go
│   ├── config/                  # Configuration
│   │   └── config.go
│   ├── middleware/              # HTTP middleware
│   │   └── middleware.go
│   ├── migrations/              # Migration system
│   │   ├── migrator.go
│   │   └── tables.go
│   ├── models/                  # Domain models
│   │   └── models.go
│   ├── password/                # Password hashing
│   │   └── password.go
│   ├── store/                   # Data access interfaces
│   │   ├── store.go
│   │   └── sqlstore/            # SQL implementation
│   │       ├── store.go
│   │       ├── user.go
│   │       ├── role.go
│   │       ├── permission.go
│   │       ├── user_role.go
│   │       ├── role_permission.go
│   │       └── refresh_token.go
│   └── tokens/                  # JWT token management
│       └── tokens.go
├── examples/                    # Example applications
│   └── basic-nethttp/
├── docs/                        # Documentation
├── goauthx.go                  # Main package entrypoint
├── go.mod
└── README.md
```

## Core Components

### 1. Models (`pkg/models`)
Domain entities representing users, roles, permissions, and their relationships.

**Key Models:**
- `User`: User accounts
- `Role`: Named groups of permissions
- `Permission`: Granular access rights
- `RefreshToken`: Long-lived tokens for session management

### 2. Store (`pkg/store`)
Data access layer with clean interfaces and SQL implementation.

**Interfaces:**
- `UserStore`: User CRUD operations
- `RoleStore`: Role management
- `PermissionStore`: Permission management
- `UserRoleStore`: User-role relationships
- `RolePermissionStore`: Role-permission relationships
- `RefreshTokenStore`: Token management

**Implementation:**
- `sqlstore`: SQL database implementation supporting MySQL, PostgreSQL, and SQL Server

### 3. Authentication Service (`pkg/auth`)
Business logic for authentication and authorization.

**Core Operations:**
- `Register()`: Create new users
- `Login()`: Authenticate users
- `Logout()`: Invalidate sessions
- `RefreshAccessToken()`: Issue new access tokens
- `ValidateToken()`: Verify JWT tokens
- `HasRole()`: Check user roles
- `HasPermission()`: Check user permissions
- `GetUserPermissions()`: Retrieve all user permissions

### 4. Token Management (`pkg/tokens`)
JWT token generation and validation.

**Features:**
- HS256 signing algorithm
- Configurable expiry
- Custom claims (user ID, email, roles)
- Refresh token generation

### 5. Password Management (`pkg/password`)
Secure password hashing and verification.

**Features:**
- Bcrypt hashing (configurable cost)
- Password strength validation
- Constant-time comparison

### 6. Middleware (`pkg/middleware`)
HTTP middleware for authentication and authorization.

**Middleware:**
- `Authenticate()`: Validate JWT tokens
- `RequireRole()`: Enforce role requirements
- `RequireAnyRole()`: Require any of multiple roles
- `RequirePermission()`: Enforce permission requirements

**Context Helpers:**
- `GetUserID()`: Extract user ID from context
- `GetUserEmail()`: Extract email from context
- `GetUserRoles()`: Extract roles from context
- `GetClaims()`: Extract full JWT claims

### 7. Configuration (`pkg/config`)
Centralized configuration with validation.

**Configuration Sections:**
- `DatabaseConfig`: Connection settings
- `JWTConfig`: Token settings
- `PasswordConfig`: Hashing settings
- `TokenConfig`: Refresh token settings

### 8. Migrations (`pkg/migrations`)
Database schema management.

**Features:**
- Versioned migrations
- Up/down support
- Multi-database dialect support
- Migration history tracking

## Authentication Flow

```
1. User Registration
   ┌──────┐
   │Client│
   └──┬───┘
      │ POST /register {email, password}
      ↓
   ┌──────────┐
   │  Auth    │ → Hash password
   │ Service  │ → Create user
   └──┬───────┘ → Generate tokens
      ↓
   ┌──────┐
   │Store │ → Save user & refresh token
   └──────┘

2. User Login
   ┌──────┐
   │Client│
   └──┬───┘
      │ POST /login {email, password}
      ↓
   ┌──────────┐
   │  Auth    │ → Verify password
   │ Service  │ → Get user roles
   └──┬───────┘ → Generate tokens
      ↓
   ┌──────┐
   │Store │ → Save refresh token
   └──────┘

3. Protected Request
   ┌──────┐
   │Client│ Authorization: Bearer <token>
   └──┬───┘
      │
      ↓
   ┌────────────┐
   │ Middleware │ → Validate JWT
   └──┬─────────┘ → Extract claims
      │           → Add to context
      ↓
   ┌─────────┐
   │ Handler │ → Process request
   └─────────┘

4. Token Refresh
   ┌──────┐
   │Client│ POST /refresh {refresh_token}
   └──┬───┘
      │
      ↓
   ┌──────────┐
   │  Auth    │ → Validate refresh token
   │ Service  │ → Get user
   └──┬───────┘ → Generate new tokens
      ↓
   ┌──────┐
   │Store │ → Save new refresh token
   └──────┘
```

## Authorization Flow

```
Permission Check:
User → [User-Roles] → Roles → [Role-Permissions] → Permissions

Example:
User "john@example.com"
  ├─ Role "editor"
  │   ├─ Permission "posts:read"
  │   ├─ Permission "posts:write"
  │   └─ Permission "posts:edit"
  └─ Role "moderator"
      ├─ Permission "comments:read"
      ├─ Permission "comments:delete"
      └─ Permission "users:ban"

HasPermission("posts:write") → true (via "editor" role)
HasPermission("users:delete") → false (no role grants this)
```

## Security Considerations

### 1. Password Security
- Passwords are hashed using bcrypt with configurable cost (default: 12)
- Passwords are never stored in plain text
- Minimum password length enforced (default: 8 characters)

### 2. Token Security
- JWT tokens use HS256 signing
- Secrets must be at least 32 characters
- Access tokens have short expiry (default: 15 minutes)
- Refresh tokens have longer expiry (default: 7 days)
- Refresh tokens can be revoked

### 3. Database Security
- Prepared statements prevent SQL injection
- Foreign key constraints ensure referential integrity
- Indexes optimize query performance

### 4. Session Management
- Refresh tokens are stored in the database
- Tokens can be revoked individually or all at once
- Expired tokens are automatically invalidated

## Extensibility

### Adding Custom User Fields
Extend the `User` model and modify the SQL schema:

```go
type User struct {
	models.User
	Department string
	EmployeeID string
}
```

### Custom Permission Logic
Implement additional permission checking:

```go
func HasResourcePermission(ctx context.Context, userID, resource, action string) (bool, error) {
	permissions, err := service.GetUserPermissions(ctx, userID)
	// Custom logic here
}
```

### Framework Integration
Create framework-specific middleware by adapting the provided middleware:

```go
// Gin example
func GinAuthMiddleware(authMiddleware *goauthx.AuthMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Adapt the middleware
	}
}
```

## Performance Considerations

### Database Connection Pooling
Configure connection pool settings based on your workload:

```go
cfg.Database.MaxOpenConns = 25
cfg.Database.MaxIdleConns = 5
cfg.Database.ConnMaxLifetime = 5 * time.Minute
```

### Token Validation
JWT validation is performed in-memory without database queries, making it very fast.

### Permission Caching
Consider caching user permissions in Redis or in-memory to reduce database load:

```go
// Pseudo-code
permissions := cache.Get(userID)
if permissions == nil {
	permissions = service.GetUserPermissions(ctx, userID)
	cache.Set(userID, permissions, 5*time.Minute)
}
```

## Testing Strategy

The library is designed to be testable:

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test database operations with real databases
3. **End-to-End Tests**: Test complete authentication flows

Mock the `Store` interface for testing services without a database:

```go
type MockStore struct {
	// Mock implementation
}

func TestRegister(t *testing.T) {
	mockStore := &MockStore{}
	service := auth.NewService(cfg, mockStore)
	// Test registration
}
```
