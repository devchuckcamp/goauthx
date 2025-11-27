# API Reference

This document provides a complete reference for the goauthx REST API endpoints.

## Table of Contents

- [Authentication Endpoints](#authentication-endpoints)
- [User Profile Endpoints](#user-profile-endpoints)
- [Password Management](#password-management)
- [Email Verification](#email-verification)
- [Error Responses](#error-responses)

## Base Configuration

By default, all authentication endpoints are prefixed with `/auth`:

- Base Path: `/auth`
- Content-Type: `application/json`
- Authorization: `Bearer <access_token>` (for protected endpoints)

You can customize these paths using `RouteConfig`:

```go
routeConfig := goauthx.DefaultRouteConfig()
routeConfig.RegisterPath = "/api/v1/register"  // Customize paths
handlers := goauthx.NewHandlers(authService, routeConfig)
```

---

## Authentication Endpoints

### Register User

Create a new user account.

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:** `201 Created`
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "active": true,
    "email_verified": false,
    "created_at": "2025-11-27T10:30:00Z",
    "updated_at": "2025-11-27T10:30:00Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "550e8400-e29b-41d4-a716-446655440001",
  "expires_at": "2025-11-27T10:45:00Z"
}
```

**Errors:**
- `400 Bad Request` - Invalid request body or password too weak
- `400 Bad Request` - Email already exists

---

### Login

Authenticate a user and receive access tokens.

**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Response:** `200 OK`
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "active": true,
    "email_verified": false,
    "created_at": "2025-11-27T10:30:00Z",
    "updated_at": "2025-11-27T10:30:00Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "550e8400-e29b-41d4-a716-446655440001",
  "expires_at": "2025-11-27T10:45:00Z"
}
```

**Errors:**
- `401 Unauthorized` - Invalid credentials
- `401 Unauthorized` - User account is inactive

---

### Refresh Token

Generate a new access token using a refresh token.

**Endpoint:** `POST /auth/refresh`

**Request Body:**
```json
{
  "refresh_token": "550e8400-e29b-41d4-a716-446655440001"
}
```

**Response:** `200 OK`
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "active": true,
    "email_verified": false
  },
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "550e8400-e29b-41d4-a716-446655440002",
  "expires_at": "2025-11-27T11:00:00Z"
}
```

**Errors:**
- `401 Unauthorized` - Invalid or expired refresh token

---

### Logout

Revoke all refresh tokens for the authenticated user.

**Endpoint:** `POST /auth/logout`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Successfully logged out"
}
```

**Errors:**
- `401 Unauthorized` - Missing or invalid access token

---

## User Profile Endpoints

### Get Profile

Retrieve the authenticated user's profile information.

**Endpoint:** `GET /auth/profile`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "active": true,
    "email_verified": true,
    "created_at": "2025-11-27T10:30:00Z",
    "updated_at": "2025-11-27T10:30:00Z"
  },
  "roles": ["user", "admin"]
}
```

**Errors:**
- `401 Unauthorized` - Missing or invalid access token
- `404 Not Found` - User not found

---

## Password Management

### Change Password

Change the authenticated user's password (requires current password).

**Endpoint:** `POST /auth/change-password`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "old_password": "currentPassword123",
  "new_password": "newSecurePassword456"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password changed successfully"
}
```

**Notes:**
- All refresh tokens are automatically revoked after password change
- User must login again with the new password

**Errors:**
- `401 Unauthorized` - Missing or invalid access token
- `401 Unauthorized` - Incorrect old password
- `400 Bad Request` - New password doesn't meet requirements

---

### Request Password Reset

Request a password reset token (sent via email in production).

**Endpoint:** `POST /auth/forgot-password`

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset link has been sent",
  "data": {
    "reset_token": "abc123...xyz"
  }
}
```

**Notes:**
- In production, the `reset_token` should NOT be included in the response
- Token should be sent via email to the user
- Token expires in 1 hour
- For security, response is the same whether email exists or not

---

### Reset Password

Reset password using a password reset token.

**Endpoint:** `POST /auth/reset-password`

**Request Body:**
```json
{
  "token": "abc123...xyz",
  "new_password": "newSecurePassword456"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset successfully"
}
```

**Notes:**
- Token can only be used once
- All refresh tokens are automatically revoked after password reset
- User must login again with the new password

**Errors:**
- `400 Bad Request` - Invalid or expired token
- `400 Bad Request` - New password doesn't meet requirements

---

## Email Verification

### Verify Email

Verify a user's email address using a verification token.

**Endpoint:** `POST /auth/verify-email` or `GET /auth/verify-email?token=xyz`

**Request Body (POST):**
```json
{
  "token": "abc123...xyz"
}
```

**Query Parameter (GET):**
```
?token=abc123...xyz
```

**Response:** `200 OK`
```json
{
  "message": "Email verified successfully"
}
```

**Notes:**
- Token expires in 24 hours
- Token can only be used once
- Supports both POST (JSON) and GET (query parameter) for flexibility

**Errors:**
- `400 Bad Request` - Missing token
- `400 Bad Request` - Invalid or expired token

---

### Resend Verification Email

Request a new email verification token for the authenticated user.

**Endpoint:** `POST /auth/resend-verification`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Verification email has been sent",
  "data": {
    "verification_token": "abc123...xyz"
  }
}
```

**Notes:**
- In production, the `verification_token` should NOT be included in the response
- Token should be sent via email to the user
- Token expires in 24 hours

**Errors:**
- `401 Unauthorized` - Missing or invalid access token
- `400 Bad Request` - Email already verified

---

## Error Responses

All error responses follow this format:

```json
{
  "error": "Detailed error message",
  "message": "HTTP status text"
}
```

### Common HTTP Status Codes

| Status Code | Description |
|-------------|-------------|
| `200 OK` | Request successful |
| `201 Created` | Resource created successfully |
| `400 Bad Request` | Invalid request data or business logic error |
| `401 Unauthorized` | Missing, invalid, or expired authentication |
| `404 Not Found` | Resource not found |
| `405 Method Not Allowed` | HTTP method not supported |
| `500 Internal Server Error` | Server error |

### Common Error Messages

**Authentication Errors:**
- `invalid credentials` - Wrong email/password
- `user account is inactive` - Account has been deactivated
- `invalid refresh token` - Refresh token is invalid or expired
- `email already exists` - Email is already registered

**Password Errors:**
- `password must be at least X characters` - Password too short
- `invalid or expired reset token` - Password reset token is invalid
- `invalid or expired verification token` - Email verification token is invalid

**Authorization Errors:**
- `permission denied` - User lacks required permissions
- `role required: admin` - User doesn't have required role

---

## cURL Examples

### Complete Authentication Flow

```bash
# 1. Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secure123","first_name":"John","last_name":"Doe"}'

# 2. Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secure123"}'

# 3. Get Profile (use access_token from login)
curl -X GET http://localhost:8080/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# 4. Change Password
curl -X POST http://localhost:8080/auth/change-password \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"old_password":"secure123","new_password":"newSecure456"}'

# 5. Refresh Token
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"YOUR_REFRESH_TOKEN"}'

# 6. Logout
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Password Reset Flow

```bash
# 1. Request password reset
curl -X POST http://localhost:8080/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'

# 2. Reset password with token
curl -X POST http://localhost:8080/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"RESET_TOKEN","new_password":"newSecure456"}'
```

### Email Verification Flow

```bash
# 1. Verify email with token (POST method)
curl -X POST http://localhost:8080/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token":"VERIFICATION_TOKEN"}'

# 2. Verify email with token (GET method - useful for email links)
curl -X GET "http://localhost:8080/auth/verify-email?token=VERIFICATION_TOKEN"

# 3. Resend verification email
curl -X POST http://localhost:8080/auth/resend-verification \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```
