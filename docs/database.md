# Database Schema

## Overview

The goauthx library uses eight core tables to manage authentication and authorization:

1. **users** - User accounts
2. **roles** - Named groups of permissions
3. **permissions** - Granular access rights
4. **user_roles** - Many-to-many relationship between users and roles
5. **role_permissions** - Many-to-many relationship between roles and permissions
6. **refresh_tokens** - Session management tokens
7. **email_verifications** - Email verification tokens
8. **password_resets** - Password reset tokens

Additionally, a **schema_migrations** table tracks applied migrations.

## Entity Relationship Diagram

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│    users     │         │  user_roles  │         │    roles     │
├──────────────┤         ├──────────────┤         ├──────────────┤
│ id (PK)      │────────<│ user_id (FK) │>────────│ id (PK)      │
│ email        │         │ role_id (FK) │         │ name         │
│ password_hash│         │ assigned_at  │         │ description  │
│ first_name   │         └──────────────┘         │ created_at   │
│ last_name    │                                  │ updated_at   │
│ active       │         ┌──────────────┐         └──────────────┘
│ created_at   │         │role_perms    │                │
│ updated_at   │         ├──────────────┤                │
└──────────────┘         │ role_id (FK) │>───────────────┘
       │                 │ perm_id (FK) │
       │                 │ granted_at   │         ┌──────────────┐
       │                 └──────────────┘         │ permissions  │
       │                        │                 ├──────────────┤
       │                        └────────────────>│ id (PK)      │
       │                                          │ name         │
       │                 ┌──────────────┐         │ resource     │
       └────────────────<│refresh_tokens│         │ action       │
                         ├──────────────┤         │ description  │
                         │ id (PK)      │         │ created_at   │
                         │ user_id (FK) │         │ updated_at   │
                         │ token        │         └──────────────┘
                         │ expires_at   │
                         │ created_at   │
                         │ revoked_at   │
                         └──────────────┘
```

## Table Schemas

### users

Stores user account information.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | VARCHAR(36) | PRIMARY KEY | Unique identifier (UUID) |
| email | VARCHAR(255) | NOT NULL, UNIQUE | User's email address |
| password_hash | VARCHAR(255) | NOT NULL | Bcrypt hashed password |
| first_name | VARCHAR(100) | | User's first name |
| last_name | VARCHAR(100) | | User's last name |
| active | BOOLEAN | NOT NULL, DEFAULT TRUE | Account active status |
| email_verified | BOOLEAN | NOT NULL, DEFAULT FALSE | Email verification status |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Last update timestamp |

**Indexes:**
- `idx_users_email` on `email`
- `idx_users_active` on `active`

**Notes:**
- Email is unique and used for login
- Password is hashed using bcrypt (never stored in plain text)
- Active flag allows soft deletion of accounts
- Email verification is optional but recommended for production

### roles

Stores role definitions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | VARCHAR(36) | PRIMARY KEY | Unique identifier (UUID) |
| name | VARCHAR(100) | NOT NULL, UNIQUE | Role name (e.g., "admin", "editor") |
| description | TEXT | | Role description |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Last update timestamp |

**Indexes:**
- `idx_roles_name` on `name`

**Notes:**
- Role names should be unique and descriptive
- Common roles: admin, user, moderator, editor, viewer

### permissions

Stores permission definitions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | VARCHAR(36) | PRIMARY KEY | Unique identifier (UUID) |
| name | VARCHAR(100) | NOT NULL, UNIQUE | Permission name (e.g., "posts:write") |
| resource | VARCHAR(100) | NOT NULL | Resource type (e.g., "posts") |
| action | VARCHAR(50) | NOT NULL | Action type (e.g., "write", "read") |
| description | TEXT | | Permission description |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Last update timestamp |

**Indexes:**
- `idx_permissions_name` on `name`
- `idx_permissions_resource` on `resource`

**Notes:**
- Permission names follow format: `resource:action`
- Example permissions: `posts:read`, `posts:write`, `users:delete`, `comments:moderate`

### user_roles

Junction table for users and roles (many-to-many).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| user_id | VARCHAR(36) | FK to users.id, NOT NULL | User identifier |
| role_id | VARCHAR(36) | FK to roles.id, NOT NULL | Role identifier |
| assigned_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Assignment timestamp |

**Primary Key:** `(user_id, role_id)`

**Foreign Keys:**
- `user_id` REFERENCES `users(id)` ON DELETE CASCADE
- `role_id` REFERENCES `roles(id)` ON DELETE CASCADE

**Indexes:**
- `idx_user_roles_user_id` on `user_id`
- `idx_user_roles_role_id` on `role_id`

**Notes:**
- A user can have multiple roles
- Deleting a user or role cascades to this table

### role_permissions

Junction table for roles and permissions (many-to-many).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| role_id | VARCHAR(36) | FK to roles.id, NOT NULL | Role identifier |
| permission_id | VARCHAR(36) | FK to permissions.id, NOT NULL | Permission identifier |
| granted_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Grant timestamp |

**Primary Key:** `(role_id, permission_id)`

**Foreign Keys:**
- `role_id` REFERENCES `roles(id)` ON DELETE CASCADE
- `permission_id` REFERENCES `permissions(id)` ON DELETE CASCADE

**Indexes:**
- `idx_role_permissions_role_id` on `role_id`
- `idx_role_permissions_permission_id` on `permission_id`

**Notes:**
- A role can have multiple permissions
- Deleting a role or permission cascades to this table

### refresh_tokens

Stores refresh tokens for session management.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | VARCHAR(36) | PRIMARY KEY | Unique identifier (UUID) |
| user_id | VARCHAR(36) | FK to users.id, NOT NULL | User identifier |
| token | VARCHAR(255) | NOT NULL, UNIQUE | Refresh token string |
| expires_at | TIMESTAMP | NOT NULL | Token expiration time |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation timestamp |
| revoked_at | TIMESTAMP | NULL | Revocation timestamp |

**Foreign Keys:**
- `user_id` REFERENCES `users(id)` ON DELETE CASCADE

**Indexes:**
- `idx_refresh_tokens_token` on `token`
- `idx_refresh_tokens_user_id` on `user_id`
- `idx_refresh_tokens_expires_at` on `expires_at`

**Notes:**
- Refresh tokens are used to obtain new access tokens
- `revoked_at` is NULL for active tokens, non-NULL when revoked
- Expired tokens can be deleted periodically

### email_verifications

Stores email verification tokens.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | VARCHAR(36) | PRIMARY KEY | Unique identifier (UUID) |
| user_id | VARCHAR(36) | NOT NULL, FOREIGN KEY | User who needs verification |
| token | VARCHAR(255) | NOT NULL, UNIQUE | Verification token |
| expires_at | TIMESTAMP | NOT NULL | Token expiration time |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation timestamp |
| used_at | TIMESTAMP | NULL | When token was used (NULL if unused) |

**Foreign Keys:**
- `user_id` REFERENCES `users(id)` ON DELETE CASCADE

**Indexes:**
- `idx_email_verifications_token` on `token`
- `idx_email_verifications_user_id` on `user_id`
- `idx_email_verifications_expires_at` on `expires_at`

**Notes:**
- Tokens expire after 24 hours by default
- `used_at` is NULL for unused tokens, non-NULL when verified
- Tokens can only be used once
- Expired tokens can be deleted periodically

### password_resets

Stores password reset tokens.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | VARCHAR(36) | PRIMARY KEY | Unique identifier (UUID) |
| user_id | VARCHAR(36) | NOT NULL, FOREIGN KEY | User requesting password reset |
| token | VARCHAR(255) | NOT NULL, UNIQUE | Reset token |
| expires_at | TIMESTAMP | NOT NULL | Token expiration time |
| created_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Creation timestamp |
| used_at | TIMESTAMP | NULL | When token was used (NULL if unused) |

**Foreign Keys:**
- `user_id` REFERENCES `users(id)` ON DELETE CASCADE

**Indexes:**
- `idx_password_resets_token` on `token`
- `idx_password_resets_user_id` on `user_id`
- `idx_password_resets_expires_at` on `expires_at`

**Notes:**
- Tokens expire after 1 hour by default
- `used_at` is NULL for unused tokens, non-NULL when password is reset
- Tokens can only be used once
- Expired tokens can be deleted periodically
- All refresh tokens are revoked when password is reset

### schema_migrations

Tracks applied database migrations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| version | INT | PRIMARY KEY | Migration version number |
| name | VARCHAR(255) | NOT NULL | Migration name |
| applied_at | TIMESTAMP | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Application timestamp |

**Notes:**
- Automatically managed by the migration system
- Do not manually modify this table

## Database-Specific Considerations

### PostgreSQL

- Uses `VARCHAR` for string columns
- Uses `BOOLEAN` for boolean columns
- Indexes created separately after table creation
- Supports `ON DELETE CASCADE` natively

**Example Connection String:**
```
postgres://user:password@localhost:5432/dbname?sslmode=disable
```

### MySQL

- Uses `VARCHAR` with UTF-8 encoding (`utf8mb4_unicode_ci`)
- Uses `BOOLEAN` (internally stored as TINYINT(1))
- Supports `ON UPDATE CURRENT_TIMESTAMP` for `updated_at` columns
- Uses `InnoDB` engine for transactions and foreign keys

**Example Connection String:**
```
user:password@tcp(localhost:3306)/dbname?parseTime=true
```

**Important:** Add `?parseTime=true` to properly handle `TIMESTAMP` columns.

### SQL Server

- Uses `NVARCHAR` for Unicode string columns
- Uses `BIT` for boolean columns
- Uses `NVARCHAR(MAX)` for text columns
- Uses `DATETIME` instead of `TIMESTAMP`
- Uses `GETDATE()` for current timestamp

**Example Connection String:**
```
sqlserver://user:password@localhost:1433?database=dbname
```

## Common Queries

### Get User with Roles
```sql
SELECT 
    u.id, u.email, u.first_name, u.last_name,
    r.id as role_id, r.name as role_name
FROM users u
LEFT JOIN user_roles ur ON ur.user_id = u.id
LEFT JOIN roles r ON r.id = ur.role_id
WHERE u.email = ?;
```

### Get User Permissions
```sql
SELECT DISTINCT p.*
FROM permissions p
INNER JOIN role_permissions rp ON rp.permission_id = p.id
INNER JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = ?;
```

### Check If User Has Permission
```sql
SELECT COUNT(*) as has_permission
FROM permissions p
INNER JOIN role_permissions rp ON rp.permission_id = p.id
INNER JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = ? AND p.name = ?;
```

### Get Active Refresh Tokens for User
```sql
SELECT *
FROM refresh_tokens
WHERE user_id = ?
  AND revoked_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP;
```

## Data Integrity

### Foreign Key Constraints
All foreign key relationships use `ON DELETE CASCADE` to maintain referential integrity:

- Deleting a user deletes their roles, refresh tokens
- Deleting a role removes it from all users
- Deleting a permission removes it from all roles

### Unique Constraints
- `users.email` - Prevents duplicate user accounts
- `roles.name` - Prevents duplicate role names
- `permissions.name` - Prevents duplicate permission names
- `refresh_tokens.token` - Ensures token uniqueness

### Indexes
Indexes are strategically placed to optimize common queries:

- Email lookup (login)
- Active user filtering
- Role/permission lookups
- Token validation
- Expiration queries

## Maintenance

### Cleanup Expired Tokens
Periodically run:

```sql
DELETE FROM refresh_tokens
WHERE expires_at < CURRENT_TIMESTAMP;
```

Or use the service method:
```go
store.DeleteExpired(ctx)
```

### Audit Inactive Users
Find users who haven't logged in recently:

```sql
SELECT u.*, MAX(rt.created_at) as last_login
FROM users u
LEFT JOIN refresh_tokens rt ON rt.user_id = u.id
GROUP BY u.id
HAVING last_login < DATE_SUB(NOW(), INTERVAL 90 DAY)
   OR last_login IS NULL;
```

## Migration History

| Version | Name | Description |
|---------|------|-------------|
| 1 | create_users_table | Creates users table |
| 2 | create_roles_table | Creates roles table |
| 3 | create_permissions_table | Creates permissions table |
| 4 | create_user_roles_table | Creates user_roles junction table |
| 5 | create_role_permissions_table | Creates role_permissions junction table |
| 6 | create_refresh_tokens_table | Creates refresh_tokens table |

Migrations are applied in order and tracked in the `schema_migrations` table.
