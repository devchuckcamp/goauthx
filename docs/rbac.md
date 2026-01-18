# Role-Based Access Control (RBAC)

goauthx provides a comprehensive RBAC system with predefined roles, permissions, and administrative management capabilities.

## Overview

The RBAC system consists of:
- **Roles**: Named groups that can be assigned to users (e.g., Admin, Manager, Customer)
- **Permissions**: Specific actions on resources (e.g., `product:create`, `order:read`)
- **Role-Permission Mappings**: Relationships defining which permissions each role has
- **User-Role Assignments**: Relationships defining which roles each user has

## Predefined Roles

| Role | Constant | Description |
|------|----------|-------------|
| Admin | `goauthx.RoleAdmin` | Full access to all resources |
| Manager | `goauthx.RoleManager` | Access to products, orders, and reports |
| Customer Experience | `goauthx.RoleCustomerExperience` | Customer support access |
| Customer | `goauthx.RoleCustomer` | Regular user with limited access |

## Predefined Permissions

### Product Permissions
| Permission | Constant | Description |
|------------|----------|-------------|
| `product:create` | `goauthx.PermProductCreate` | Create new products |
| `product:read` | `goauthx.PermProductRead` | View products |
| `product:update` | `goauthx.PermProductUpdate` | Update products |
| `product:delete` | `goauthx.PermProductDelete` | Delete products |

### Order Permissions
| Permission | Constant | Description |
|------------|----------|-------------|
| `order:create` | `goauthx.PermOrderCreate` | Create new orders |
| `order:read` | `goauthx.PermOrderRead` | View orders |
| `order:update` | `goauthx.PermOrderUpdate` | Update orders |
| `order:process` | `goauthx.PermOrderProcess` | Process orders |

### User Permissions
| Permission | Constant | Description |
|------------|----------|-------------|
| `user:create` | `goauthx.PermUserCreate` | Create new users |
| `user:read` | `goauthx.PermUserRead` | View users |
| `user:update` | `goauthx.PermUserUpdate` | Update users |
| `user:delete` | `goauthx.PermUserDelete` | Delete users |
| `user:update_own` | `goauthx.PermUserUpdateOwn` | Update own profile |

### Report Permissions
| Permission | Constant | Description |
|------------|----------|-------------|
| `report:view` | `goauthx.PermReportView` | View reports |

### Customer Support Permissions
| Permission | Constant | Description |
|------------|----------|-------------|
| `customer:view` | `goauthx.PermCustomerView` | View customer information |
| `customer:order_history` | `goauthx.PermCustomerOrderHistory` | View customer order history |

## Default Role-Permission Matrix

| Permission | Admin | Manager | Customer Exp | Customer |
|------------|:-----:|:-------:|:------------:|:--------:|
| product:create | ✓ | ✓ | | |
| product:read | ✓ | ✓ | | ✓ |
| product:update | ✓ | ✓ | | |
| product:delete | ✓ | ✓ | | |
| order:create | ✓ | ✓ | | ✓ |
| order:read | ✓ | ✓ | ✓ | ✓ |
| order:update | ✓ | ✓ | | |
| order:process | ✓ | ✓ | | |
| user:create | ✓ | | | |
| user:read | ✓ | | | |
| user:update | ✓ | | | |
| user:delete | ✓ | | | |
| user:update_own | ✓ | ✓ | ✓ | ✓ |
| report:view | ✓ | ✓ | | |
| customer:view | ✓ | | ✓ | |
| customer:order_history | ✓ | | ✓ | |

## Seeding the Database

Use the `Seeder` to populate your database with predefined roles and permissions:

```go
package main

import (
    "context"
    "log"

    "github.com/devchuckcamp/goauthx"
)

func main() {
    // Create store and service...
    store, _ := goauthx.NewStore(dbConfig)

    // Create seeder
    seeder := goauthx.NewSeeder(store)

    // Seed all roles, permissions, and relationships
    if err := seeder.SeedAll(context.Background()); err != nil {
        log.Fatal(err)
    }

    // Or seed individually:
    // seeder.SeedRoles(ctx)
    // seeder.SeedPermissions(ctx)
    // seeder.SeedRolePermissions(ctx)
}
```

### Assigning Roles to Users

```go
// Assign default role (Customer) to a new user
seeder.AssignDefaultRoleToUser(ctx, userID)

// Assign a specific role
seeder.AssignRoleToUser(ctx, userID, goauthx.RoleManager)

// Remove a role
seeder.RemoveRoleFromUser(ctx, userID, goauthx.RoleManager)

// Assign default role to all users without roles
count, err := seeder.AssignDefaultRoleToUsersWithoutRoles(ctx)
```

## Protecting Routes with Middleware

### Require a Specific Role

```go
mux.Handle("/admin/dashboard",
    authMiddleware.Authenticate(
        authMiddleware.RequireRole("admin")(
            http.HandlerFunc(adminDashboardHandler),
        ),
    ),
)
```

### Require Any of Multiple Roles

```go
mux.Handle("/manager/reports",
    authMiddleware.Authenticate(
        authMiddleware.RequireAnyRole("admin", "manager")(
            http.HandlerFunc(reportsHandler),
        ),
    ),
)
```

### Require All Roles

```go
mux.Handle("/super-admin",
    authMiddleware.Authenticate(
        authMiddleware.RequireAllRoles("admin", "manager")(
            http.HandlerFunc(superAdminHandler),
        ),
    ),
)
```

### Require a Specific Permission

```go
mux.Handle("/products",
    authMiddleware.Authenticate(
        authMiddleware.RequirePermission("product:create")(
            http.HandlerFunc(createProductHandler),
        ),
    ),
)
```

### Require Any Permission

```go
mux.Handle("/products/manage",
    authMiddleware.Authenticate(
        authMiddleware.RequireAnyPermission("product:update", "product:delete")(
            http.HandlerFunc(manageProductHandler),
        ),
    ),
)
```

### Owner-or-Role Pattern

Allow access if the user is the resource owner OR has a specific role:

```go
getUserIDFromRequest := func(r *http.Request) string {
    // Extract user ID from URL, e.g., /users/{id}
    return r.URL.Query().Get("id")
}

mux.Handle("/users/",
    authMiddleware.Authenticate(
        authMiddleware.RequireOwnerOrRole(
            getUserIDFromRequest,
            "admin",
        )(http.HandlerFunc(updateUserHandler)),
    ),
)
```

### Owner-or-Permission Pattern

```go
mux.Handle("/users/",
    authMiddleware.Authenticate(
        authMiddleware.RequireOwnerOrPermission(
            getUserIDFromRequest,
            "user:update",
        )(http.HandlerFunc(updateUserHandler)),
    ),
)
```

## Checking Permissions Programmatically

```go
// Check if user has a specific role
hasRole, err := service.HasRole(ctx, userID, "admin")

// Check if user has a specific permission
hasPerm, err := service.HasPermission(ctx, userID, "product:create")

// Check if user has any of the specified permissions
hasAny, err := service.HasAnyPermission(ctx, userID, []string{"product:create", "product:update"})

// Check if user has all of the specified permissions
hasAll, err := service.HasAllPermissions(ctx, userID, []string{"product:create", "product:update"})

// Get all user roles
roles, err := service.GetUserRoles(ctx, userID)

// Get all user permissions
permissions, err := service.GetUserPermissions(ctx, userID)
```

## Admin API Endpoints

The `AdminHandlers` provides REST endpoints for managing roles, permissions, and assignments:

```go
adminHandlers := goauthx.NewAdminHandlers(service, store, nil)
adminHandlers.RegisterRoutes(mux)
```

### Role Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/roles` | List all roles |
| POST | `/admin/roles` | Create a new role |
| GET | `/admin/roles/{id}` | Get a role by ID |
| PUT | `/admin/roles/{id}` | Update a role |
| DELETE | `/admin/roles/{id}` | Delete a role |

### Permission Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/permissions` | List all permissions |
| POST | `/admin/permissions` | Create a new permission |
| GET | `/admin/permissions/{id}` | Get a permission by ID |
| PUT | `/admin/permissions/{id}` | Update a permission |
| DELETE | `/admin/permissions/{id}` | Delete a permission |

### User Role Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users/{id}/roles` | Get user's roles |
| POST | `/admin/users/{id}/roles` | Assign role to user |
| DELETE | `/admin/users/{id}/roles/{roleId}` | Remove role from user |

### Role Permission Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/roles/{id}/permissions` | Get role's permissions |
| POST | `/admin/roles/{id}/permissions` | Grant permission to role |
| DELETE | `/admin/roles/{id}/permissions/{permId}` | Revoke permission from role |

## Extending with Custom Roles and Permissions

You can define custom roles and permissions beyond the predefined ones:

```go
// Create a custom role
customRole := &goauthx.Role{
    Name:        "content_moderator",
    Description: "Can moderate user-generated content",
}
store.CreateRole(ctx, customRole)

// Create a custom permission
customPerm := &goauthx.Permission{
    Name:        "content:moderate",
    Resource:    "content",
    Action:      "moderate",
    Description: "Moderate user content",
}
store.CreatePermission(ctx, customPerm)

// Grant permission to role
store.GrantPermission(ctx, customRole.ID, customPerm.ID)
```

## Best Practices

1. **Use Constants**: Always use the type-safe constants (`goauthx.RoleAdmin`, `goauthx.PermProductCreate`) instead of string literals.

2. **Seed on Startup**: Run the seeder during application startup to ensure all roles and permissions exist.

3. **Check Permissions, Not Roles**: When possible, check for specific permissions rather than roles. This makes it easier to adjust access control without changing code.

4. **Use Middleware for Routes**: Prefer using middleware for route protection over manual checks in handlers.

5. **Assign Default Role**: Always assign the default customer role to new users during registration.

6. **Audit Changes**: Log role and permission changes for security auditing.

## Type Safety

The RBAC system uses type-safe constants to prevent typos:

```go
// Good - type-safe
if goauthx.IsValidRoleName("admin") { ... }
role := goauthx.RoleAdmin

// Less safe - string literals
if roleName == "admin" { ... }  // Could typo "Admin" or "ADMIN"
```

## Helper Functions

```go
// Check if a role name is valid
isValid := goauthx.IsValidRoleName("admin")  // true
isValid := goauthx.IsValidRoleName("invalid")  // false

// Check if a permission name is valid
isValid := goauthx.IsValidPermissionName("product:create")  // true

// Get role description
desc := goauthx.GetRoleDescription(goauthx.RoleAdmin)

// Get permission definition
def := goauthx.GetPermissionDefinition(goauthx.PermProductCreate)

// Get all role names
allRoles := goauthx.AllRoleNames()

// Get all permission names
allPerms := goauthx.AllPermissionNames()

// Get default role for new users
defaultRole := goauthx.DefaultRole()  // RoleCustomer
```
