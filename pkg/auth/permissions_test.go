package auth

import (
	"context"
	"testing"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/models"
)

func TestServiceHasPermission_IncludesDirectUserPermissions(t *testing.T) {
	ctx := context.Background()

	cfg := config.DefaultConfig()
	cfg.Database.Driver = config.MySQL
	cfg.Database.DSN = "test"
	cfg.JWT.Secret = "0123456789abcdef0123456789abcdef" // 32 chars
	cfg.JWT.AccessTokenExpiry = 15 * time.Minute

	store := NewMockStore()

	user := &models.User{ID: "user-1", Email: "u@example.com", Active: true}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	perm := &models.Permission{ID: "perm-1", Name: "report:view", Resource: "report", Action: "view"}
	if err := store.CreatePermission(ctx, perm); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}

	if err := store.GrantUserPermission(ctx, user.ID, perm.ID); err != nil {
		t.Fatalf("GrantUserPermission: %v", err)
	}

	svc, err := NewService(cfg, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	has, err := svc.HasPermission(ctx, user.ID, perm.Name)
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	if !has {
		t.Fatalf("expected HasPermission=true for direct permission")
	}
}

func TestServiceGetUserPermissions_IncludesRoleAndDirectPermissions(t *testing.T) {
	ctx := context.Background()

	cfg := config.DefaultConfig()
	cfg.Database.Driver = config.MySQL
	cfg.Database.DSN = "test"
	cfg.JWT.Secret = "0123456789abcdef0123456789abcdef" // 32 chars
	cfg.JWT.AccessTokenExpiry = 15 * time.Minute

	store := NewMockStore()

	user := &models.User{ID: "user-1", Email: "u@example.com", Active: true}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	role := &models.Role{ID: "role-1", Name: "manager"}
	if err := store.CreateRole(ctx, role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := store.AssignRole(ctx, user.ID, role.ID); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	rolePerm := &models.Permission{ID: "perm-role", Name: "product:read", Resource: "product", Action: "read"}
	directPerm := &models.Permission{ID: "perm-direct", Name: "report:view", Resource: "report", Action: "view"}
	if err := store.CreatePermission(ctx, rolePerm); err != nil {
		t.Fatalf("CreatePermission(role): %v", err)
	}
	if err := store.CreatePermission(ctx, directPerm); err != nil {
		t.Fatalf("CreatePermission(direct): %v", err)
	}
	if err := store.GrantPermission(ctx, role.ID, rolePerm.ID); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	if err := store.GrantUserPermission(ctx, user.ID, directPerm.ID); err != nil {
		t.Fatalf("GrantUserPermission: %v", err)
	}

	svc, err := NewService(cfg, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	perms, err := svc.GetUserPermissions(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}

	got := map[string]bool{}
	for _, p := range perms {
		got[p.Name] = true
	}

	if !got[rolePerm.Name] {
		t.Fatalf("expected role permission %q present", rolePerm.Name)
	}
	if !got[directPerm.Name] {
		t.Fatalf("expected direct permission %q present", directPerm.Name)
	}
}
