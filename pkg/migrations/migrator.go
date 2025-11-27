package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/config"
)

// Migration represents a database migration
type Migration struct {
	Version     int
	Name        string
	UpSQL       string
	DownSQL     string
	AppliedAt   *time.Time
}

// Migrator handles database migrations
type Migrator struct {
	db     *sql.DB
	driver config.DatabaseDriver
}

// NewMigrator creates a new migrator
func NewMigrator(db *sql.DB, driver config.DatabaseDriver) *Migrator {
	return &Migrator{
		db:     db,
		driver: driver,
	}
}

// Up runs all pending migrations
func (m *Migrator) Up(ctx context.Context) error {
	// Ensure migrations table exists
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table: %w", err)
	}
	
	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}
	
	// Get all migrations
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}
	
	// Filter pending migrations
	pending := make([]*Migration, 0)
	for _, migration := range migrations {
		if !contains(applied, migration.Version) {
			pending = append(pending, migration)
		}
	}
	
	if len(pending) == 0 {
		fmt.Println("No pending migrations")
		return nil
	}
	
	// Apply pending migrations
	for _, migration := range pending {
		fmt.Printf("Applying migration %d: %s\n", migration.Version, migration.Name)
		if err := m.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
		fmt.Printf("Migration %d applied successfully\n", migration.Version)
	}
	
	return nil
}

// Down rolls back the last migration
func (m *Migrator) Down(ctx context.Context) error {
	// Ensure migrations table exists
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table: %w", err)
	}
	
	// Get last applied migration
	lastVersion, err := m.getLastAppliedMigration(ctx)
	if err != nil {
		return fmt.Errorf("failed to get last applied migration: %w", err)
	}
	
	if lastVersion == 0 {
		fmt.Println("No migrations to roll back")
		return nil
	}
	
	// Load migrations
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}
	
	// Find the migration to roll back
	var migration *Migration
	for _, m := range migrations {
		if m.Version == lastVersion {
			migration = m
			break
		}
	}
	
	if migration == nil {
		return fmt.Errorf("migration %d not found", lastVersion)
	}
	
	fmt.Printf("Rolling back migration %d: %s\n", migration.Version, migration.Name)
	if err := m.rollbackMigration(ctx, migration); err != nil {
		return fmt.Errorf("failed to rollback migration %d: %w", migration.Version, err)
	}
	fmt.Printf("Migration %d rolled back successfully\n", migration.Version)
	
	return nil
}

// Status shows the status of all migrations
func (m *Migrator) Status(ctx context.Context) error {
	// Ensure migrations table exists
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table: %w", err)
	}
	
	// Get applied migrations
	applied, err := m.getAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}
	
	// Load migrations
	migrations, err := m.loadMigrations()
	if err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}
	
	fmt.Println("Migration Status:")
	fmt.Println("================")
	for _, migration := range migrations {
		status := "pending"
		if contains(applied, migration.Version) {
			status = "applied"
		}
		fmt.Printf("[%s] %d: %s\n", status, migration.Version, migration.Name)
	}
	
	return nil
}

func (m *Migrator) ensureMigrationsTable(ctx context.Context) error {
	var createSQL string
	
	switch m.driver {
	case config.MySQL:
		createSQL = `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version INT PRIMARY KEY,
				name VARCHAR(255) NOT NULL,
				applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
		`
	case config.Postgres:
		createSQL = `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version INT PRIMARY KEY,
				name VARCHAR(255) NOT NULL,
				applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
		`
	case config.SQLServer:
		createSQL = `
			IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='schema_migrations' AND xtype='U')
			CREATE TABLE schema_migrations (
				version INT PRIMARY KEY,
				name NVARCHAR(255) NOT NULL,
				applied_at DATETIME DEFAULT GETDATE()
			)
		`
	default:
		return fmt.Errorf("unsupported database driver: %s", m.driver)
	}
	
	_, err := m.db.ExecContext(ctx, createSQL)
	return err
}

func (m *Migrator) getAppliedMigrations(ctx context.Context) ([]int, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	
	return versions, rows.Err()
}

func (m *Migrator) getLastAppliedMigration(ctx context.Context) (int, error) {
	var version int
	err := m.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	return version, err
}

func (m *Migrator) applyMigration(ctx context.Context, migration *Migration) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	
	// Execute up SQL
	if _, err := tx.ExecContext(ctx, migration.UpSQL); err != nil {
		return err
	}
	
	// Record migration
	placeholder := "?"
	if m.driver == config.Postgres {
		placeholder = "$1, $2"
	}
	
	query := fmt.Sprintf("INSERT INTO schema_migrations (version, name) VALUES (%s)", placeholder)
	if m.driver == config.Postgres {
		query = "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)"
	}
	
	if _, err := tx.ExecContext(ctx, query, migration.Version, migration.Name); err != nil {
		return err
	}
	
	return tx.Commit()
}

func (m *Migrator) rollbackMigration(ctx context.Context, migration *Migration) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	
	// Execute down SQL
	if _, err := tx.ExecContext(ctx, migration.DownSQL); err != nil {
		return err
	}
	
	// Remove migration record
	placeholder := "?"
	if m.driver == config.Postgres {
		placeholder = "$1"
	}
	
	query := fmt.Sprintf("DELETE FROM schema_migrations WHERE version = %s", placeholder)
	if _, err := tx.ExecContext(ctx, query, migration.Version); err != nil {
		return err
	}
	
	return tx.Commit()
}

func (m *Migrator) loadMigrations() ([]*Migration, error) {
	// Define migrations inline
	migrations := []*Migration{
		{
			Version: 1,
			Name:    "create_users_table",
			UpSQL:   getCreateUsersTableSQL(m.driver),
			DownSQL: "DROP TABLE IF EXISTS users",
		},
		{
			Version: 2,
			Name:    "create_roles_table",
			UpSQL:   getCreateRolesTableSQL(m.driver),
			DownSQL: "DROP TABLE IF EXISTS roles",
		},
		{
			Version: 3,
			Name:    "create_permissions_table",
			UpSQL:   getCreatePermissionsTableSQL(m.driver),
			DownSQL: "DROP TABLE IF EXISTS permissions",
		},
		{
			Version: 4,
			Name:    "create_user_roles_table",
			UpSQL:   getCreateUserRolesTableSQL(m.driver),
			DownSQL: "DROP TABLE IF EXISTS user_roles",
		},
		{
			Version: 5,
			Name:    "create_role_permissions_table",
			UpSQL:   getCreateRolePermissionsTableSQL(m.driver),
			DownSQL: "DROP TABLE IF EXISTS role_permissions",
		},
		{
			Version: 6,
			Name:    "create_refresh_tokens_table",
			UpSQL:   getCreateRefreshTokensTableSQL(m.driver),
			DownSQL: "DROP TABLE IF EXISTS refresh_tokens",
		},
		{
			Version: 7,
			Name:    "create_email_verifications_table",
			UpSQL:   getCreateEmailVerificationsTableSQL(m.driver),
			DownSQL: getDropEmailVerificationsTableSQL(m.driver),
		},
		{
			Version: 8,
			Name:    "create_password_resets_table",
			UpSQL:   getCreatePasswordResetsTableSQL(m.driver),
			DownSQL: getDropPasswordResetsTableSQL(m.driver),
		},
		{
			Version: 9,
			Name:    "add_email_verified_column",
			UpSQL:   getAddEmailVerifiedColumnSQL(m.driver),
			DownSQL: getDropEmailVerifiedColumnSQL(m.driver),
		},
		{
			Version: 10,
			Name:    "create_oauth_accounts_table",
			UpSQL:   getCreateOAuthAccountsTableSQL(m.driver),
			DownSQL: getDropOAuthAccountsTableSQL(m.driver),
		},
	}
	
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	
	return migrations, nil
}

func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}
