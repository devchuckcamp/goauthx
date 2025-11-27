# Migration System

## Overview

The goauthx migration system provides a robust way to manage database schema changes across multiple database platforms (MySQL, PostgreSQL, SQL Server).

## Components

### 1. Migration Tool (`cmd/goauthx-migrate`)
A CLI tool for running migrations from the command line.

### 2. Migrator (`pkg/migrations/migrator.go`)
The core migration engine that handles:
- Migration version tracking
- Applying migrations (up)
- Rolling back migrations (down)
- Status reporting

### 3. Migration Definitions (`pkg/migrations/tables.go`)
SQL schemas for each supported database dialect.

## CLI Usage

### Building the Tool

```bash
cd cmd/goauthx-migrate
go build -o goauthx-migrate
```

Or build for distribution:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o goauthx-migrate-linux

# Windows
GOOS=windows GOARCH=amd64 go build -o goauthx-migrate.exe

# macOS
GOOS=darwin GOARCH=amd64 go build -o goauthx-migrate-darwin
```

### Commands

#### Apply Migrations (Up)

Applies all pending migrations.

```bash
# PostgreSQL
./goauthx-migrate --dsn "postgres://user:pass@localhost/db?sslmode=disable" \
                  --driver postgres \
                  up

# MySQL
./goauthx-migrate --dsn "user:pass@tcp(localhost:3306)/db?parseTime=true" \
                  --driver mysql \
                  up

# SQL Server
./goauthx-migrate --dsn "sqlserver://user:pass@localhost:1433?database=db" \
                  --driver sqlserver \
                  up
```

**Output:**
```
Applying migration 1: create_users_table
Migration 1 applied successfully
Applying migration 2: create_roles_table
Migration 2 applied successfully
...
Migrations completed successfully
```

#### Rollback Migration (Down)

Rolls back the most recently applied migration.

```bash
./goauthx-migrate --dsn "..." --driver postgres down
```

**Output:**
```
Rolling back migration 6: create_refresh_tokens_table
Migration 6 rolled back successfully
Rollback completed successfully
```

#### Check Status

Shows which migrations have been applied.

```bash
./goauthx-migrate --dsn "..." --driver postgres status
```

**Output:**
```
Migration Status:
================
[applied]  1: create_users_table
[applied]  2: create_roles_table
[applied]  3: create_permissions_table
[applied]  4: create_user_roles_table
[applied]  5: create_role_permissions_table
[pending]  6: create_refresh_tokens_table
```

#### Version

Show the tool version:

```bash
./goauthx-migrate --version
```

#### Help

Show usage information:

```bash
./goauthx-migrate --help
```

## Programmatic Usage

You can also run migrations directly from your Go code:

```go
package main

import (
	"context"
	"database/sql"
	"log"

	"github.com/devchuckcamp/goauthx"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	// Open database connection
	db, err := sql.Open("pgx", "postgres://user:pass@localhost/db?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create migrator
	migrator := goauthx.NewMigrator(
		&goauthx.DatabaseStore{DB: db},
		goauthx.Postgres,
	)

	// Run migrations
	ctx := context.Background()
	if err := migrator.Up(ctx); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	log.Println("Migrations completed successfully")
}
```

Or use it with the store:

```go
cfg := goauthx.DefaultConfig()
cfg.Database.Driver = goauthx.Postgres
cfg.Database.DSN = "postgres://..."

store, err := goauthx.NewStore(cfg.Database)
if err != nil {
	log.Fatal(err)
}

migrator := goauthx.NewMigrator(store, cfg.Database.Driver)
if err := migrator.Up(context.Background()); err != nil {
	log.Fatal(err)
}
```

## Migration Architecture

### How It Works

1. **Initialization**
   - The migrator ensures a `schema_migrations` table exists
   - This table tracks which migrations have been applied

2. **Migration Discovery**
   - Migrations are defined in code (not as files)
   - Each migration has a version number, name, and SQL

3. **Version Tracking**
   - Applied migrations are recorded in `schema_migrations`
   - Only pending migrations are applied

4. **Transaction Safety**
   - Each migration runs in a transaction
   - If a migration fails, it's rolled back automatically
   - The `schema_migrations` table is only updated on success

5. **Dialect Support**
   - Migration SQL is generated based on the database driver
   - Supports dialect-specific features (AUTO_INCREMENT, SERIAL, etc.)

### Migration Table

The `schema_migrations` table structure:

| Column | Type | Description |
|--------|------|-------------|
| version | INT | Migration version (primary key) |
| name | VARCHAR(255) | Migration name |
| applied_at | TIMESTAMP | When the migration was applied |

**Example data:**
```
version | name                        | applied_at
--------|-----------------------------|--------------------------
1       | create_users_table          | 2024-01-15 10:30:00
2       | create_roles_table          | 2024-01-15 10:30:01
3       | create_permissions_table    | 2024-01-15 10:30:02
```

## Migrations List

### Migration 1: Create Users Table
Creates the `users` table for storing user accounts.

**Tables:** users

### Migration 2: Create Roles Table
Creates the `roles` table for storing role definitions.

**Tables:** roles

### Migration 3: Create Permissions Table
Creates the `permissions` table for storing permission definitions.

**Tables:** permissions

### Migration 4: Create User Roles Table
Creates the `user_roles` junction table for user-role relationships.

**Tables:** user_roles
**Dependencies:** users, roles

### Migration 5: Create Role Permissions Table
Creates the `role_permissions` junction table for role-permission relationships.

**Tables:** role_permissions
**Dependencies:** roles, permissions

### Migration 6: Create Refresh Tokens Table
Creates the `refresh_tokens` table for session management.

**Tables:** refresh_tokens
**Dependencies:** users

## Connection Strings

### PostgreSQL

**Format:**
```
postgres://username:password@host:port/database?options
```

**Examples:**
```bash
# Local development
postgres://postgres:postgres@localhost:5432/authdb?sslmode=disable

# With SSL
postgres://user:pass@db.example.com:5432/prod?sslmode=require

# Unix socket
postgres://user:pass@/dbname?host=/var/run/postgresql
```

**Common Options:**
- `sslmode`: `disable`, `require`, `verify-ca`, `verify-full`
- `connect_timeout`: Connection timeout in seconds
- `application_name`: Name shown in pg_stat_activity

### MySQL

**Format:**
```
username:password@tcp(host:port)/database?options
```

**Examples:**
```bash
# Local development
root:password@tcp(localhost:3306)/authdb?parseTime=true

# With charset
user:pass@tcp(db.example.com:3306)/prod?parseTime=true&charset=utf8mb4

# Unix socket
user:pass@unix(/var/run/mysqld/mysqld.sock)/dbname?parseTime=true
```

**Important Options:**
- `parseTime=true`: **Required** - Parses DATE and DATETIME to time.Time
- `charset=utf8mb4`: Use UTF-8 encoding
- `loc=Local`: Timezone for TIMESTAMP values

### SQL Server

**Format:**
```
sqlserver://username:password@host:port?database=dbname&options
```

**Examples:**
```bash
# Local development (Windows Authentication)
sqlserver://localhost:1433?database=authdb&trusted_connection=yes

# SQL Authentication
sqlserver://sa:YourPassword@localhost:1433?database=authdb

# Azure SQL Database
sqlserver://user@server:pass@server.database.windows.net:1433?database=db&encrypt=true
```

**Common Options:**
- `database`: Database name
- `encrypt`: Enable/disable encryption (`true`, `false`, `disable`)
- `TrustServerCertificate`: Skip certificate validation
- `connection timeout`: Connection timeout in seconds

## Best Practices

### 1. Always Backup Before Migration

```bash
# PostgreSQL
pg_dump -U user -d authdb -f backup.sql

# MySQL
mysqldump -u user -p authdb > backup.sql

# SQL Server
sqlcmd -S localhost -Q "BACKUP DATABASE authdb TO DISK='backup.bak'"
```

### 2. Test Migrations in Development First

Never run migrations directly on production without testing:

```bash
# 1. Test on local database
./goauthx-migrate --dsn "postgres://localhost/authdb_test" --driver postgres up

# 2. Verify the results
./goauthx-migrate --dsn "postgres://localhost/authdb_test" --driver postgres status

# 3. Test rollback
./goauthx-migrate --dsn "postgres://localhost/authdb_test" --driver postgres down

# 4. Re-apply
./goauthx-migrate --dsn "postgres://localhost/authdb_test" --driver postgres up
```

### 3. Use Environment Variables for Credentials

```bash
export DB_DSN="postgres://user:pass@localhost/db?sslmode=disable"
export DB_DRIVER="postgres"

./goauthx-migrate --dsn "$DB_DSN" --driver "$DB_DRIVER" up
```

### 4. Automate in CI/CD

**Example GitHub Actions:**
```yaml
- name: Run Migrations
  run: |
    ./goauthx-migrate \
      --dsn "${{ secrets.DATABASE_URL }}" \
      --driver postgres \
      up
```

**Example Docker Compose:**
```yaml
services:
  migrate:
    image: your-app-with-migrate
    command: >
      goauthx-migrate
      --dsn "postgres://user:pass@db:5432/authdb?sslmode=disable"
      --driver postgres
      up
    depends_on:
      - db
```

### 5. Monitor Migration Progress

For long-running migrations, check the database:

```sql
-- PostgreSQL
SELECT * FROM pg_stat_activity WHERE datname = 'authdb';

-- MySQL
SHOW PROCESSLIST;

-- SQL Server
SELECT * FROM sys.dm_exec_requests;
```

## Troubleshooting

### Migration Fails Midway

**Problem:** A migration fails after partially executing.

**Solution:**
1. Check the `schema_migrations` table
2. If the failed migration was recorded, manually remove it:
   ```sql
   DELETE FROM schema_migrations WHERE version = X;
   ```
3. Manually fix any partial changes
4. Re-run the migration

### Connection Timeout

**Problem:** `failed to connect to database: context deadline exceeded`

**Solution:**
- Verify database is running
- Check firewall rules
- Verify connection string
- Increase connection timeout

### Permission Denied

**Problem:** `failed to create table: permission denied`

**Solution:**
- Verify database user has CREATE TABLE privileges
- Grant necessary permissions:
  ```sql
  -- PostgreSQL
  GRANT CREATE ON DATABASE authdb TO user;
  
  -- MySQL
  GRANT CREATE ON authdb.* TO 'user'@'%';
  
  -- SQL Server
  ALTER ROLE db_ddladmin ADD MEMBER [user];
  ```

### Migration Already Applied

**Problem:** Migration appears applied but tables don't exist.

**Solution:**
Check `schema_migrations` table and compare with actual tables:
```sql
SELECT * FROM schema_migrations ORDER BY version;
SHOW TABLES;  -- MySQL
\dt          -- PostgreSQL
SELECT name FROM sys.tables;  -- SQL Server
```

## Extending the Migration System

### Adding New Migrations

To add a new migration, edit `pkg/migrations/migrator.go`:

```go
func (m *Migrator) loadMigrations() ([]*Migration, error) {
	migrations := []*Migration{
		// ... existing migrations ...
		{
			Version: 7,
			Name:    "add_user_profile_table",
			UpSQL:   getCreateUserProfileTableSQL(m.driver),
			DownSQL: "DROP TABLE IF EXISTS user_profiles",
		},
	}
	// ...
}
```

Then add the SQL generator in `pkg/migrations/tables.go`:

```go
func getCreateUserProfileTableSQL(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return `CREATE TABLE user_profiles (...) ENGINE=InnoDB;`
	case config.Postgres:
		return `CREATE TABLE user_profiles (...);`
	case config.SQLServer:
		return `CREATE TABLE user_profiles (...);`
	}
}
```

### Using External Migration Files

For more complex setups, you might want to load migrations from files. Modify `loadMigrations()` to read from disk:

```go
func (m *Migrator) loadMigrations() ([]*Migration, error) {
	// Read .sql files from migrations directory
	// Parse version from filename
	// Return migrations sorted by version
}
```

## Future Enhancements

Potential improvements to the migration system:

1. **Checksums**: Verify migration integrity
2. **Dry Run**: Preview changes without applying
3. **Parallel Execution**: Apply independent migrations concurrently
4. **Seed Data**: Initial data loading
5. **Migration Templates**: Generate migration boilerplate
