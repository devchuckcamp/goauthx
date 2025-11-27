package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/store"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
)

// SQLStore implements the Store interface for SQL databases
type SQLStore struct {
	db     *sql.DB
	tx     *sql.Tx
	driver config.DatabaseDriver
}

// New creates a new SQLStore
func New(cfg config.DatabaseConfig) (store.Store, error) {
	driverName := getDriverName(cfg.Driver)
	
	db, err := sql.Open(driverName, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	
	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	
	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	
	return &SQLStore{
		db:     db,
		driver: cfg.Driver,
	}, nil
}

func getDriverName(driver config.DatabaseDriver) string {
	switch driver {
	case config.MySQL:
		return "mysql"
	case config.Postgres:
		return "pgx"
	case config.SQLServer:
		return "sqlserver"
	default:
		return string(driver)
	}
}

// BeginTx starts a new transaction
func (s *SQLStore) BeginTx(ctx context.Context) (store.Store, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	
	return &SQLStore{
		db:     s.db,
		tx:     tx,
		driver: s.driver,
	}, nil
}

// Commit commits the current transaction
func (s *SQLStore) Commit() error {
	if s.tx == nil {
		return fmt.Errorf("no transaction to commit")
	}
	return s.tx.Commit()
}

// Rollback rolls back the current transaction
func (s *SQLStore) Rollback() error {
	if s.tx == nil {
		return fmt.Errorf("no transaction to rollback")
	}
	return s.tx.Rollback()
}

// Close closes the database connection
func (s *SQLStore) Close() error {
	return s.db.Close()
}

// DB returns the underlying database connection
func (s *SQLStore) DB() *sql.DB {
	return s.db
}

// executor returns either the transaction or the database connection
func (s *SQLStore) executor() interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
} {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

// placeholder returns the appropriate placeholder for the database driver
func (s *SQLStore) placeholder(n int) string {
	switch s.driver {
	case config.Postgres:
		return fmt.Sprintf("$%d", n)
	case config.MySQL, config.SQLServer:
		return "?"
	default:
		return "?"
	}
}
