package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/devchuckcamp/goauthx/pkg/config"
	"github.com/devchuckcamp/goauthx/pkg/migrations"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
)

const version = "1.0.0"

func main() {
	var (
		dsn        = flag.String("dsn", "", "Database connection string (required)")
		driver     = flag.String("driver", "", "Database driver: mysql, postgres, or sqlserver (required)")
		showHelp   = flag.Bool("help", false, "Show help message")
		showVersion = flag.Bool("version", false, "Show version")
	)
	
	flag.Usage = usage
	flag.Parse()
	
	if *showVersion {
		fmt.Printf("goauthx-migrate version %s\n", version)
		os.Exit(0)
	}
	
	if *showHelp {
		usage()
		os.Exit(0)
	}
	
	if *dsn == "" || *driver == "" {
		fmt.Fprintln(os.Stderr, "Error: --dsn and --driver are required")
		usage()
		os.Exit(1)
	}
	
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: command is required (up, down, or status)")
		usage()
		os.Exit(1)
	}
	
	command := args[0]
	
	// Validate driver
	var dbDriver config.DatabaseDriver
	switch *driver {
	case "mysql":
		dbDriver = config.MySQL
	case "postgres":
		dbDriver = config.Postgres
	case "sqlserver":
		dbDriver = config.SQLServer
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid driver '%s'. Must be mysql, postgres, or sqlserver\n", *driver)
		os.Exit(1)
	}
	
	// Connect to database
	driverName := getDriverName(dbDriver)
	db, err := sql.Open(driverName, *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	
	// Create migrator
	migrator := migrations.NewMigrator(db, dbDriver)
	
	// Execute command
	switch command {
	case "up":
		if err := migrator.Up(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error: migration failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Migrations completed successfully")
		
	case "down":
		if err := migrator.Down(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error: rollback failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Rollback completed successfully")
		
	case "status":
		if err := migrator.Status(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get status: %v\n", err)
			os.Exit(1)
		}
		
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", command)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `goauthx-migrate - Database migration tool for goauthx

Usage:
  goauthx-migrate [options] <command>

Commands:
  up        Apply all pending migrations
  down      Rollback the last migration
  status    Show the status of all migrations

Options:
  --dsn string      Database connection string (required)
  --driver string   Database driver: mysql, postgres, or sqlserver (required)
  --help            Show this help message
  --version         Show version information

Examples:
  # Apply all migrations to a PostgreSQL database
  goauthx-migrate --dsn "postgres://user:pass@localhost/dbname?sslmode=disable" --driver postgres up

  # Apply all migrations to a MySQL database
  goauthx-migrate --dsn "user:pass@tcp(localhost:3306)/dbname?parseTime=true" --driver mysql up

  # Apply all migrations to a SQL Server database
  goauthx-migrate --dsn "sqlserver://user:pass@localhost:1433?database=dbname" --driver sqlserver up

  # Roll back the last migration
  goauthx-migrate --dsn "..." --driver postgres down

  # Check migration status
  goauthx-migrate --dsn "..." --driver postgres status

Connection String Formats:
  MySQL:      user:password@tcp(host:port)/database?parseTime=true
  PostgreSQL: postgres://user:password@host:port/database?sslmode=disable
  SQL Server: sqlserver://user:password@host:port?database=dbname

`)
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
