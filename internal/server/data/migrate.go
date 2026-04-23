// Package data owns the relational layer: migrations, typed queries (via sqlc),
// and the Store abstraction that fronts both Postgres and SQLite backends.
//
// Migrations live in embedded .sql files under migrations/{postgres,sqlite}/.
// The runner uses golang-migrate; for Postgres the caller must pass a *sql.DB
// built on the pgx stdlib driver (name "pgx"). For SQLite any *sql.DB opened
// against the modernc.org/sqlite driver ("sqlite") is fine.
package data

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	// Register the pgx stdlib driver under the name "pgx" so sql.Open("pgx", ...)
	// works for the callers that open a disposable *sql.DB for migrations.
	_ "github.com/jackc/pgx/v5/stdlib"
	// Register the pure-Go SQLite driver under the name "sqlite".
	_ "modernc.org/sqlite"
)

// Dialect identifies the relational backend.
type Dialect string

const (
	DialectPostgres Dialect = "postgres"
	DialectSQLite   Dialect = "sqlite"
)

//go:embed migrations/postgres/*.sql migrations/sqlite/*.sql
var migrationFS embed.FS

// Migrate applies every pending up-migration for the given dialect against db.
// It is a no-op when every migration has already been applied. Down migrations
// are never run automatically.
func Migrate(ctx context.Context, dialect Dialect, db *sql.DB) error {
	sub, err := fs.Sub(migrationFS, "migrations/"+string(dialect))
	if err != nil {
		return fmt.Errorf("migrate: sub fs: %w", err)
	}
	source, err := iofs.New(sub, ".")
	if err != nil {
		return fmt.Errorf("migrate: source: %w", err)
	}
	defer source.Close()

	m, err := newMigrate(source, dialect, db)
	if err != nil {
		return err
	}
	// NOTE: we intentionally do NOT call m.Close(). The migrate database driver
	// wraps the caller-provided *sql.DB and closes it on Close(); but for both
	// dialects the caller wants to keep that connection alive for ongoing
	// queries. The source.Driver is already closed by the deferred call above,
	// and the *migrate.Migrate struct itself owns nothing else worth releasing.

	// Run migrations respecting the caller's cancellation.
	done := make(chan error, 1)
	go func() { done <- m.Up() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("migrate: up: %w", err)
		}
	}
	return nil
}

func newMigrate(src source.Driver, dialect Dialect, db *sql.DB) (*migrate.Migrate, error) {
	switch dialect {
	case DialectPostgres:
		drv, err := migratepgx.WithInstance(db, &migratepgx.Config{})
		if err != nil {
			return nil, fmt.Errorf("migrate: pgx driver: %w", err)
		}
		m, err := migrate.NewWithInstance("iofs", src, "pgx/v5", drv)
		if err != nil {
			return nil, fmt.Errorf("migrate: new (postgres): %w", err)
		}
		return m, nil
	case DialectSQLite:
		drv, err := migratesqlite.WithInstance(db, &migratesqlite.Config{})
		if err != nil {
			return nil, fmt.Errorf("migrate: sqlite driver: %w", err)
		}
		m, err := migrate.NewWithInstance("iofs", src, "sqlite", drv)
		if err != nil {
			return nil, fmt.Errorf("migrate: new (sqlite): %w", err)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("migrate: unknown dialect %q", dialect)
	}
}
