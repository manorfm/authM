package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations runs all pending migrations
func (p *Postgres) RunMigrations(ctx context.Context) error {
	// Get the absolute path to the migrations directory
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting working directory: %w", err)
	}

	migrationsPath := filepath.Join(wd, "migrations")

	// Create the database URL for migrations
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		p.pool.Config().ConnConfig.User,
		p.pool.Config().ConnConfig.Password,
		p.pool.Config().ConnConfig.Host,
		p.pool.Config().ConnConfig.Port,
		p.pool.Config().ConnConfig.Database,
	)

	// Create a new migrate instance
	m, err := migrate.New(
		fmt.Sprintf("file://%s", migrationsPath),
		dbURL,
	)
	if err != nil {
		return fmt.Errorf("error creating migrate instance: %w", err)
	}
	defer m.Close()

	// Run migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("error running migrations: %w", err)
	}

	p.log.Info("Migrations completed successfully")
	return nil
}
