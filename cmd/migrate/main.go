package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"go.uber.org/zap"
)

func main() {
	// Parse command line flags
	up := flag.Bool("up", false, "Run migrations up")
	down := flag.Bool("down", false, "Run migrations down")
	steps := flag.Int("steps", 0, "Number of steps to migrate (positive for up, negative for down)")
	force := flag.String("force", "", "Force migration to specific version")
	migrationDir := flag.String("dir", "migrations/up", "Migration directory path")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Create database connection
	ctx := context.Background()
	db, err := database.NewPostgres(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		logger.Fatal("Failed to get current working directory", zap.Error(err))
	}

	// Construct database URL
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBName,
	)

	// Create migration instance
	m, err := migrate.New(
		fmt.Sprintf("file://%s/%s", cwd, *migrationDir),
		dbURL,
	)
	if err != nil {
		logger.Fatal("Failed to create migration instance", zap.Error(err))
	}
	defer m.Close()

	// Add logging for migration files
	logger.Info("Migration files found",
		zap.String("path", fmt.Sprintf("%s/%s", cwd, *migrationDir)),
		zap.String("dbURL", dbURL),
	)

	// Run migrations based on flags
	if *force != "" {
		version, err := strconv.ParseUint(*force, 10, 64)
		if err != nil {
			logger.Fatal("Invalid version number", zap.Error(err))
		}
		if version == 0 {
			// Para versão 0, primeiro tentamos dropar todas as tabelas
			if err := m.Drop(); err != nil {
				logger.Fatal("Failed to drop database schema", zap.Error(err))
			}
			logger.Info("Dropped all tables and reset migration state")
		} else {
			if err := m.Force(int(version)); err != nil {
				logger.Fatal("Failed to force migration version", zap.Error(err))
			}
			logger.Info("Forced migration version", zap.Uint64("version", version))
		}
	} else if *up {
		logger.Info("Running migrations up")
		if err := m.Up(); err != nil {
			if err == migrate.ErrNoChange {
				logger.Info("No migrations to apply")
			} else {
				logger.Fatal("Failed to run migrations up", zap.Error(err))
			}
		}
		logger.Info("Migrations up completed successfully")
	} else if *down {
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			logger.Fatal("Failed to run migrations down", zap.Error(err))
		}
		logger.Info("Migrations down completed successfully")
	} else if *steps != 0 {
		if err := m.Steps(*steps); err != nil && err != migrate.ErrNoChange {
			logger.Fatal("Failed to run migrations steps", zap.Error(err))
		}
		logger.Info("Migrations steps completed successfully", zap.Int("steps", *steps))
	} else {
		// Show current migration version
		version, dirty, err := m.Version()
		if err != nil && err != migrate.ErrNilVersion {
			logger.Fatal("Failed to get migration version", zap.Error(err))
		}
		logger.Info("Current migration version",
			zap.Uint("version", version),
			zap.Bool("dirty", dirty),
		)
	}
}
