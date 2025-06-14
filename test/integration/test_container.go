package integration

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/manorfm/authM/internal/infrastructure/config"
	"github.com/manorfm/authM/internal/infrastructure/database"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

// setupTestContainerWithMigrations creates a new PostgreSQL container for testing and runs all migrations
func setupTestContainerWithMigrations(t *testing.T) (testcontainers.Container, *config.Config) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:15-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "test",
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections"),
			wait.ForListeningPort("5432/tcp"),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	cfg := &config.Config{
		DBHost:     host,
		DBPort:     port.Int(),
		DBUser:     "test",
		DBPassword: "test",
		DBName:     "test",
	}

	// Setup database and run migrations
	var db *database.Postgres
	for i := 0; i < 10; i++ {
		db, err = database.NewPostgres(ctx, cfg, zap.NewNop())
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	require.NoError(t, err)

	// Read and execute migrations
	migrationsDir := "../../migrations/up"
	entries, err := os.ReadDir(migrationsDir)
	require.NoError(t, err)

	// Sort files to ensure migrations run in order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	t.Logf("Running migrations in order:")
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			if entry.Name() == "000001_create_database.up.sql" {
				continue
			}
			t.Logf("- %s", entry.Name())
			content, err := os.ReadFile(filepath.Join(migrationsDir, entry.Name()))
			require.NoError(t, err)

			err = db.Exec(ctx, string(content))
			require.NoError(t, err)
		}
	}

	// Close the database connection after migrations
	db.Close()

	return container, cfg
}
