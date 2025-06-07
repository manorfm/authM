package database

import (
	"context"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

func setupTestContainer(t *testing.T) (testcontainers.Container, *config.Config) {
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

	return container, cfg
}

func TestNewPostgres(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	container, cfg := setupTestContainer(t)
	defer container.Terminate(ctx)

	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name:    "valid configuration",
			cfg:     cfg,
			wantErr: false,
		},
		{
			name: "invalid host",
			cfg: &config.Config{
				DBHost:     "invalid-host",
				DBPort:     5432,
				DBUser:     "postgres",
				DBPassword: "postgres",
				DBName:     "user_manager_test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := NewPostgres(ctx, tt.cfg, logger)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, db)
			assert.NotNil(t, db.pool)

			// Test connection
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = db.pool.Ping(ctx)
			assert.NoError(t, err)

			// Test transaction
			tx, err := db.BeginTx(ctx)
			require.NoError(t, err)
			assert.NotNil(t, tx)
			err = tx.Rollback(ctx)
			assert.NoError(t, err)

			// Test query
			rows, err := db.Query(ctx, "SELECT 1")
			require.NoError(t, err)
			assert.NotNil(t, rows)
			rows.Close()

			// Test query row
			var result int
			err = db.QueryRow(ctx, "SELECT 1").Scan(&result)
			require.NoError(t, err)
			assert.Equal(t, 1, result)

			// Test exec
			err = db.Exec(ctx, "SELECT 1")
			require.NoError(t, err)
		})
	}
}

func TestPostgres_Close(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	container, cfg := setupTestContainer(t)
	defer container.Terminate(ctx)

	db, err := NewPostgres(ctx, cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, db)

	db.Close()

	// Test that pool is closed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = db.pool.Ping(ctx)
	assert.Error(t, err)
}
