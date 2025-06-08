package repository

import (
	"context"
	"testing"

	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

// setupTestDB creates a test database connection and runs migrations
func setupTestDB(t *testing.T) (*database.Postgres, func()) {
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
	db, err := database.NewPostgres(ctx, cfg, zap.NewNop())
	require.NoError(t, err)

	// Create tables
	err = db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS totp_secrets (
			user_id VARCHAR(26) PRIMARY KEY,
			secret VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS totp_backup_codes (
			user_id VARCHAR(26) PRIMARY KEY,
			codes JSONB NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	// Clean up tables before each test
	err = db.Exec(ctx, `
		TRUNCATE TABLE totp_secrets, totp_backup_codes CASCADE;
	`)
	require.NoError(t, err)

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, cleanup
}

func TestTOTPRepository_SaveTOTPSecret(t *testing.T) {
	// Setup
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewTOTPRepository(db, zap.NewNop())
	ctx := context.Background()

	// Test cases
	tests := []struct {
		name      string
		userID    string
		secret    string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    "user1",
			secret:    "JBSWY3DPEHPK3PXP",
			wantError: false,
		},
		{
			name:      "Empty Secret",
			userID:    "user2",
			secret:    "",
			wantError: true,
		},
		{
			name:      "Update Existing",
			userID:    "user1",
			secret:    "NEWSECRET123",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.SaveTOTPSecret(ctx, tt.userID, tt.secret)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the secret was saved
				savedSecret, err := repo.GetTOTPSecret(ctx, tt.userID)
				assert.NoError(t, err)
				assert.Equal(t, tt.secret, savedSecret)
			}
		})
	}
}

func TestTOTPRepository_GetTOTPSecret(t *testing.T) {
	// Setup
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewTOTPRepository(db, zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	secret := "JBSWY3DPEHPK3PXP"
	err := repo.SaveTOTPSecret(ctx, userID, secret)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		want      string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			want:      secret,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			want:      "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			got, err := repo.GetTOTPSecret(ctx, tt.userID)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
				assert.Empty(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTOTPRepository_SaveBackupCodes(t *testing.T) {
	// Setup
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewTOTPRepository(db, zap.NewNop())
	ctx := context.Background()

	// Test cases
	tests := []struct {
		name      string
		userID    string
		codes     []string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    "user1",
			codes:     []string{"ABCDEF1234", "GHIJKL5678"},
			wantError: false,
		},
		{
			name:      "Empty Codes",
			userID:    "user2",
			codes:     []string{},
			wantError: true,
		},
		{
			name:      "Update Existing",
			userID:    "user1",
			codes:     []string{"NEWCODE1234", "NEWCODE5678"},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.SaveBackupCodes(ctx, tt.userID, tt.codes)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the codes were saved
				savedCodes, err := repo.GetBackupCodes(ctx, tt.userID)
				assert.NoError(t, err)
				assert.Equal(t, tt.codes, savedCodes)
			}
		})
	}
}

func TestTOTPRepository_GetBackupCodes(t *testing.T) {
	// Setup
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewTOTPRepository(db, zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	codes := []string{"ABCDEF1234", "GHIJKL5678"}
	err := repo.SaveBackupCodes(ctx, userID, codes)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		want      []string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			want:      codes,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			want:      nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			got, err := repo.GetBackupCodes(ctx, tt.userID)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTOTPRepository_MarkBackupCodeAsUsed(t *testing.T) {
	// Setup
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewTOTPRepository(db, zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	codes := []string{"ABCDEF1234", "GHIJKL5678"}
	err := repo.SaveBackupCodes(ctx, userID, codes)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		codeIndex int
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			codeIndex: 0,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			codeIndex: 0,
			wantError: true,
		},
		{
			name:      "Invalid Code Index",
			userID:    userID,
			codeIndex: 2,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.MarkBackupCodeAsUsed(ctx, tt.userID, tt.codeIndex)

			// Assert
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the code was marked as used
				savedCodes, err := repo.GetBackupCodes(ctx, tt.userID)
				assert.NoError(t, err)
				assert.Equal(t, "", savedCodes[tt.codeIndex]) // Code should be empty string
			}
		})
	}
}

func TestTOTPRepository_DeleteTOTPConfig(t *testing.T) {
	// Setup
	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewTOTPRepository(db, zap.NewNop())
	ctx := context.Background()

	// Insert test data
	userID := "user1"
	secret := "JBSWY3DPEHPK3PXP"
	err := repo.SaveTOTPSecret(ctx, userID, secret)
	require.NoError(t, err)

	codes := []string{"ABCDEF1234", "GHIJKL5678"}
	err = repo.SaveBackupCodes(ctx, userID, codes)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		userID    string
		wantError bool
	}{
		{
			name:      "Success",
			userID:    userID,
			wantError: false,
		},
		{
			name:      "User Not Found",
			userID:    "nonexistent",
			wantError: false, // No error when deleting non-existent config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := repo.DeleteTOTPConfig(ctx, tt.userID)

			// Assert
			assert.NoError(t, err)

			// Verify the config was deleted
			secret, err := repo.GetTOTPSecret(ctx, tt.userID)
			assert.Error(t, err)
			assert.Empty(t, secret)

			codes, err := repo.GetBackupCodes(ctx, tt.userID)
			assert.Error(t, err)
			assert.Nil(t, codes)
		})
	}
}

func contains(slice []string, item string) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}
