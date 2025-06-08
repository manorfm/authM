package integration

import (
	"context"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/ipede/user-manager-service/internal/infrastructure/repository"
	"github.com/ipede/user-manager-service/internal/infrastructure/totp"
	"github.com/oklog/ulid/v2"
	extotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTOTPService_Integration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Setup test container with migrations
	container, cfg := setupTestContainerWithMigrations(t)
	defer container.Terminate(ctx)

	// Setup database
	db, err := database.NewPostgres(ctx, cfg, logger)
	require.NoError(t, err)
	defer db.Close()

	// Setup repositories
	userRepo := repository.NewUserRepository(db, logger)
	totpRepo := repository.NewTOTPRepository(db, logger)

	// Setup TOTP service with real generator
	totpGenerator := totp.NewGenerator(logger)
	totpService := application.NewTOTPService(totpRepo, totpGenerator, logger)

	t.Run("Enable and Verify TOTP", func(t *testing.T) {
		// Create a test user
		user := &domain.User{
			ID:            ulid.Make(),
			Name:          "Test User",
			Email:         "test@example.com",
			Password:      "password123",
			Phone:         "1234567890",
			Roles:         []string{"user"},
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		t.Logf("Creating user with ID: %s", user.ID.String())
		err := userRepo.Create(ctx, user)
		if err != nil {
			t.Logf("userRepo.Create error: %+v", err)
			t.FailNow()
		}
		require.NoError(t, err)

		// Ensure user exists in DB
		fetched, err := userRepo.FindByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("user should exist in DB before enabling TOTP: %v", err)
		}
		require.Equal(t, user.ID, fetched.ID)

		t.Logf("Enabling TOTP for user ID: %s", user.ID.String())
		// Enable TOTP
		config, backupCodes, err := totpService.EnableTOTP(user.ID.String())
		if err != nil {
			t.Logf("EnableTOTP error: %+v", err)
		}
		require.NoError(t, err)
		assert.NotNil(t, config)
		assert.NotEmpty(t, backupCodes)
		assert.Len(t, backupCodes, 10)

		// Generate a valid TOTP code
		code, err := extotp.GenerateCode(config.Secret, time.Now())
		require.NoError(t, err)
		assert.NotEmpty(t, code)

		// Verify TOTP code
		err = totpService.VerifyTOTP(user.ID.String(), code)
		require.NoError(t, err)

		// Verify backup code
		err = totpService.VerifyBackupCode(user.ID.String(), backupCodes[0])
		require.NoError(t, err)

		// Disable TOTP
		err = totpService.DisableTOTP(user.ID.String())
		require.NoError(t, err)

		// Verify TOTP is disabled
		err = totpService.VerifyTOTP(user.ID.String(), code)
		assert.ErrorIs(t, err, domain.ErrTOTPNotEnabled)
	})

	t.Run("Invalid TOTP Operations", func(t *testing.T) {
		// Try to enable TOTP for non-existent user
		_, _, err := totpService.EnableTOTP("non-existent")
		assert.ErrorIs(t, err, domain.ErrDatabaseQuery)

		// Try to verify TOTP for non-existent user
		err = totpService.VerifyTOTP("non-existent", "123456")
		assert.ErrorIs(t, err, domain.ErrTOTPNotEnabled)

		// Try to verify backup code for non-existent user
		err = totpService.VerifyBackupCode("non-existent", "backup-code")
		assert.ErrorIs(t, err, domain.ErrTOTPNotEnabled)
	})

	t.Run("Invalid TOTP Codes", func(t *testing.T) {
		// Create a test user
		user := &domain.User{
			ID:            ulid.Make(),
			Name:          "Test User Invalid",
			Email:         "test-invalid@example.com",
			Password:      "password123",
			Phone:         "1234567890",
			Roles:         []string{"user"},
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		err := userRepo.Create(ctx, user)
		require.NoError(t, err)

		// Enable TOTP
		_, backupCodes, err := totpService.EnableTOTP(user.ID.String())
		require.NoError(t, err)

		// Try invalid TOTP code
		err = totpService.VerifyTOTP(user.ID.String(), "000000")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)

		// Try invalid backup code
		err = totpService.VerifyBackupCode(user.ID.String(), "invalid-backup-code")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPBackupCode)

		// Try reusing a backup code
		err = totpService.VerifyBackupCode(user.ID.String(), backupCodes[0])
		require.NoError(t, err)
		err = totpService.VerifyBackupCode(user.ID.String(), backupCodes[0])
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPBackupCode)
	})

	t.Run("Re-enable TOTP", func(t *testing.T) {
		// Create a test user
		user := &domain.User{
			ID:            ulid.Make(),
			Name:          "Test User Re-enable",
			Email:         "test-reenable@example.com",
			Password:      "password123",
			Phone:         "1234567890",
			Roles:         []string{"user"},
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		err := userRepo.Create(ctx, user)
		require.NoError(t, err)

		// Enable TOTP first time
		config1, backupCodes1, err := totpService.EnableTOTP(user.ID.String())
		require.NoError(t, err)

		// Try to enable TOTP again
		_, _, err = totpService.EnableTOTP(user.ID.String())
		assert.ErrorIs(t, err, domain.ErrTOTPAlreadyEnabled)

		// Disable TOTP
		err = totpService.DisableTOTP(user.ID.String())
		require.NoError(t, err)

		// Enable TOTP second time
		config2, backupCodes2, err := totpService.EnableTOTP(user.ID.String())
		require.NoError(t, err)

		// Verify new configuration is different
		assert.NotEqual(t, config1.Secret, config2.Secret)
		assert.NotEqual(t, backupCodes1, backupCodes2)

		// Verify old TOTP code doesn't work
		oldCode, err := extotp.GenerateCode(config1.Secret, time.Now())
		require.NoError(t, err)
		err = totpService.VerifyTOTP(user.ID.String(), oldCode)
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)

		// Verify new TOTP code works
		newCode, err := extotp.GenerateCode(config2.Secret, time.Now())
		require.NoError(t, err)
		err = totpService.VerifyTOTP(user.ID.String(), newCode)
		require.NoError(t, err)
	})
}
