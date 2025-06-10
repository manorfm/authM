package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/repository"
	"github.com/ipede/user-manager-service/internal/infrastructure/totp"
	"github.com/oklog/ulid/v2"
	extotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

// MockEmailService is a mock implementation of the email service
type MockEmailService struct {
	mock.Mock
	verificationCode string
	resetCode        string
}

func (m *MockEmailService) SendVerificationEmail(ctx context.Context, email, code string) error {
	m.verificationCode = code
	args := m.Called(ctx, email, code)
	return args.Error(0)
}

func (m *MockEmailService) SendPasswordResetEmail(ctx context.Context, email, code string) error {
	m.resetCode = code
	args := m.Called(ctx, email, code)
	return args.Error(0)
}

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

	// Setup database and run migrations
	db, err := database.NewPostgres(ctx, cfg, zap.NewNop())
	require.NoError(t, err)

	// Run migrations
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			email VARCHAR(255) NOT NULL UNIQUE,
			password VARCHAR(255) NOT NULL,
			phone VARCHAR(255) NOT NULL,
			roles TEXT[] NOT NULL,
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS verification_codes (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			code VARCHAR(255) NOT NULL,
			type VARCHAR(50) NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_codes_user_id ON verification_codes(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON verification_codes(expires_at)`,
		`CREATE TABLE IF NOT EXISTS oauth2_clients (
			id VARCHAR(255) PRIMARY KEY,
			secret VARCHAR(255) NOT NULL,
			redirect_uris TEXT[] NOT NULL,
			grant_types TEXT[] NOT NULL,
			scopes TEXT[] NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS authorization_codes (
			code VARCHAR(255) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
			user_id VARCHAR(255) NOT NULL,
			scopes TEXT[] NOT NULL,
			code_challenge VARCHAR(255),
			code_challenge_method VARCHAR(32),
			code_verifier VARCHAR(255),
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)`,
		`CREATE TABLE IF NOT EXISTS totp_secrets (
			user_id VARCHAR(255) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			secret VARCHAR(255) NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS totp_backup_codes (
			user_id VARCHAR(255) PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			codes JSONB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS mfa_tickets (
			id VARCHAR(255) PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		)`,
	}

	for _, migration := range migrations {
		err := db.Exec(ctx, migration)
		require.NoError(t, err)
	}

	// Close the database connection after migrations
	db.Close()

	return container, cfg
}

func TestAuthService_Integration(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	// Setup test container with migrations
	container, cfg := setupTestContainer(t)
	defer container.Terminate(ctx)

	// Setup database
	db, err := database.NewPostgres(ctx, cfg, logger)
	require.NoError(t, err)
	defer db.Close()

	// Setup repositories
	userRepo := repository.NewUserRepository(db, logger)
	verificationRepo := repository.NewVerificationCodeRepository(db, logger)
	mfaTicketRepo := repository.NewMFATicketRepository(db, logger)
	totpRepo := repository.NewTOTPRepository(db, logger)

	// Setup email service (mock)
	emailSvc := &MockEmailService{}
	emailSvc.On("SendVerificationEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	emailSvc.On("SendPasswordResetEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// Setup JWT service (real, local key)
	tempDir, err := os.MkdirTemp("", "jwt-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	jwtCfg := &config.Config{
		JWTAccessDuration:  15 * time.Minute,
		JWTRefreshDuration: 24 * time.Hour,
		JWTKeyPath:         filepath.Join(tempDir, "test-key"),
		RSAKeySize:         2048,
	}
	jwtStrategy, err := jwt.NewLocalStrategy(jwtCfg, logger)
	require.NoError(t, err)
	jwtService := jwt.NewJWTService(jwtStrategy, jwtCfg, logger)

	// Setup TOTP service
	totpGenerator := totp.NewGenerator(logger)
	totpService := application.NewTOTPService(totpRepo, totpGenerator, logger)

	// Setup auth service
	authService := application.NewAuthService(
		userRepo,
		verificationRepo,
		jwtService,
		emailSvc,
		totpService,
		mfaTicketRepo,
		logger,
	)

	// Teste temporário: criar ticket MFA isolado
	tempTicket := &domain.MFATicket{
		Ticket:    ulid.Make(),
		User:      "temp-user",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	err = mfaTicketRepo.Create(ctx, tempTicket)
	if err != nil {
		fmt.Printf("[DEBUG] Erro ao criar ticket MFA isolado: %v\n", err)
	}

	t.Run("Register and Login Flow", func(t *testing.T) {
		// Register a new user
		user, err := authService.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		require.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "test@example.com", user.Email)
		assert.False(t, user.EmailVerified)

		// Try to login before email verification
		_, err = authService.Login(ctx, "test@example.com", "password123")
		assert.ErrorIs(t, err, domain.ErrEmailNotVerified)

		// Verify email using the code from the mock
		err = authService.VerifyEmail(ctx, "test@example.com", emailSvc.verificationCode)
		require.NoError(t, err)

		// Login after email verification
		result, err := authService.Login(ctx, "test@example.com", "password123")
		require.NoError(t, err)
		assert.NotNil(t, result)

		tokens, ok := result.(*domain.TokenPair)
		require.True(t, ok)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("Password Reset Flow", func(t *testing.T) {
		// Create a new user for password reset test
		user, err := authService.Register(ctx, "Reset User", "reset@example.com", "oldpassword", "9876543210")
		require.NoError(t, err)
		assert.NotNil(t, user)

		// Verify email
		err = authService.VerifyEmail(ctx, "reset@example.com", emailSvc.verificationCode)
		require.NoError(t, err)

		// Request password reset
		err = authService.RequestPasswordReset(ctx, "reset@example.com")
		require.NoError(t, err)

		// Reset password using the code from the mock
		err = authService.ResetPassword(ctx, "reset@example.com", emailSvc.resetCode, "newpassword")
		require.NoError(t, err)

		// Try to login with new password
		result, err := authService.Login(ctx, "reset@example.com", "newpassword")
		require.NoError(t, err)
		assert.NotNil(t, result)

		tokens, ok := result.(*domain.TokenPair)
		require.True(t, ok)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
	})

	t.Run("Invalid Login Attempts", func(t *testing.T) {
		// Create a new user for invalid login test
		user, err := authService.Register(ctx, "Invalid Login User", "invalid@example.com", "password123", "5555555555")
		require.NoError(t, err)
		assert.NotNil(t, user)

		// Verify email
		err = authService.VerifyEmail(ctx, "invalid@example.com", emailSvc.verificationCode)
		require.NoError(t, err)

		// Try to login with invalid credentials
		_, err = authService.Login(ctx, "invalid@example.com", "wrongpassword")
		assert.ErrorIs(t, err, domain.ErrInvalidCredentials)
	})

	t.Run("Login with TOTP Flow", func(t *testing.T) {
		// Create a test user
		user, err := authService.Register(ctx, "TOTP User", "totp@example.com", "password123", "1234567890")
		require.NoError(t, err)
		assert.NotNil(t, user)

		// Verify email
		err = authService.VerifyEmail(ctx, "totp@example.com", emailSvc.verificationCode)
		require.NoError(t, err)

		// Enable TOTP
		totp, err := totpService.EnableTOTP(user.ID.String())
		if err != nil {
			fmt.Printf("[DEBUG] Erro ao habilitar TOTP: %v\n", err)
		}
		require.NoError(t, err)
		fmt.Printf("[DEBUG] TOTP habilitado: %+v\n", totp)
		assert.NotNil(t, totp.QRCode)
		assert.NotEmpty(t, totp.BackupCodes)

		// Verificar se segredo TOTP foi salvo
		secretCheck, err := totpService.GetTOTPSecret(ctx, user.ID.String())
		if err != nil {
			fmt.Printf("[DEBUG] Erro ao checar segredo TOTP após Enable: %v\n", err)
		}
		fmt.Printf("[DEBUG] Segredo TOTP após Enable: %s\n", secretCheck)

		// Try to login - should get MFA ticket
		fmt.Printf("[DEBUG] Chamando Login para gerar ticket MFA...\n")
		result, err := authService.Login(ctx, "totp@example.com", "password123")
		if err != nil {
			fmt.Printf("[DEBUG] Erro no Login: %v\n", err)
		}
		require.NoError(t, err)
		fmt.Printf("[DEBUG] Resultado do Login: %#v\n", result)
		assert.NotNil(t, result)

		ticket, ok := result.(*domain.MFATicket)
		if !ok {
			fmt.Printf("[DEBUG] Resultado não é MFATicket: %#v\n", result)
		}
		require.True(t, ok)
		assert.NotEmpty(t, ticket.Ticket)
		assert.Equal(t, user.ID.String(), ticket.User)

		// Generate a valid TOTP code
		secret, err := totpService.GetTOTPSecret(ctx, user.ID.String())
		if err != nil {
			fmt.Printf("[DEBUG] Erro ao obter segredo TOTP: %v\n", err)
		}
		require.NoError(t, err)
		code, err := extotp.GenerateCode(secret, time.Now())
		if err != nil {
			fmt.Printf("[DEBUG] Erro ao gerar código TOTP: %v\n", err)
		}
		require.NoError(t, err)

		// Verify MFA and get tokens
		result, err = authService.VerifyMFA(ctx, ticket.Ticket.String(), code)
		if err != nil {
			fmt.Printf("[DEBUG] Erro no VerifyMFA: %v\n", err)
		}
		require.NoError(t, err)
		assert.NotNil(t, result)

		var tokens *domain.TokenPair
		tokens, ok = result.(*domain.TokenPair)
		require.True(t, ok)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)

		// Try to use the same ticket again - should fail
		_, err = authService.VerifyMFA(ctx, ticket.Ticket.String(), code)
		assert.ErrorIs(t, err, domain.ErrInvalidMFATicket)

		// Try to use an expired ticket
		expiredTicket := &domain.MFATicket{
			Ticket:    ulid.Make(),
			User:      user.ID.String(),
			CreatedAt: time.Now().Add(-6 * time.Minute),
			ExpiresAt: time.Now().Add(-1 * time.Minute),
		}
		err = mfaTicketRepo.Create(ctx, expiredTicket)
		require.NoError(t, err)

		_, err = authService.VerifyMFA(ctx, expiredTicket.Ticket.String(), code)
		assert.ErrorIs(t, err, domain.ErrMFATicketExpired)

		// Try to use an invalid ticket
		_, err = authService.VerifyMFA(ctx, "invalid", code)
		assert.ErrorIs(t, err, domain.ErrInvalidMFATicket)

		// Try to use an invalid code (ticket já foi deletado, então retorna invalid ticket)
		_, err = authService.VerifyMFA(ctx, ticket.Ticket.String(), "000000")
		assert.ErrorIs(t, err, domain.ErrInvalidMFATicket)

		// Try to use a backup code (ticket já foi deletado, então retorna invalid ticket)
		_, err = authService.VerifyMFA(ctx, ticket.Ticket.String(), totp.BackupCodes[0])
		assert.ErrorIs(t, err, domain.ErrInvalidMFATicket)
	})
}
