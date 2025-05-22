package application

import (
	"context"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/password"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id domain.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) AddRole(ctx context.Context, userID domain.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockUserRepository) RemoveRole(ctx context.Context, userID domain.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id domain.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.User), args.Error(1)
}

func TestAuthService_Register(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		repo := new(MockUserRepository)
		cfg := &config.Config{
			DBHost:             "localhost",
			DBPort:             5432,
			DBUser:             "postgres",
			DBPassword:         "postgres",
			DBName:             "user_manager_test",
			JWTAccessDuration:  15 * time.Minute,
			JWTRefreshDuration: 24 * time.Hour,
			JWTKeyPath:         "test-key",
			JWTKeyPassword:     "",
			VaultAddress:       "http://localhost:8200",
			VaultToken:         "test-token",
			VaultMountPath:     "transit",
			VaultKeyName:       "test-key",
			VaultRoleName:      "test-role",
			VaultAuthMethod:    "token",
			VaultRetryCount:    3,
			VaultRetryDelay:    time.Second,
			VaultTimeout:       time.Second * 5,
			ServerPort:         8080,
			ServerHost:         "localhost",
		}
		jwtService := jwt.NewJWTService(cfg, logger)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(false, nil)
		repo.On("Create", ctx, mock.Anything).Return(nil)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "Test User", user.Name)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "1234567890", user.Phone)
		assert.NotEmpty(t, user.Password)
		assert.NotEmpty(t, user.ID)
		assert.NotZero(t, user.CreatedAt)
		assert.NotZero(t, user.UpdatedAt)
	})

	t.Run("user already exists", func(t *testing.T) {
		repo := new(MockUserRepository)
		cfg := &config.Config{
			DBHost:             "localhost",
			DBPort:             5432,
			DBUser:             "postgres",
			DBPassword:         "postgres",
			DBName:             "user_manager_test",
			JWTAccessDuration:  15 * time.Minute,
			JWTRefreshDuration: 24 * time.Hour,
			JWTKeyPath:         "test-key",
			JWTKeyPassword:     "",
			VaultAddress:       "http://localhost:8200",
			VaultToken:         "test-token",
			VaultMountPath:     "transit",
			VaultKeyName:       "test-key",
			VaultRoleName:      "test-role",
			VaultAuthMethod:    "token",
			VaultRetryCount:    3,
			VaultRetryDelay:    time.Second,
			VaultTimeout:       time.Second * 5,
			ServerPort:         8080,
			ServerHost:         "localhost",
		}
		jwtService := jwt.NewJWTService(cfg, logger)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(true, nil)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, domain.ErrUserAlreadyExists, err)
	})

	t.Run("repository error on exists check", func(t *testing.T) {
		repo := new(MockUserRepository)
		cfg := &config.Config{
			DBHost:             "localhost",
			DBPort:             5432,
			DBUser:             "postgres",
			DBPassword:         "postgres",
			DBName:             "user_manager_test",
			JWTAccessDuration:  15 * time.Minute,
			JWTRefreshDuration: 24 * time.Hour,
			JWTKeyPath:         "test-key",
			JWTKeyPassword:     "",
			VaultAddress:       "http://localhost:8200",
			VaultToken:         "test-token",
			VaultMountPath:     "transit",
			VaultKeyName:       "test-key",
			VaultRoleName:      "test-role",
			VaultAuthMethod:    "token",
			VaultRetryCount:    3,
			VaultRetryDelay:    time.Second,
			VaultTimeout:       time.Second * 5,
			ServerPort:         8080,
			ServerHost:         "localhost",
		}
		jwtService := jwt.NewJWTService(cfg, logger)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(false, assert.AnError)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("repository error on create", func(t *testing.T) {
		repo := new(MockUserRepository)
		cfg := &config.Config{
			DBHost:             "localhost",
			DBPort:             5432,
			DBUser:             "postgres",
			DBPassword:         "postgres",
			DBName:             "user_manager_test",
			JWTAccessDuration:  15 * time.Minute,
			JWTRefreshDuration: 24 * time.Hour,
			JWTKeyPath:         "test-key",
			JWTKeyPassword:     "",
			VaultAddress:       "http://localhost:8200",
			VaultToken:         "test-token",
			VaultMountPath:     "transit",
			VaultKeyName:       "test-key",
			VaultRoleName:      "test-role",
			VaultAuthMethod:    "token",
			VaultRetryCount:    3,
			VaultRetryDelay:    time.Second,
			VaultTimeout:       time.Second * 5,
			ServerPort:         8080,
			ServerHost:         "localhost",
		}
		jwtService := jwt.NewJWTService(cfg, logger)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(false, nil)
		repo.On("Create", ctx, mock.Anything).Return(assert.AnError)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestAuthService_Login(t *testing.T) {
	tests := []struct {
		name          string
		mockSetup     func(*MockUserRepository)
		email         string
		password      string
		expectedError error
		expectedToken *domain.TokenPair
	}{
		{
			name: "user not found",
			mockSetup: func(mockRepo *MockUserRepository) {
				mockRepo.On("FindByEmail", mock.Anything, "nonexistent@example.com").Return(nil, domain.ErrUserNotFound)
			},
			email:         "nonexistent@example.com",
			password:      "password123",
			expectedError: domain.ErrInvalidCredentials,
			expectedToken: nil,
		},
		{
			name: "invalid password",
			mockSetup: func(mockRepo *MockUserRepository) {
				hashedPassword, _ := password.HashPassword("correctpassword")
				mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
					ID:       ulid.Make(),
					Email:    "test@example.com",
					Password: hashedPassword,
					Roles:    []string{"user"},
				}, nil)
			},
			email:         "test@example.com",
			password:      "wrongpassword",
			expectedError: domain.ErrInvalidCredentials,
			expectedToken: nil,
		},
		{
			name: "successful login",
			mockSetup: func(mockRepo *MockUserRepository) {
				hashedPassword, _ := password.HashPassword("correctpassword")
				mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
					ID:       ulid.Make(),
					Email:    "test@example.com",
					Password: hashedPassword,
					Roles:    []string{"user"},
				}, nil)
			},
			email:         "test@example.com",
			password:      "correctpassword",
			expectedError: nil,
			expectedToken: &domain.TokenPair{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := new(MockUserRepository)
			cfg := &config.Config{
				DBHost:             "localhost",
				DBPort:             5432,
				DBUser:             "postgres",
				DBPassword:         "postgres",
				DBName:             "user_manager_test",
				JWTAccessDuration:  15 * time.Minute,
				JWTRefreshDuration: 24 * time.Hour,
				JWTKeyPath:         "test-key",
				JWTKeyPassword:     "",
				VaultAddress:       "http://localhost:8200",
				VaultToken:         "test-token",
				VaultMountPath:     "transit",
				VaultKeyName:       "test-key",
				VaultRoleName:      "test-role",
				VaultAuthMethod:    "token",
				VaultRetryCount:    3,
				VaultRetryDelay:    time.Second,
				VaultTimeout:       time.Second * 5,
				ServerPort:         8080,
				ServerHost:         "localhost",
			}
			jwtService := jwt.NewJWTService(cfg, zap.NewNop())
			service := NewAuthService(repo, jwtService, zap.NewNop())

			tt.mockSetup(repo)

			token, err := service.Login(context.Background(), tt.email, tt.password)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.RefreshToken)
			}
		})
	}
}
