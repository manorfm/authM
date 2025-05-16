package application

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id domain.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id domain.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) List(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.User), args.Error(1)
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

func TestAuthService_Register(t *testing.T) {
	logger, _ := zap.NewProduction()
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService, err := jwt.New(time.Hour, time.Hour*24)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
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
		jwtService, err := jwt.New(time.Hour, time.Hour*24)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(true, nil)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, domain.ErrUserAlreadyExists, err)
	})

	t.Run("repository error on exists check", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService, err := jwt.New(time.Hour, time.Hour*24)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(false, assert.AnError)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("repository error on create", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService, err := jwt.New(time.Hour, time.Hour*24)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
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
	hashedPassword := "$2a$10$BJTcDRbpKbFlFzLKKnN2t.o1xvMvefT/2ZG8KTjOqIqcyzqd47DCW" // hash for "password123"
	tests := []struct {
		name        string
		email       string
		password    string
		mockUser    *domain.User
		mockError   error
		expectedErr error
	}{
		{
			name:     "successful login",
			email:    "test@example.com",
			password: "password123",
			mockUser: &domain.User{
				ID:       domain.MustParseULID("01H9Z7K3Y4D5E6F7G8H9J0K1L2"),
				Email:    "test@example.com",
				Password: hashedPassword,
				Roles:    []string{"user"},
			},
		},
		{
			name:        "invalid credentials - user not found",
			email:       "test@example.com",
			password:    "password123",
			mockError:   domain.ErrUserNotFound,
			expectedErr: domain.ErrUserNotFound,
		},
		{
			name:     "invalid credentials - wrong password",
			email:    "test@example.com",
			password: "wrong_password",
			mockUser: &domain.User{
				ID:       domain.MustParseULID("01H9Z7K3Y4D5E6F7G8H9J0K1L2"),
				Email:    "test@example.com",
				Password: hashedPassword,
			},
			expectedErr: domain.ErrInvalidCredentials,
		},
		{
			name:        "repository error",
			email:       "test@example.com",
			password:    "password123",
			mockUser:    nil,
			mockError:   assert.AnError,
			expectedErr: fmt.Errorf("failed to find user: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockUserRepository)
			jwtService, err := jwt.New(time.Hour, time.Hour*24)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			logger := zap.NewNop()

			service := NewAuthService(mockRepo, jwtService, logger)

			if tt.mockUser != nil {
				mockRepo.On("FindByEmail", mock.Anything, tt.email).Return(tt.mockUser, nil)
			} else {
				mockRepo.On("FindByEmail", mock.Anything, tt.email).Return(nil, tt.mockError)
			}

			tokenPair, err := service.Login(context.Background(), tt.email, tt.password)

			if tt.expectedErr != nil {
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
				assert.Nil(t, tokenPair)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.NotEmpty(t, tokenPair.AccessToken)
				assert.NotEmpty(t, tokenPair.RefreshToken)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}
