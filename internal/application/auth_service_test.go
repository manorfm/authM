package application

import (
	"context"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
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

func (m *MockUserRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.User, error) {
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

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id ulid.ULID) error {
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

func (m *MockUserRepository) AddRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockUserRepository) RemoveRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func TestAuthService_Register(t *testing.T) {
	logger, _ := zap.NewProduction()
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
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
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(true, nil)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, domain.ErrUserAlreadyExists, err)
	})

	t.Run("repository error on exists check", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("ExistsByEmail", ctx, "test@example.com").Return(false, assert.AnError)

		user, err := service.Register(ctx, "Test User", "test@example.com", "password123", "1234567890")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("repository error on create", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
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
	logger, _ := zap.NewProduction()
	ctx := context.Background()

	t.Run("successful login", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
		service := NewAuthService(repo, jwtService, logger)

		hashedPassword, _ := password.HashPassword("password123")
		user := &domain.User{
			ID:        domain.ULID(ulid.Make()),
			Name:      "Test User",
			Email:     "test@example.com",
			Password:  hashedPassword,
			Phone:     "1234567890",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		repo.On("FindByEmail", ctx, "test@example.com").Return(user, nil)

		user, tokenPair, err := service.Login(ctx, "test@example.com", "password123")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.NotNil(t, tokenPair)
		assert.NotEmpty(t, tokenPair.AccessToken)
		assert.NotEmpty(t, tokenPair.RefreshToken)
	})

	t.Run("invalid credentials - user not found", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("FindByEmail", ctx, "test@example.com").Return(nil, domain.ErrUserNotFound)

		user, tokenPair, err := service.Login(ctx, "test@example.com", "wrongpassword")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Nil(t, tokenPair)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
	})

	t.Run("invalid credentials - wrong password", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
		service := NewAuthService(repo, jwtService, logger)

		hashedPassword, _ := password.HashPassword("correctpassword")
		user := &domain.User{
			ID:        domain.ULID(ulid.Make()),
			Name:      "Test User",
			Email:     "test@example.com",
			Password:  hashedPassword,
			Phone:     "1234567890",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		repo.On("FindByEmail", ctx, "test@example.com").Return(user, nil)

		user, tokenPair, err := service.Login(ctx, "test@example.com", "wrongpassword")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Nil(t, tokenPair)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
	})

	t.Run("repository error", func(t *testing.T) {
		repo := new(MockUserRepository)
		jwtService := jwt.New("test-secret", time.Hour, time.Hour*24)
		service := NewAuthService(repo, jwtService, logger)

		repo.On("FindByEmail", ctx, "test@example.com").Return(nil, assert.AnError)

		user, tokenPair, err := service.Login(ctx, "test@example.com", "password123")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Nil(t, tokenPair)
		assert.Equal(t, domain.ErrInvalidCredentials, err)
	})
}
