package application

import (
	"context"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/password"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type AuthService struct {
	userRepo domain.UserRepository
	jwt      *jwt.JWT
	logger   *zap.Logger
}

func NewAuthService(userRepo domain.UserRepository, jwt *jwt.JWT, logger *zap.Logger) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		jwt:      jwt,
		logger:   logger,
	}
}

// Register creates a new user
func (s *AuthService) Register(ctx context.Context, name, email, passwordStr, phone string) (*domain.User, error) {
	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := password.HashPassword(passwordStr)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &domain.User{
		ID:        domain.ULID(ulid.Make()),
		Name:      name,
		Email:     email,
		Password:  hashedPassword,
		Phone:     phone,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save user to database
	err = s.userRepo.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, email, passwordStr string) (*domain.User, *domain.TokenPair, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, nil, domain.ErrInvalidCredentials
	}

	err = password.CheckPassword(passwordStr, user.Password)
	if err != nil {
		return nil, nil, domain.ErrInvalidCredentials
	}

	infraTokenPair, err := s.jwt.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		return nil, nil, err
	}

	tokenPair := &domain.TokenPair{
		AccessToken:  infraTokenPair.AccessToken,
		RefreshToken: infraTokenPair.RefreshToken,
	}

	return user, tokenPair, nil
}
