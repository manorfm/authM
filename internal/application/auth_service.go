package application

import (
	"context"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/password"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type AuthService struct {
	userRepo   domain.UserRepository
	jwtService domain.JWTService
	logger     *zap.Logger
}

func NewAuthService(userRepo domain.UserRepository, jwtService domain.JWTService, logger *zap.Logger) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		jwtService: jwtService,
		logger:     logger,
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
		s.logger.Error("failed to hash password", zap.Error(err))
		return nil, domain.ErrInternal
	}

	// Create user
	user := &domain.User{
		ID:        domain.ULID(ulid.Make()),
		Name:      name,
		Email:     email,
		Password:  hashedPassword,
		Phone:     phone,
		Roles:     []string{"ADMIN"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save user to database
	err = s.userRepo.Create(ctx, user)
	if err != nil {
		s.logger.Error("failed to create user", zap.Error(err))
		return nil, domain.ErrInternal
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, email, passwordStr string) (*domain.TokenPair, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	err = password.CheckPassword(passwordStr, user.Password)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	tokenPair, err := s.jwtService.GenerateTokenPair(user.ID, user.Roles)
	if err != nil {
		return nil, domain.ErrFailedGenerateToken
	}

	return tokenPair, nil
}
