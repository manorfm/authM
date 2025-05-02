package application

import (
	"context"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"go.uber.org/zap"
)

type UserService struct {
	userRepo domain.UserRepository
	logger   *zap.Logger
}

func NewUserService(userRepo domain.UserRepository, logger *zap.Logger) *UserService {
	return &UserService{
		userRepo: userRepo,
		logger:   logger,
	}
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, id domain.ULID) (*domain.User, error) {
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

// UpdateUser updates a user's details
func (s *UserService) UpdateUser(ctx context.Context, id domain.ULID, name, phone string) error {
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return domain.ErrUserNotFound
	}

	user.Name = name
	user.Phone = phone
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(ctx, user)
}

// ListUsers retrieves a list of users with pagination
func (s *UserService) ListUsers(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	return s.userRepo.List(ctx, limit, offset)
}
