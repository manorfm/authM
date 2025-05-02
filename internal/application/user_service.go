package application

import (
	"context"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"go.uber.org/zap"
)

type UserService struct {
	db     *database.Postgres
	logger *zap.Logger
}

func NewUserService(db *database.Postgres, logger *zap.Logger) *UserService {
	return &UserService{
		db:     db,
		logger: logger,
	}
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, id domain.ULID) (*domain.User, error) {
	user := &domain.User{}
	err := s.db.QueryRow(ctx, `
		SELECT id, name, email, phone, created_at, updated_at
		FROM users WHERE id = $1
	`, id.String()).Scan(&user.ID, &user.Name, &user.Email, &user.Phone, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	return user, nil
}

// UpdateUser updates a user's details
func (s *UserService) UpdateUser(ctx context.Context, id domain.ULID, name, phone string) error {
	err := s.db.Exec(ctx, `
		UPDATE users
		SET name = $1, phone = $2, updated_at = $3
		WHERE id = $4
	`, name, phone, time.Now(), id.String())
	if err != nil {
		return err
	}

	return nil
}

// ListUsers retrieves a list of users with pagination
func (s *UserService) ListUsers(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, name, email, phone, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Phone, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}
