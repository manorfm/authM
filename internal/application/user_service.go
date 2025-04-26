package application

import (
	"context"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/password"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

// UserService implements the domain.UserService interface
type UserService struct {
	db     *database.Postgres
	jwt    *jwt.JWT
	logger *zap.Logger
}

// NewUserService creates a new UserService instance
func NewUserService(db *database.Postgres, jwt *jwt.JWT, logger *zap.Logger) *UserService {
	return &UserService{
		db:     db,
		jwt:    jwt,
		logger: logger,
	}
}

// Register creates a new user
func (s *UserService) Register(ctx context.Context, name, email, passwordStr, phone string) (*domain.User, error) {
	// Check if user already exists
	var count int
	err := s.db.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
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
	err = s.db.Exec(ctx, `
		INSERT INTO users (id, name, email, password, phone, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, user.ID.String(), user.Name, user.Email, user.Password, user.Phone, user.CreatedAt, user.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// Login authenticates a user and returns a token pair
func (s *UserService) Login(ctx context.Context, email, passwordStr string) (*domain.User, *domain.TokenPair, error) {
	// Get user by email
	user := &domain.User{}
	err := s.db.QueryRow(ctx, `
		SELECT id, name, email, password, phone, created_at, updated_at
		FROM users WHERE email = $1
	`, email).Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Phone, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, nil, domain.ErrInvalidCredentials
	}

	// Check password
	err = password.CheckPassword(passwordStr, user.Password)
	if err != nil {
		return nil, nil, domain.ErrInvalidCredentials
	}

	// Generate token pair
	infraTokenPair, err := s.jwt.GenerateTokenPair(user.ID, []string{"user"})
	if err != nil {
		return nil, nil, err
	}

	// Convert infrastructure token pair to domain token pair
	tokenPair := &domain.TokenPair{
		AccessToken:  infraTokenPair.AccessToken,
		RefreshToken: infraTokenPair.RefreshToken,
	}

	return user, tokenPair, nil
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
