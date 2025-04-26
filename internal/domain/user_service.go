package domain

import (
	"context"
	"errors"

	"github.com/oklog/ulid/v2"
)

// UserService defines the interface for user operations
type UserService interface {
	// Register creates a new user
	Register(ctx context.Context, name, email, password, phone string) (*User, error)
	// Login authenticates a user and returns a token pair
	Login(ctx context.Context, email, password string) (*User, *TokenPair, error)
	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, id ulid.ULID) (*User, error)
	// UpdateUser updates a user's details
	UpdateUser(ctx context.Context, id ulid.ULID, name, phone string) error
	// ListUsers retrieves a list of users with pagination
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}

// ErrUserNotFound is returned when a user is not found
var ErrUserNotFound = errors.New("user not found")

// ErrUserAlreadyExists is returned when a user with the same email already exists
var ErrUserAlreadyExists = errors.New("user already exists")

// ErrInvalidCredentials is returned when login credentials are invalid
var ErrInvalidCredentials = errors.New("invalid credentials")
