package domain

import (
	"context"
)

// UserService defines the interface for user operations
type AuthService interface {
	// Register creates a new user
	Register(ctx context.Context, name, email, password, phone string) (*User, error)
	// Login authenticates a user and returns a token pair
	Login(ctx context.Context, email, password string) (*TokenPair, error)
	VerifyEmail(ctx context.Context, email, code string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, email, code, newPassword string) error
}
