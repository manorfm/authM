package domain

import (
	"context"
	"errors"

	"github.com/oklog/ulid/v2"
)

type UserService interface {
	GetUser(ctx context.Context, id ulid.ULID) (*User, error)
	UpdateUser(ctx context.Context, id ulid.ULID, name, phone string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}

var ErrUserNotFound = errors.New("user not found")
