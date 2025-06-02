package domain

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// ULID represents a Universally Unique Lexicographically Sortable Identifier
// @Description A string representation of ULID
// @type string
// @format ulid
type ULID = ulid.ULID

// User represents a user in the system
type User struct {
	ID            ulid.ULID  `json:"id"`
	Name          string     `json:"name"`
	Email         string     `json:"email"`
	Password      string     `json:"-"` // Password is not serialized to JSON
	Phone         string     `json:"phone"`
	Roles         []string   `json:"roles"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

// CreateUserRequest represents the request to create a new user
type CreateUserRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Phone    string `json:"phone" validate:"required"`
}

// UpdateUserRequest represents the request to update a user
type UpdateUserRequest struct {
	Name  string `json:"name" validate:"required"`
	Phone string `json:"phone" validate:"required"`
}

// LoginRequest represents the request to login a user
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// NewUser creates a new user instance
func NewUser(name, email, password, phone string) (*User, error) {
	id := ulid.Make()

	user := &User{
		ID:        id,
		Name:      name,
		Email:     email,
		Password:  password,
		Phone:     phone,
		Roles:     []string{"user"}, // Default role
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return user, nil
}

// AddRole adds a role to the user
func (u *User) AddRole(role string) {
	for _, r := range u.Roles {
		if r == role {
			return
		}
	}
	u.Roles = append(u.Roles, role)
}

// RemoveRole removes a role from the user
func (u *User) RemoveRole(role string) {
	for i, r := range u.Roles {
		if r == role {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			return
		}
	}
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}
