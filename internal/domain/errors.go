package domain

import "errors"

var (
	// ErrInvalidCredentials is returned when credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrInvalidClient is returned when the client is invalid
	ErrInvalidClient = errors.New("invalid client")

	// ErrInternal is returned when there is an internal server error
	ErrInternal = errors.New("internal server error")

	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")

	// ErrUserAlreadyExists is returned when a user already exists
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrInvalidScope is returned when the scope is invalid
	ErrInvalidScope = errors.New("invalid scope")
)
