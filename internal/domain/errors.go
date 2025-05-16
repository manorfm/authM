package domain

import "errors"

var (
	// ErrInvalidCredentials is returned when credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrInvalidClient is returned when the client is invalid
	ErrInvalidClient = errors.New("invalid client")

	// ErrInternal is returned when there is an internal server error
	ErrInternal = errors.New("internal server error")
)
