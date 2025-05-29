package domain

import "fmt"

type BusinessError struct {
	error
	Code    string `json:"code"`
	Message string `json:"message"`
}

type InfraError struct {
	error
	Code    string `json:"code"`
	Message string `json:"message"`
}

var (
	// ErrInvalidCredentials is returned when credentials are invalid
	ErrInvalidCredentials = NewBusinessError("U0001", "Invalid credentials")

	// ErrInvalidClient is returned when the client is invalid
	ErrInvalidClient = NewBusinessError("U0002", "Invalid client")

	// ErrInvalidAuthorizationCode is returned when the authorization code is invalid
	ErrInvalidAuthorizationCode = NewBusinessError("U0003", "Invalid authorization code")

	// ErrAuthorizationCodeExpired is returned when the authorization code is expired
	ErrAuthorizationCodeExpired = NewBusinessError("U0004", "Authorization code expired")

	// ErrInvalidUserID is returned when the user ID is invalid
	ErrInvalidUserID = NewBusinessError("U0005", "Invalid user ID")

	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = NewBusinessError("U0006", "User not found")

	// ErrUserAlreadyExists is returned when a user already exists
	ErrUserAlreadyExists = NewBusinessError("U0007", "User already exists")

	// ErrInvalidScope is returned when the scope is invalid
	ErrInvalidScope = NewBusinessError("U0008", "Invalid scope")

	// ErrInvalidField is returned when the field is invalid
	ErrInvalidField = NewBusinessError("U0009", "Invalid field")

	// ErrInvalidRequestBody is returned when the request body is invalid
	ErrInvalidRequestBody = NewBusinessError("U0010", "Invalid request body")

	// ErrInternal is returned when there is an internal server error
	ErrInternal = NewInfraError("U0011", "Internal server error")

	// ErrFailedGenerateToken is returned when the scope is invalid
	ErrFailedGenerateToken = NewInfraError("U0012", "Failed to generate token")

	// ErrDatabaseQuery is returned when the email check fails
	ErrDatabaseQuery = NewInfraError("U0013", "Query error")
)

func NewBusinessError(code, message string) *BusinessError {
	return &BusinessError{
		error:   fmt.Errorf("%s: %s", code, message),
		Code:    code,
		Message: message,
	}
}

func NewInfraError(code, message string) *InfraError {
	return &InfraError{
		error:   fmt.Errorf("%s: %s", code, message),
		Code:    code,
		Message: message,
	}
}
