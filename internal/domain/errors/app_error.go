package apperrors

import "fmt"

// AppError represents an application error
// @Description An application error with a message and optional details
type AppError struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
	Code    string `json:"code"`
}

// Error types
const (
	ValidationError   = "VALIDATION_ERROR"
	UnauthorizedError = "UNAUTHORIZED_ERROR"
	NotFoundError     = "NOT_FOUND_ERROR"
	ConflictError     = "CONFLICT_ERROR"
	InternalError     = "INTERNAL_ERROR"
)

// Error returns the error message
func (e *AppError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error
func NewValidationError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    "VALIDATION_ERROR",
	}
}

// NewUnauthorizedError creates a new unauthorized error
func NewUnauthorizedError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    "UNAUTHORIZED",
	}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    "NOT_FOUND",
	}
}

// NewConflictError creates a new conflict error
func NewConflictError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    "CONFLICT",
	}
}

// NewInternalError creates a new internal error
func NewInternalError(message string, err error) *AppError {
	return &AppError{
		Message: message,
		Details: err.Error(),
		Code:    "INTERNAL_ERROR",
	}
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return fmt.Errorf("%s: %s", e.Code, e.Message)
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == ValidationError
	}
	return false
}

// IsUnauthorizedError checks if the error is an unauthorized error
func IsUnauthorizedError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == UnauthorizedError
	}
	return false
}

// IsNotFoundError checks if the error is a not found error
func IsNotFoundError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == NotFoundError
	}
	return false
}

// IsConflictError checks if the error is a conflict error
func IsConflictError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == ConflictError
	}
	return false
}

// IsInternalError checks if the error is an internal error
func IsInternalError(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == InternalError
	}
	return false
}
