package errors

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents the standard error response structure
type ErrorResponse struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Details []ErrorDetail `json:"details,omitempty"`
}

// ErrorDetail represents a validation error detail
type ErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error codes
const (
	ErrCodeValidation     = "ERR_003"
	ErrCodeAuthentication = "ERR_002"
	ErrCodeAuthorization  = "ERR_001"
	ErrCodeInternal       = "ERR_004"
	ErrCodeNotFound       = "ERR_005"
	ErrCodeInvalidRequest = "ERR_003"
	ErrCodeConflict       = "ERR_001"
)

// RespondWithError sends a standardized error response
func RespondWithError(w http.ResponseWriter, code string, message string, details []ErrorDetail, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Code:    code,
		Message: message,
		Details: details,
	})
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) ValidationError {
	return ValidationError{
		Field:   field,
		Message: message,
	}
}

// ValidationErrors is a slice of validation errors
type ValidationErrors []ValidationError

// Add adds a validation error to the slice
func (v *ValidationErrors) Add(field, message string) {
	*v = append(*v, NewValidationError(field, message))
}

// HasErrors returns true if there are any validation errors
func (v ValidationErrors) HasErrors() bool {
	return len(v) > 0
}

// ToErrorDetails converts validation errors to error details
func (v ValidationErrors) ToErrorDetails() []ErrorDetail {
	details := make([]ErrorDetail, len(v))
	for i, err := range v {
		details[i] = ErrorDetail{
			Field:   err.Field,
			Message: err.Message,
		}
	}
	return details
}
