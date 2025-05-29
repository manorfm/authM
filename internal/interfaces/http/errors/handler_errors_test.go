package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRespondWithError(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		message        string
		details        []ErrorDetail
		status         int
		expectedBody   ErrorResponse
		expectedStatus int
	}{
		{
			name:    "validation error",
			code:    ErrCodeValidation,
			message: "Validation failed",
			details: []ErrorDetail{
				{
					Field:   "email",
					Message: "email is required",
				},
			},
			status: http.StatusBadRequest,
			expectedBody: ErrorResponse{
				Code:    ErrCodeValidation,
				Message: "Validation failed",
				Details: []ErrorDetail{
					{
						Field:   "email",
						Message: "email is required",
					},
				},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:    "authentication error",
			code:    ErrCodeAuthentication,
			message: "Invalid credentials",
			status:  http.StatusUnauthorized,
			expectedBody: ErrorResponse{
				Code:    ErrCodeAuthentication,
				Message: "Invalid credentials",
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			RespondWithError(w, tt.code, tt.message, tt.details, tt.status)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var response ErrorResponse
			err := json.NewDecoder(w.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)
		})
	}
}

func TestValidationErrors(t *testing.T) {
	t.Run("add validation error", func(t *testing.T) {
		var errors ValidationErrors
		errors.Add("email", "email is required")
		errors.Add("password", "password is required")

		assert.Equal(t, 2, len(errors))
		assert.Equal(t, "email", errors[0].Field)
		assert.Equal(t, "email is required", errors[0].Message)
		assert.Equal(t, "password", errors[1].Field)
		assert.Equal(t, "password is required", errors[1].Message)
	})

	t.Run("has errors", func(t *testing.T) {
		var errors ValidationErrors
		assert.False(t, errors.HasErrors())

		errors.Add("email", "email is required")
		assert.True(t, errors.HasErrors())
	})

	t.Run("to error details", func(t *testing.T) {
		var errors ValidationErrors
		errors.Add("email", "email is required")
		errors.Add("password", "password is required")

		details := errors.ToErrorDetails()
		assert.Equal(t, 2, len(details))
		assert.Equal(t, "email", details[0].Field)
		assert.Equal(t, "email is required", details[0].Message)
		assert.Equal(t, "password", details[1].Field)
		assert.Equal(t, "password is required", details[1].Message)
	})
}
