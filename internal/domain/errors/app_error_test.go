package apperrors

import (
	"errors"
	"testing"
)

func TestAppError(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		wantErr  string
		wantCode string
	}{
		{
			name:     "validation_error",
			err:      NewValidationError("invalid input"),
			wantErr:  "invalid input",
			wantCode: "VALIDATION_ERROR",
		},
		{
			name:     "unauthorized_error",
			err:      NewUnauthorizedError("unauthorized"),
			wantErr:  "unauthorized",
			wantCode: "UNAUTHORIZED",
		},
		{
			name:     "not_found_error",
			err:      NewNotFoundError("not found"),
			wantErr:  "not found",
			wantCode: "NOT_FOUND",
		},
		{
			name:     "conflict_error",
			err:      NewConflictError("conflict"),
			wantErr:  "conflict",
			wantCode: "CONFLICT",
		},
		{
			name:     "internal_error_with_cause",
			err:      NewInternalError("internal error", errors.New("cause")),
			wantErr:  "internal error",
			wantCode: "INTERNAL_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.wantErr {
				t.Errorf("AppError.Error() = %v, want %v", tt.err.Error(), tt.wantErr)
			}
			if tt.err.Code != tt.wantCode {
				t.Errorf("AppError.Code = %v, want %v", tt.err.Code, tt.wantCode)
			}
		})
	}
}
