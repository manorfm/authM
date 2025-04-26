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
			wantCode: "VALIDATION",
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
			wantErr:  "internal error: cause",
			wantCode: "INTERNAL",
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

func TestErrorTypeChecks(t *testing.T) {
	tests := []struct {
		name string
		err  *AppError
		want bool
	}{
		{
			name: "is_validation_error",
			err:  NewValidationError("test"),
			want: true,
		},
		{
			name: "is_unauthorized_error",
			err:  NewUnauthorizedError("test"),
			want: true,
		},
		{
			name: "is_not_found_error",
			err:  NewNotFoundError("test"),
			want: true,
		},
		{
			name: "is_conflict_error",
			err:  NewConflictError("test"),
			want: true,
		},
		{
			name: "is_internal_error",
			err:  NewInternalError("test", nil),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "is_validation_error":
				if IsValidationError(tt.err) != tt.want {
					t.Errorf("IsValidationError() = %v, want %v", IsValidationError(tt.err), tt.want)
				}
			case "is_unauthorized_error":
				if IsUnauthorizedError(tt.err) != tt.want {
					t.Errorf("IsUnauthorizedError() = %v, want %v", IsUnauthorizedError(tt.err), tt.want)
				}
			case "is_not_found_error":
				if IsNotFoundError(tt.err) != tt.want {
					t.Errorf("IsNotFoundError() = %v, want %v", IsNotFoundError(tt.err), tt.want)
				}
			case "is_conflict_error":
				if IsConflictError(tt.err) != tt.want {
					t.Errorf("IsConflictError() = %v, want %v", IsConflictError(tt.err), tt.want)
				}
			case "is_internal_error":
				if IsInternalError(tt.err) != tt.want {
					t.Errorf("IsInternalError() = %v, want %v", IsInternalError(tt.err), tt.want)
				}
			}
		})
	}
}
