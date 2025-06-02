package domain

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
)

// VerificationCodeRepository defines the interface for verification code operations
type VerificationCodeRepository interface {
	// Create stores a new verification code
	Create(ctx context.Context, code *VerificationCode) error

	// FindByCode finds a verification code by its code value
	FindByCode(ctx context.Context, code string) (*VerificationCode, error)

	// FindByUserIDAndType finds the latest verification code for a user and type
	FindByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType VerificationCodeType) (*VerificationCode, error)

	// DeleteExpired deletes expired verification codes
	DeleteExpired(ctx context.Context, before time.Time) error

	// DeleteByUserIDAndType deletes all verification codes for a user and type
	DeleteByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType VerificationCodeType) error
}
