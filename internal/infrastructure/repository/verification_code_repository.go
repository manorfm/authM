package repository

import (
	"context"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type VerificationCodeRepository struct {
	logger *zap.Logger
	db     *database.Postgres
}

func NewVerificationCodeRepository(db *database.Postgres, logger *zap.Logger) *VerificationCodeRepository {
	return &VerificationCodeRepository{
		db:     db,
		logger: logger,
	}
}

func (r *VerificationCodeRepository) Create(ctx context.Context, code *domain.VerificationCode) error {
	return r.db.Exec(ctx, `
		INSERT INTO verification_codes (id, user_id, code, type, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, code.ID.String(), code.UserID.String(), code.Code, code.Type, code.ExpiresAt, code.CreatedAt)
}

func (r *VerificationCodeRepository) FindByCode(ctx context.Context, code string) (*domain.VerificationCode, error) {
	verificationCode := &domain.VerificationCode{}
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, code, type, expires_at, created_at
		FROM verification_codes
		WHERE code = $1
	`, code).Scan(
		&verificationCode.ID,
		&verificationCode.UserID,
		&verificationCode.Code,
		&verificationCode.Type,
		&verificationCode.ExpiresAt,
		&verificationCode.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to find verification code", zap.Error(err))
		return nil, domain.ErrInvalidVerificationCode
	}
	return verificationCode, nil
}

func (r *VerificationCodeRepository) FindByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType domain.VerificationCodeType) (*domain.VerificationCode, error) {
	verificationCode := &domain.VerificationCode{}
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, code, type, expires_at, created_at
		FROM verification_codes
		WHERE user_id = $1 AND type = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, userID.String(), codeType).Scan(
		&verificationCode.ID,
		&verificationCode.UserID,
		&verificationCode.Code,
		&verificationCode.Type,
		&verificationCode.ExpiresAt,
		&verificationCode.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to find verification code by user and type", zap.Error(err))
		return nil, domain.ErrInvalidVerificationCode
	}
	return verificationCode, nil
}

func (r *VerificationCodeRepository) DeleteExpired(ctx context.Context, before time.Time) error {
	return r.db.Exec(ctx, `
		DELETE FROM verification_codes
		WHERE expires_at < $1
	`, before)
}

func (r *VerificationCodeRepository) DeleteByUserIDAndType(ctx context.Context, userID ulid.ULID, codeType domain.VerificationCodeType) error {
	return r.db.Exec(ctx, `
		DELETE FROM verification_codes
		WHERE user_id = $1 AND type = $2
	`, userID.String(), codeType)
}
