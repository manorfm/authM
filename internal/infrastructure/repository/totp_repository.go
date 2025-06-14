package repository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/manorfm/authM/internal/domain"
	"github.com/manorfm/authM/internal/infrastructure/database"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// TOTPRepository implements the TOTP repository interface
type TOTPRepository struct {
	db     *database.Postgres
	logger *zap.Logger
}

// NewTOTPRepository creates a new TOTP repository
func NewTOTPRepository(db *database.Postgres, logger *zap.Logger) *TOTPRepository {
	return &TOTPRepository{
		db:     db,
		logger: logger,
	}
}

// SaveTOTPSecret saves a TOTP secret for a user
func (r *TOTPRepository) SaveTOTPSecret(ctx context.Context, userID string, secret string) error {
	if secret == "" {
		r.logger.Error("invalid secret")
		return domain.ErrInternal
	}

	query := `
		INSERT INTO totp_secrets (user_id, secret)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE
		SET secret = $2
	`

	err := r.db.Exec(ctx, query, userID, secret)
	if err != nil {
		r.logger.Error("failed to save TOTP secret",
			zap.String("user_id", userID),
			zap.String("query", query),
			zap.String("error_type", fmt.Sprintf("%T", err)),
			zap.Error(err))
		return domain.ErrDatabaseQuery
	}

	return nil
}

// GetTOTPSecret retrieves a TOTP secret for a user
func (r *TOTPRepository) GetTOTPSecret(ctx context.Context, userID string) (string, error) {
	query := `
		SELECT secret
		FROM totp_secrets
		WHERE user_id = $1
	`

	var secret string
	err := r.db.QueryRow(ctx, query, userID).Scan(&secret)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", domain.ErrTOTPNotEnabled
		}
		r.logger.Error("failed to get TOTP secret", zap.Error(err))
		return "", domain.ErrDatabaseQuery
	}

	return secret, nil
}

// SaveBackupCodes saves backup codes for a user
func (r *TOTPRepository) SaveBackupCodes(ctx context.Context, userID string, codes []string) error {
	if len(codes) == 0 {
		r.logger.Error("invalid backup codes")
		return domain.ErrInternal
	}

	// Convert codes to JSON
	data, err := json.Marshal(domain.TOTPBackupCodes{Codes: codes})
	if err != nil {
		r.logger.Error("failed to marshal backup codes", zap.Error(err))
		return domain.ErrDatabaseQuery
	}

	query := `
		INSERT INTO totp_backup_codes (user_id, codes)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE
		SET codes = $2
	`

	err = r.db.Exec(ctx, query, userID, data)
	if err != nil {
		r.logger.Error("failed to save backup codes", zap.String("user_id", userID), zap.Error(err))
		return domain.ErrDatabaseQuery
	}

	return nil
}

// GetBackupCodes retrieves backup codes for a user
func (r *TOTPRepository) GetBackupCodes(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT codes
		FROM totp_backup_codes
		WHERE user_id = $1
	`

	var data []byte
	err := r.db.QueryRow(ctx, query, userID).Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, domain.ErrTOTPNotEnabled
		}
		r.logger.Error("failed to get backup codes", zap.Error(err))
		return nil, domain.ErrDatabaseQuery
	}

	var codes domain.TOTPBackupCodes
	err = json.Unmarshal(data, &codes)
	if err != nil {
		r.logger.Error("failed to unmarshal backup codes", zap.Error(err))
		return nil, domain.ErrDatabaseQuery
	}

	return codes.Codes, nil
}

// MarkBackupCodeAsUsed marks a backup code as used
func (r *TOTPRepository) MarkBackupCodeAsUsed(ctx context.Context, userID string, codeIndex int) error {
	// Get current codes
	codes, err := r.GetBackupCodes(ctx, userID)
	if err != nil {
		return err
	}

	// Validate index
	if codeIndex < 0 || codeIndex >= len(codes) {
		r.logger.Error("invalid code index")
		return domain.ErrDatabaseQuery
	}

	// Mark code as used
	codes[codeIndex] = ""

	// Save updated codes
	return r.SaveBackupCodes(ctx, userID, codes)
}

// DeleteTOTPConfig deletes all TOTP configuration for a user
func (r *TOTPRepository) DeleteTOTPConfig(ctx context.Context, userID string) error {
	// Delete secret
	query := `
		DELETE FROM totp_secrets
		WHERE user_id = $1
	`
	err := r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Error("failed to delete TOTP secret", zap.Error(err))
		return domain.ErrDatabaseQuery
	}

	// Delete backup codes
	query = `
		DELETE FROM totp_backup_codes
		WHERE user_id = $1
	`
	err = r.db.Exec(ctx, query, userID)
	if err != nil {
		r.logger.Error("failed to delete backup codes", zap.Error(err))
		return domain.ErrDatabaseQuery
	}

	return nil
}
