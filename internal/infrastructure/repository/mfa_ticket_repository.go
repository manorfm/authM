package repository

import (
	"context"

	"github.com/manorfm/authM/internal/domain"
	"github.com/manorfm/authM/internal/infrastructure/database"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// MFATicketRepository implements the MFA ticket repository interface
type MFATicketRepository struct {
	db     *database.Postgres
	logger *zap.Logger
}

// NewMFATicketRepository creates a new MFA ticket repository
func NewMFATicketRepository(db *database.Postgres, logger *zap.Logger) *MFATicketRepository {
	return &MFATicketRepository{
		db:     db,
		logger: logger,
	}
}

// Create creates a new MFA ticket
func (r *MFATicketRepository) Create(ctx context.Context, ticket *domain.MFATicket) error {
	query := `
		INSERT INTO mfa_tickets (id, user_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4)
	`

	err := r.db.Exec(ctx, query,
		ticket.Ticket.String(),
		ticket.User,
		ticket.CreatedAt,
		ticket.ExpiresAt,
	)
	if err != nil {
		r.logger.Error("failed to create MFA ticket",
			zap.String("ticket_id", ticket.Ticket.String()),
			zap.Error(err))
		return domain.ErrDatabaseQuery
	}

	return nil
}

// Get retrieves an MFA ticket by ID
func (r *MFATicketRepository) Get(ctx context.Context, id string) (*domain.MFATicket, error) {
	query := `
		SELECT id, user_id, created_at, expires_at
		FROM mfa_tickets
		WHERE id = $1
	`

	var ticket domain.MFATicket
	err := r.db.QueryRow(ctx, query, id).Scan(
		&ticket.Ticket,
		&ticket.User,
		&ticket.CreatedAt,
		&ticket.ExpiresAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, domain.ErrInvalidMFATicket
		}
		r.logger.Error("failed to get MFA ticket",
			zap.String("ticket_id", id),
			zap.Error(err))
		return nil, domain.ErrDatabaseQuery
	}

	return &ticket, nil
}

// Delete deletes an MFA ticket
func (r *MFATicketRepository) Delete(ctx context.Context, id string) error {
	query := `
		DELETE FROM mfa_tickets
		WHERE id = $1
	`

	err := r.db.Exec(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete MFA ticket",
			zap.String("ticket_id", id),
			zap.Error(err))
		return domain.ErrDatabaseQuery
	}

	return nil
}
