package repository

import (
	"context"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"go.uber.org/zap"
)

// PostgresOAuth2Repository implements OAuth2Repository using PostgreSQL
type PostgresOAuth2Repository struct {
	db     *database.Postgres
	logger *zap.Logger
}

// NewOAuth2Repository creates a new PostgresOAuth2Repository
func NewOAuth2Repository(db *database.Postgres, logger *zap.Logger) domain.OAuth2Repository {
	return &PostgresOAuth2Repository{
		db:     db,
		logger: logger,
	}
}

func (r *PostgresOAuth2Repository) CreateClient(ctx context.Context, client *domain.OAuth2Client) error {
	return r.db.Exec(ctx, `
		INSERT INTO oauth2_clients (id, secret, redirect_uris, grant_types, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, client.ID, client.Secret, client.RedirectURIs, client.GrantTypes, client.Scopes, client.CreatedAt, client.UpdatedAt)
}

func (r *PostgresOAuth2Repository) FindClientByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	client := &domain.OAuth2Client{}

	err := r.db.QueryRow(ctx, `
		SELECT id, secret, redirect_uris, grant_types, scopes, created_at, updated_at
		FROM oauth2_clients WHERE id = $1
	`, id).Scan(&client.ID, &client.Secret, &client.RedirectURIs, &client.GrantTypes, &client.Scopes, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to find client by id", zap.Error(err))
		return nil, domain.ErrClientNotFound
	}

	return client, nil
}

func (r *PostgresOAuth2Repository) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {

	return r.db.Exec(ctx, `
		UPDATE oauth2_clients
		SET secret = $1, redirect_uris = $2, grant_types = $3, scopes = $4, updated_at = $5
		WHERE id = $6
	`, client.Secret, client.RedirectURIs, client.GrantTypes, client.Scopes, client.UpdatedAt, client.ID)
}

func (r *PostgresOAuth2Repository) DeleteClient(ctx context.Context, id string) error {
	return r.db.Exec(ctx, "DELETE FROM oauth2_clients WHERE id = $1", id)
}

func (r *PostgresOAuth2Repository) ListClients(ctx context.Context) ([]*domain.OAuth2Client, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, secret, redirect_uris, grant_types, scopes, created_at, updated_at
		FROM oauth2_clients
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clients := make([]*domain.OAuth2Client, 0)
	for rows.Next() {
		client := &domain.OAuth2Client{}

		err := rows.Scan(&client.ID, &client.Secret, &client.RedirectURIs, &client.GrantTypes, &client.Scopes, &client.CreatedAt, &client.UpdatedAt)
		if err != nil {
			return nil, err
		}

		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		r.logger.Error("Error scanning rows", zap.Error(err))
		return nil, err
	}

	return clients, nil
}

func (r *PostgresOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	return r.db.Exec(ctx, `
		INSERT INTO authorization_codes (code, client_id, user_id, scopes, expires_at, created_at, code_verifier, code_challenge, code_challenge_method)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, code.Code, code.ClientID, code.UserID, code.Scopes, code.ExpiresAt, code.CreatedAt, code.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod)
}

func (r *PostgresOAuth2Repository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	authCode := &domain.AuthorizationCode{}

	err := r.db.QueryRow(ctx, `
		SELECT code, client_id, user_id, scopes, expires_at, created_at, code_verifier, code_challenge, code_challenge_method
		FROM authorization_codes WHERE code = $1
	`, code).Scan(&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.Scopes, &authCode.ExpiresAt, &authCode.CreatedAt, &authCode.CodeVerifier, &authCode.CodeChallenge, &authCode.CodeChallengeMethod)
	if err != nil {
		r.logger.Error("failed to get authorization code", zap.Error(err))
		return nil, domain.ErrInvalidAuthorizationCode
	}

	return authCode, nil
}

func (r *PostgresOAuth2Repository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	return r.db.Exec(ctx, "DELETE FROM authorization_codes WHERE code = $1", code)
}
