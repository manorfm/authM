package repository

import (
	"context"
	"encoding/json"

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
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}

	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return err
	}

	scopes, err := json.Marshal(client.Scopes)
	if err != nil {
		return err
	}

	return r.db.Exec(ctx, `
		INSERT INTO oauth2_clients (id, secret, redirect_uris, grant_types, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, client.ID, client.Secret, redirectURIs, grantTypes, scopes, client.CreatedAt, client.UpdatedAt)
}

func (r *PostgresOAuth2Repository) FindClientByID(ctx context.Context, id string) (*domain.OAuth2Client, error) {
	client := &domain.OAuth2Client{}
	var redirectURIs, grantTypes, scopes []byte

	err := r.db.QueryRow(ctx, `
		SELECT id, secret, redirect_uris, grant_types, scopes, created_at, updated_at
		FROM oauth2_clients WHERE id = $1
	`, id).Scan(&client.ID, &client.Secret, &redirectURIs, &grantTypes, &scopes, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(redirectURIs, &client.RedirectURIs); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(grantTypes, &client.GrantTypes); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(scopes, &client.Scopes); err != nil {
		return nil, err
	}

	return client, nil
}

func (r *PostgresOAuth2Repository) UpdateClient(ctx context.Context, client *domain.OAuth2Client) error {
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}

	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return err
	}

	scopes, err := json.Marshal(client.Scopes)
	if err != nil {
		return err
	}

	return r.db.Exec(ctx, `
		UPDATE oauth2_clients
		SET secret = $1, redirect_uris = $2, grant_types = $3, scopes = $4, updated_at = $5
		WHERE id = $6
	`, client.Secret, redirectURIs, grantTypes, scopes, client.UpdatedAt, client.ID)
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

	var clients []*domain.OAuth2Client
	for rows.Next() {
		client := &domain.OAuth2Client{}
		var redirectURIs, grantTypes, scopes []byte

		err := rows.Scan(&client.ID, &client.Secret, &redirectURIs, &grantTypes, &scopes, &client.CreatedAt, &client.UpdatedAt)
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(redirectURIs, &client.RedirectURIs); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(grantTypes, &client.GrantTypes); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(scopes, &client.Scopes); err != nil {
			return nil, err
		}

		clients = append(clients, client)
	}
	return clients, nil
}

func (r *PostgresOAuth2Repository) CreateAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	scopes, err := json.Marshal(code.Scopes)
	if err != nil {
		return err
	}

	return r.db.Exec(ctx, `
		INSERT INTO authorization_codes (code, client_id, user_id, scopes, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, code.Code, code.ClientID, code.UserID, scopes, code.ExpiresAt, code.CreatedAt)
}

func (r *PostgresOAuth2Repository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	authCode := &domain.AuthorizationCode{}
	var scopes []byte

	err := r.db.QueryRow(ctx, `
		SELECT code, client_id, user_id, scopes, expires_at, created_at
		FROM authorization_codes WHERE code = $1
	`, code).Scan(&authCode.Code, &authCode.ClientID, &authCode.UserID, &scopes, &authCode.ExpiresAt, &authCode.CreatedAt)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(scopes, &authCode.Scopes); err != nil {
		return nil, err
	}

	return authCode, nil
}

func (r *PostgresOAuth2Repository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	return r.db.Exec(ctx, "DELETE FROM authorization_codes WHERE code = $1", code)
}
