package domain

import "context"

// OAuth2Repository defines the interface for OAuth2 data access
type OAuth2Repository interface {
	// CreateClient creates a new OAuth2 client
	CreateClient(ctx context.Context, client *OAuth2Client) error

	// FindClientByID finds an OAuth2 client by ID
	FindClientByID(ctx context.Context, id string) (*OAuth2Client, error)

	// UpdateClient updates an OAuth2 client
	UpdateClient(ctx context.Context, client *OAuth2Client) error

	// DeleteClient deletes an OAuth2 client
	DeleteClient(ctx context.Context, id string) error

	// ListClients lists all OAuth2 clients
	ListClients(ctx context.Context) ([]*OAuth2Client, error)

	// CreateAuthorizationCode creates a new authorization code
	CreateAuthorizationCode(ctx context.Context, code *AuthorizationCode) error

	// GetAuthorizationCode gets an authorization code by code
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)

	// DeleteAuthorizationCode deletes an authorization code
	DeleteAuthorizationCode(ctx context.Context, code string) error
}
