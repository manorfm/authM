package domain

import (
	"context"
	"time"
)

// OAuth2Client represents a registered OAuth2 client
type OAuth2Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// OAuth2Service defines the interface for OAuth2 operations
type OAuth2Service interface {
	// ValidateClient validates if a client exists and if the redirect URI is allowed
	ValidateClient(ctx context.Context, clientID, redirectURI string) (*OAuth2Client, error)

	// GenerateAuthorizationCode generates a new authorization code for the client and user
	GenerateAuthorizationCode(ctx context.Context, clientID, userID string, scopes []string) (string, error)

	// ValidateAuthorizationCode validates an authorization code and returns the associated data
	ValidateAuthorizationCode(ctx context.Context, code string) (*OAuth2Client, string, []string, error)
}
