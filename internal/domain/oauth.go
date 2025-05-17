package domain

import (
	"context"
	"time"
)

// OAuth2Client represents a registered OAuth2 client
type OAuth2Client struct {
	ID           string    `json:"id"`
	Secret       string    `json:"secret"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuthorizationCode represents an OAuth2 authorization code
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	Scopes              []string  `json:"scopes"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
	CodeVerifier        string    `json:"code_verifier"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
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
