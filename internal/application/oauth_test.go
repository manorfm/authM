package application

import (
	"context"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/stretchr/testify/assert"
)

func TestOAuth2Service_ValidateClient(t *testing.T) {
	service := NewOAuth2Service()

	// Adiciona um cliente customizado para o teste
	service.clients["client123"] = &domain.OAuth2Client{
		ID:           "client123",
		Secret:       "secret",
		RedirectURIs: []string{"http://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	t.Run("successful client validation", func(t *testing.T) {
		client, err := service.ValidateClient(context.Background(), "client123", "http://example.com/callback")
		assert.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "client123", client.ID)
	})

	t.Run("client not found", func(t *testing.T) {
		client, err := service.ValidateClient(context.Background(), "nonexistent", "http://example.com/callback")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Equal(t, ErrClientNotFound, err)
	})

	t.Run("invalid redirect URI", func(t *testing.T) {
		client, err := service.ValidateClient(context.Background(), "client123", "http://malicious.com/callback")
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Equal(t, ErrInvalidRedirectURI, err)
	})
}

func TestOAuth2Service_GenerateAndValidateAuthorizationCode(t *testing.T) {
	service := NewOAuth2Service()
	service.clients["client123"] = &domain.OAuth2Client{
		ID:           "client123",
		Secret:       "secret",
		RedirectURIs: []string{"http://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	userID := "user123"
	scopes := []string{"openid", "profile"}

	code, err := service.GenerateAuthorizationCode(context.Background(), "client123", userID, scopes)
	assert.NoError(t, err)
	assert.NotEmpty(t, code)

	// Validação de código válido
	client, gotUserID, gotScopes, err := service.ValidateAuthorizationCode(context.Background(), code)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "client123", client.ID)
	assert.Equal(t, userID, gotUserID)
	assert.Equal(t, scopes, gotScopes)

	// Código não existe mais (foi consumido)
	client, gotUserID, gotScopes, err = service.ValidateAuthorizationCode(context.Background(), code)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Empty(t, gotUserID)
	assert.Nil(t, gotScopes)
	assert.Equal(t, ErrInvalidCode, err)

	// Código inválido
	client, gotUserID, gotScopes, err = service.ValidateAuthorizationCode(context.Background(), "invalid_code")
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Empty(t, gotUserID)
	assert.Nil(t, gotScopes)
	assert.Equal(t, ErrInvalidCode, err)

	// Código expirado
	code2, err := service.GenerateAuthorizationCode(context.Background(), "client123", userID, scopes)
	assert.NoError(t, err)
	service.codes[code2].Expires = time.Now().Add(-time.Minute)
	client, gotUserID, gotScopes, err = service.ValidateAuthorizationCode(context.Background(), code2)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Empty(t, gotUserID)
	assert.Nil(t, gotScopes)
	assert.Equal(t, ErrInvalidCode, err)
}
