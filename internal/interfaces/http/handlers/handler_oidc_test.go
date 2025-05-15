package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, name, email, password, phone string) (*domain.User, error) {
	args := m.Called(ctx, name, email, password, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, email, password string) (*domain.TokenPair, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(1).(*domain.TokenPair), args.Error(1)
}

func TestHandleOpenIDConfiguration(t *testing.T) {
	// Setup
	logger, _ := zap.NewDevelopment()
	mockAuthService := new(MockAuthService)
	handler := NewOIDCHandler(mockAuthService, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	// Execute request
	handler.HandleOpenIDConfiguration(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var config OpenIDConfiguration
	err := json.NewDecoder(w.Body).Decode(&config)
	assert.NoError(t, err)

	// Verify configuration values
	assert.Equal(t, "http://localhost:8080", config.Issuer)
	assert.Equal(t, "http://localhost:8080/oauth2/authorize", config.AuthorizationEndpoint)
	assert.Equal(t, "http://localhost:8080/oauth2/token", config.TokenEndpoint)
	assert.Equal(t, "http://localhost:8080/oauth2/userinfo", config.UserInfoEndpoint)
	assert.Equal(t, "http://localhost:8080/.well-known/jwks.json", config.JWKSURI)
	assert.Contains(t, config.ResponseTypes, "code")
	assert.Contains(t, config.ScopesSupported, "openid")
}

func TestHandleJWKS(t *testing.T) {
	// Setup
	logger, _ := zap.NewDevelopment()
	mockAuthService := new(MockAuthService)
	handler := NewOIDCHandler(mockAuthService, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	// Execute request
	handler.HandleJWKS(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleAuthorize(t *testing.T) {
	// Setup
	logger, _ := zap.NewDevelopment()
	mockAuthService := new(MockAuthService)
	handler := NewOIDCHandler(mockAuthService, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/oauth2/authorize", nil)
	w := httptest.NewRecorder()

	// Execute request
	handler.HandleAuthorize(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleToken(t *testing.T) {
	// Setup
	logger, _ := zap.NewDevelopment()
	mockAuthService := new(MockAuthService)
	handler := NewOIDCHandler(mockAuthService, logger)

	// Create test request
	req := httptest.NewRequest("POST", "/oauth2/token", nil)
	w := httptest.NewRecorder()

	// Execute request
	handler.HandleToken(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleUserInfo(t *testing.T) {
	// Setup
	logger, _ := zap.NewDevelopment()
	mockAuthService := new(MockAuthService)
	handler := NewOIDCHandler(mockAuthService, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/oauth2/userinfo", nil)
	w := httptest.NewRecorder()

	// Execute request
	handler.HandleUserInfo(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}
