package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/domain"
	infrajwt "github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockAuthService is a mock implementation of domain.AuthService
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
	return args.Get(0).(*domain.TokenPair), args.Error(1)
}

func (m *MockAuthService) GetUserByID(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) UpdateUser(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockAuthService) DeleteUser(ctx context.Context, id ulid.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id ulid.ULID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) AddRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

func (m *MockUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) List(ctx context.Context, offset, limit int) ([]*domain.User, error) {
	args := m.Called(ctx, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.User), args.Error(1)
}

func (m *MockUserRepository) RemoveRole(ctx context.Context, userID ulid.ULID, role string) error {
	args := m.Called(ctx, userID, role)
	return args.Error(0)
}

type MockOAuth2Service struct {
	mock.Mock
}

func (m *MockOAuth2Service) ValidateClient(ctx context.Context, clientID, redirectURI string) (*domain.OAuth2Client, error) {
	args := m.Called(ctx, clientID, redirectURI)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuth2Client), args.Error(1)
}

func (m *MockOAuth2Service) GenerateAuthorizationCode(ctx context.Context, clientID string, userID string, scopes []string) (string, error) {
	args := m.Called(ctx, clientID, userID, scopes)
	return args.String(0), args.Error(1)
}

func (m *MockOAuth2Service) ValidateAuthorizationCode(ctx context.Context, code string) (*domain.OAuth2Client, string, []string, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, "", nil, args.Error(3)
	}
	return args.Get(0).(*domain.OAuth2Client), args.String(1), args.Get(2).([]string), args.Error(3)
}

func getJWTService(t *testing.T) *infrajwt.JWT {
	// 15 minutos = 15 * 60 segundos
	accessDuration := 15 * time.Minute
	// 24 horas = 24 * time.Hour
	refreshDuration := 24 * time.Hour

	jwtService, err := infrajwt.New(accessDuration, refreshDuration)
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
	}
	return jwtService
}

func TestHandleOpenIDConfiguration(t *testing.T) {
	// Setup
	mockAuthService := new(MockAuthService)
	mockUserRepo := new(MockUserRepository)
	jwtService := getJWTService(t)
	oauthService := application.NewOAuth2Service()
	logger := zap.NewNop()

	handler := NewOIDCHandler(
		mockAuthService,
		oauthService,
		jwtService,
		logger,
		mockUserRepo,
	)

	t.Run("successful configuration response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		w := httptest.NewRecorder()

		handler.HandleOpenIDConfiguration(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var config OpenIDConfiguration
		err := json.Unmarshal(w.Body.Bytes(), &config)
		assert.NoError(t, err)

		assert.Equal(t, "http://localhost:8080", config.Issuer)
		assert.Equal(t, "http://localhost:8080/oauth2/authorize", config.AuthorizationEndpoint)
		assert.Equal(t, "http://localhost:8080/oauth2/token", config.TokenEndpoint)
		assert.Equal(t, "http://localhost:8080/oauth2/userinfo", config.UserInfoEndpoint)
		assert.Equal(t, "http://localhost:8080/.well-known/jwks.json", config.JWKSURI)
		assert.Contains(t, config.ResponseTypes, "code")
		assert.Contains(t, config.ResponseTypes, "token")
		assert.Contains(t, config.ResponseTypes, "id_token")
		assert.Contains(t, config.SubjectTypes, "public")
		assert.Contains(t, config.IDTokenSigningAlgs, "RS256")
		assert.Contains(t, config.ScopesSupported, "openid")
		assert.Contains(t, config.ScopesSupported, "profile")
		assert.Contains(t, config.ScopesSupported, "email")
		assert.Contains(t, config.TokenEndpointAuthMethods, "client_secret_basic")
		assert.Contains(t, config.TokenEndpointAuthMethods, "client_secret_post")
		assert.Contains(t, config.ClaimsSupported, "sub")
		assert.Contains(t, config.ClaimsSupported, "iss")
		assert.Contains(t, config.ClaimsSupported, "name")
		assert.Contains(t, config.ClaimsSupported, "email")
	})
}

func TestHandleJWKS(t *testing.T) {
	// Setup
	mockAuthService := new(MockAuthService)
	mockUserRepo := new(MockUserRepository)
	jwtService := getJWTService(t)
	oauthService := application.NewOAuth2Service()
	logger := zap.NewNop()

	handler := NewOIDCHandler(
		mockAuthService,
		oauthService,
		jwtService,
		logger,
		mockUserRepo,
	)

	t.Run("successful JWKS response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()

		handler.HandleJWKS(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response JWKS
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)

		assert.Len(t, response.Keys, 1)

		key := response.Keys[0]
		assert.Equal(t, "RSA", key.Kty)
		assert.Equal(t, "RS256", key.Alg)
		assert.Equal(t, "sig", key.Use)
		assert.NotEmpty(t, key.N)
		assert.NotEmpty(t, key.E)
		assert.NotEmpty(t, key.Kid)
	})
}

func TestHandleAuthorize(t *testing.T) {
	// Setup
	mockAuthService := new(MockAuthService)
	mockUserRepo := new(MockUserRepository)
	jwtService := getJWTService(t)
	oauthService := &MockOAuth2Service{}
	logger := zap.NewNop()

	// Configure OAuth2 service for successful case
	client := &domain.OAuth2Client{
		ID:           "test",
		Secret:       "secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	// Mock ValidateClient
	oauthService.On("ValidateClient", mock.Anything, "test", "http://localhost:3000/callback").Return(client, nil)
	oauthService.On("ValidateClient", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("invalid client"))

	// Mock GenerateAuthorizationCode
	oauthService.On("GenerateAuthorizationCode", mock.Anything, "test", mock.Anything, mock.Anything).Return("auth_code", nil)

	handler := NewOIDCHandler(
		mockAuthService,
		oauthService,
		jwtService,
		logger,
		mockUserRepo,
	)

	t.Run("missing required parameters", func(t *testing.T) {
		testCases := []struct {
			name       string
			query      string
			wantStatus int
			wantBody   string
		}{
			{
				name:       "missing response_type",
				query:      "client_id=test&redirect_uri=http://localhost:3000/callback",
				wantStatus: http.StatusBadRequest,
				wantBody:   "response_type is required",
			},
			{
				name:       "missing client_id",
				query:      "response_type=code&redirect_uri=http://localhost:3000/callback",
				wantStatus: http.StatusBadRequest,
				wantBody:   "client_id is required",
			},
			{
				name:       "missing redirect_uri",
				query:      "response_type=code&client_id=test",
				wantStatus: http.StatusBadRequest,
				wantBody:   "redirect_uri is required",
			},
			{
				name:       "invalid response_type",
				query:      "response_type=invalid&client_id=test&redirect_uri=http://localhost:3000/callback",
				wantStatus: http.StatusBadRequest,
				wantBody:   "invalid response_type",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+tc.query, nil)
				w := httptest.NewRecorder()

				handler.HandleAuthorize(w, req)

				assert.Equal(t, tc.wantStatus, w.Code)
				assert.Contains(t, w.Body.String(), tc.wantBody)
			})
		}
	})

	t.Run("invalid client", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=invalid&redirect_uri=http://localhost:3000/callback", nil)
		w := httptest.NewRecorder()

		handler.HandleAuthorize(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid client")
	})

	t.Run("invalid redirect URI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test&redirect_uri=http://evil.com/callback", nil)
		w := httptest.NewRecorder()

		handler.HandleAuthorize(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid client")
	})

	t.Run("unauthenticated user", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:3000/callback", nil)
		w := httptest.NewRecorder()

		handler.HandleAuthorize(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "/login?redirect=")
	})

	t.Run("authenticated user", func(t *testing.T) {
		// Create a valid token
		userID := ulid.Make()
		tokenPair, err := jwtService.GenerateTokenPair(userID, []string{"user"})
		assert.NoError(t, err)

		claims, err := jwtService.ValidateToken(tokenPair.AccessToken)
		assert.NoError(t, err)
		assert.Equal(t, userID.String(), claims.Subject)

		// Create request with valid token
		req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:3000/callback&state=test_state", nil)
		req.Header.Set("Authorization", "Bearer "+tokenPair.AccessToken)
		w := httptest.NewRecorder()

		// Handle request
		handler.HandleAuthorize(w, req)

		// Assert response
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "http://localhost:3000/callback?state=test_state&code=")

	})
}

func TestHandleToken(t *testing.T) {
	// Setup
	mockAuthService := new(MockAuthService)
	mockUserRepo := new(MockUserRepository)
	jwtService := getJWTService(t)
	oauthService := &MockOAuth2Service{}
	logger := zap.NewNop()

	// Configure OAuth2 service for successful case
	client := &domain.OAuth2Client{
		ID:           "client_id",
		Secret:       "client_secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}
	userID := ulid.Make()
	scopes := []string{"user"}

	// Mock ValidateAuthorizationCode
	oauthService.On("ValidateAuthorizationCode", mock.Anything, "valid_code").Return(client, userID.String(), scopes, nil)
	oauthService.On("ValidateAuthorizationCode", mock.Anything, mock.Anything).Return(nil, "", nil, errors.New("invalid code"))

	// Mock FindByID
	mockUserRepo.On("FindByID", mock.Anything, userID).Return(&domain.User{
		ID:    userID,
		Name:  "Test User",
		Email: "test@example.com",
	}, nil)

	handler := NewOIDCHandler(
		mockAuthService,
		oauthService,
		jwtService,
		logger,
		mockUserRepo,
	)

	// Test cases
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Missing required fields",
			requestBody: TokenRequest{
				GrantType: "authorization_code",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "code is required",
		},
		{
			name: "Invalid grant type",
			requestBody: TokenRequest{
				GrantType:    "invalid",
				Code:         "code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Unsupported grant type",
		},
		{
			name: "Invalid authorization code",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "invalid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid authorization code",
		},
		{
			name: "Invalid client credentials",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "invalid_client",
				ClientSecret: "invalid_secret",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid client credentials",
		},
		{
			name: "Invalid redirect URI",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid_code",
				RedirectURI:  "http://invalid.com/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid redirect URI",
		},
		{
			name: "Successful token exchange",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			// Handle request
			handler.HandleToken(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			} else {
				// For successful case, verify token response
				var response TokenResponse
				err := json.NewDecoder(w.Body).Decode(&response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response.AccessToken)
				assert.Equal(t, "Bearer", response.TokenType)
				assert.Equal(t, 3600, response.ExpiresIn)
				assert.NotEmpty(t, response.RefreshToken)
				assert.NotEmpty(t, response.IDToken)
			}
		})
	}
}

func TestHandleUserInfo(t *testing.T) {
	// Setup
	mockAuthService := new(MockAuthService)
	mockUserRepo := new(MockUserRepository)
	jwtService := getJWTService(t)
	oauthService := &MockOAuth2Service{}
	logger := zap.NewNop()

	// Create a test user
	userID := ulid.Make()
	user := &domain.User{
		ID:    userID,
		Name:  "Test User",
		Email: "test@example.com",
		Phone: "1234567890",
	}

	// Generate a valid token
	tokenPair, err := jwtService.GenerateTokenPair(userID, []string{"user"})
	assert.NoError(t, err)

	// Mock FindByID
	mockUserRepo.On("FindByID", mock.Anything, userID).Return(user, nil)

	handler := NewOIDCHandler(
		mockAuthService,
		oauthService,
		jwtService,
		logger,
		mockUserRepo,
	)

	// Test cases
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Missing access token",
		},
		{
			name:           "Invalid token format",
			authHeader:     "Invalid",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token format",
		},
		{
			name:           "Invalid token",
			authHeader:     "Bearer invalid_token",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token",
		},
		{
			name:           "Successful user info",
			authHeader:     "Bearer " + tokenPair.AccessToken,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			// Handle request
			handler.HandleUserInfo(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			} else {
				// For successful case, verify user info response
				var response map[string]interface{}
				err := json.NewDecoder(w.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, userID.String(), response["sub"])
				assert.Equal(t, user.Name, response["name"])
				assert.Equal(t, user.Email, response["email"])
				assert.Equal(t, user.Phone, response["phone"])
				assert.Equal(t, true, response["email_verified"])
			}
		})
	}
}
