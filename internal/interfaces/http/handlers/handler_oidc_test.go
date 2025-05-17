package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	infrajwt "github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	httperrors "github.com/ipede/user-manager-service/internal/interfaces/http/errors"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// OpenIDConfiguration represents the OpenID configuration structure
type OpenIDConfiguration struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	ResponseTypes            []string `json:"response_types_supported"`
	SubjectTypes             []string `json:"subject_types_supported"`
	IDTokenSigningAlgs       []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported          []string `json:"scopes_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported          []string `json:"claims_supported"`
}

// JWKS represents the JSON Web Key Set structure
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

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

type mockOIDCService struct {
	mock.Mock
}

func (m *mockOIDCService) GetUserInfo(ctx context.Context, userID string) (map[string]interface{}, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *mockOIDCService) GetJWKS(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *mockOIDCService) GetOpenIDConfiguration(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *mockOIDCService) ExchangeCode(ctx context.Context, code string, codeVerifier string) (*domain.TokenPair, error) {
	args := m.Called(ctx, code, codeVerifier)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenPair), args.Error(1)
}

func (m *mockOIDCService) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.TokenPair), args.Error(1)
}

func (m *mockOIDCService) Authorize(ctx context.Context, clientID, redirectURI, state, scope string) (string, error) {
	args := m.Called(ctx, clientID, redirectURI, state, scope)
	return args.String(0), args.Error(1)
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
	tests := []struct {
		name           string
		mockSetup      func(*mockOIDCService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "successful configuration response",
			mockSetup: func(m *mockOIDCService) {
				m.On("GetOpenIDConfiguration", mock.Anything).Return(map[string]interface{}{
					"issuer":                                "http://localhost:8080",
					"authorization_endpoint":                "http://localhost:8080/oauth2/authorize",
					"token_endpoint":                        "http://localhost:8080/oauth2/token",
					"userinfo_endpoint":                     "http://localhost:8080/oauth2/userinfo",
					"jwks_uri":                              "http://localhost:8080/.well-known/jwks.json",
					"response_types_supported":              []interface{}{"code", "token", "id_token"},
					"subject_types_supported":               []interface{}{"public"},
					"id_token_signing_alg_values_supported": []interface{}{"RS256"},
					"scopes_supported":                      []interface{}{"openid", "profile", "email"},
					"token_endpoint_auth_methods_supported": []interface{}{"client_secret_basic", "client_secret_post"},
					"claims_supported":                      []interface{}{"sub", "iss", "name", "email"},
				}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"issuer":                                "http://localhost:8080",
				"authorization_endpoint":                "http://localhost:8080/oauth2/authorize",
				"token_endpoint":                        "http://localhost:8080/oauth2/token",
				"userinfo_endpoint":                     "http://localhost:8080/oauth2/userinfo",
				"jwks_uri":                              "http://localhost:8080/.well-known/jwks.json",
				"response_types_supported":              []interface{}{"code", "token", "id_token"},
				"subject_types_supported":               []interface{}{"public"},
				"id_token_signing_alg_values_supported": []interface{}{"RS256"},
				"scopes_supported":                      []interface{}{"openid", "profile", "email"},
				"token_endpoint_auth_methods_supported": []interface{}{"client_secret_basic", "client_secret_post"},
				"claims_supported":                      []interface{}{"sub", "iss", "name", "email"},
			},
		},
		{
			name: "service error",
			mockSetup: func(m *mockOIDCService) {
				m.On("GetOpenIDConfiguration", mock.Anything).Return(nil, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"code":    httperrors.ErrCodeInternal,
				"message": "Failed to get OpenID configuration",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := new(mockOIDCService)
			tt.mockSetup(mockService)

			// Create handler with mock service
			handler := NewOIDCHandler(mockService, zap.NewNop())

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
			w := httptest.NewRecorder()

			// Call handler
			handler.GetOpenIDConfigurationHandler(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.NewDecoder(w.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}

func TestHandleJWKS(t *testing.T) {
	tests := []struct {
		name           string
		mockSetup      func(*mockOIDCService)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "successful JWKS response",
			mockSetup: func(m *mockOIDCService) {
				m.On("GetJWKS", mock.Anything).Return(map[string]interface{}{
					"keys": []map[string]interface{}{
						{
							"kty": "RSA",
							"use": "sig",
							"kid": "1",
							"alg": "RS256",
							"n":   "test_n",
							"e":   "test_e",
						},
					},
				}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"keys": []interface{}{
					map[string]interface{}{
						"kty": "RSA",
						"use": "sig",
						"kid": "1",
						"alg": "RS256",
						"n":   "test_n",
						"e":   "test_e",
					},
				},
			},
		},
		{
			name: "service error",
			mockSetup: func(m *mockOIDCService) {
				m.On("GetJWKS", mock.Anything).Return(nil, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"code":    httperrors.ErrCodeInternal,
				"message": "Failed to get JWKS",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := new(mockOIDCService)
			tt.mockSetup(mockService)

			// Create handler with mock service
			handler := NewOIDCHandler(mockService, zap.NewNop())

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
			w := httptest.NewRecorder()

			// Call handler
			handler.GetJWKSHandler(w, req)

			// Assert response
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.NewDecoder(w.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response)

			// Verify mock expectations
			mockService.AssertExpectations(t)
		})
	}
}

func TestHandleAuthorize(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name             string
		queryParams      map[string]string
		mockSetup        func()
		expectedStatus   int
		expectedBody     interface{}
		expectedRedirect string
	}{
		{
			name: "successful authorization",
			queryParams: map[string]string{
				"client_id":             "client123",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
			mockSetup: func() {
				mockService.On("Authorize", mock.Anything, "client123", "http://localhost:3000/callback", "state123", "openid profile").
					Return("auth_code_123", nil)
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "http://localhost:3000/callback?code=auth_code_123&state=state123",
		},
		{
			name: "missing response type",
			queryParams: map[string]string{
				"client_id":    "client123",
				"redirect_uri": "http://localhost:3000/callback",
				"state":        "state123",
				"scope":        "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported response type",
			},
		},
		{
			name: "unsupported response type",
			queryParams: map[string]string{
				"client_id":     "client123",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "token",
				"state":         "state123",
				"scope":         "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported response type",
			},
		},
		{
			name: "missing required parameters",
			queryParams: map[string]string{
				"response_type": "code",
				"state":         "state123",
				"scope":         "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeValidation,
				Message: "Validation failed",
				Details: []httperrors.ErrorDetail{
					{
						Field:   "client_id",
						Message: "client_id is required",
					},
					{
						Field:   "redirect_uri",
						Message: "redirect_uri is required",
					},
				},
			},
		},
		{
			name: "invalid client",
			queryParams: map[string]string{
				"client_id":             "invalid_client",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
			mockSetup: func() {
				mockService.On("Authorize", mock.Anything, "invalid_client", "http://localhost:3000/callback", "state123", "openid profile").
					Return("", domain.ErrInvalidClient)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "Invalid client",
			},
		},
		{
			name: "successful authorization with PKCE",
			queryParams: map[string]string{
				"client_id":             "client123",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
			mockSetup: func() {
				mockService.On("Authorize", mock.Anything, "client123", "http://localhost:3000/callback", "state123", "openid profile").
					Return("auth_code_123", nil)
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "http://localhost:3000/callback?code=auth_code_123&state=state123",
		},
		{
			name: "missing code challenge",
			queryParams: map[string]string{
				"client_id":     "client123",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
				"state":         "state123",
				"scope":         "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "PKCE code challenge is required",
			},
		},
		{
			name: "unsupported code challenge method",
			queryParams: map[string]string{
				"client_id":             "client123",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "unsupported",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported code challenge method",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			// Create request with query parameters
			req := httptest.NewRequest("GET", "/oauth2/authorize", nil)
			q := req.URL.Query()
			for key, value := range tt.queryParams {
				q.Set(key, value)
			}
			req.URL.RawQuery = q.Encode()

			// Add user ID to context
			ctx := context.WithValue(req.Context(), "sub", "user123")
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.AuthorizeHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusFound {
				// Check redirect URL
				location := rr.Header().Get("Location")
				assert.Equal(t, tt.expectedRedirect, location)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(httperrors.ErrorResponse), response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestHandleToken(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name: "Missing required fields",
			requestBody: TokenRequest{
				GrantType: "authorization_code",
			},
			mockSetup: func() {
				// No mock setup needed for validation error
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeValidation,
				Message: "Missing client credentials",
			},
		},
		{
			name: "Invalid grant type",
			requestBody: TokenRequest{
				GrantType:    "invalid",
				Code:         "code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				CodeVerifier: "code_verifier_123",
			},
			mockSetup: func() {
				// No mock setup needed for invalid grant type
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported grant type",
			},
		},
		{
			name: "Missing code verifier",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				// missing code_verifier
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "PKCE is required",
			},
		},
		{
			name: "Invalid authorization code",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "invalid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				CodeVerifier: "code_verifier_123",
			},
			mockSetup: func() {
				mockService.On("ExchangeCode", mock.Anything, "invalid_code", "code_verifier_123").
					Return(nil, domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "Invalid credentials",
			},
		},
		{
			name: "Invalid client credentials",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "invalid_client",
				ClientSecret: "invalid_secret",
				CodeVerifier: "code_verifier_123",
			},
			mockSetup: func() {
				mockService.On("ExchangeCode", mock.Anything, "valid_code", "code_verifier_123").
					Return(nil, domain.ErrInvalidClient)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "Invalid client",
			},
		},
		{
			name: "Invalid PKCE",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				CodeVerifier: "invalid_verifier",
			},
			mockSetup: func() {
				mockService.On("ExchangeCode", mock.Anything, "valid_code", "invalid_verifier").
					Return(nil, domain.ErrInvalidPKCE)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Invalid PKCE",
			},
		},
		{
			name: "Successful token exchange with PKCE",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid_code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "client_id",
				ClientSecret: "client_secret",
				CodeVerifier: "valid_verifier",
			},
			mockSetup: func() {
				mockService.On("ExchangeCode", mock.Anything, "valid_code", "valid_verifier").
					Return(&domain.TokenPair{
						AccessToken:  "access_token_123",
						RefreshToken: "refresh_token_123",
					}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: &domain.TokenPair{
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			req := httptest.NewRequest("POST", "/oauth2/token", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.TokenHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response domain.TokenPair
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(*domain.TokenPair), &response)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(httperrors.ErrorResponse), response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestHandleUserInfo(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name           string
		authHeader     string
		userID         string
		mockSetup      func()
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name:       "user not authenticated",
			authHeader: "",
			userID:     "",
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "User not authenticated",
			},
		},
		{
			name:       "successful user info",
			authHeader: "",
			userID:     "user123",
			mockSetup: func() {
				mockService.On("GetUserInfo", mock.Anything, "user123").
					Return(map[string]interface{}{
						"sub":            "user123",
						"name":           "Test User",
						"email":          "test@example.com",
						"email_verified": true,
					}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"sub":            "user123",
				"name":           "Test User",
				"email":          "test@example.com",
				"email_verified": true,
			},
		},
		{
			name:       "internal server error",
			authHeader: "",
			userID:     "user123",
			mockSetup: func() {
				mockService.On("GetUserInfo", mock.Anything, "user123").
					Return(nil, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInternal,
				Message: "Failed to get user info",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			req := httptest.NewRequest("GET", "/userinfo", nil)
			if tt.userID != "" {
				ctx := context.WithValue(req.Context(), "sub", tt.userID)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			handler.GetUserInfoHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestOIDCHandler_GetUserInfoHandler(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name           string
		userID         string
		mockSetup      func()
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name:   "successful user info retrieval",
			userID: "user123",
			mockSetup: func() {
				mockService.On("GetUserInfo", mock.Anything, "user123").
					Return(map[string]interface{}{
						"sub":            "user123",
						"name":           "Test User",
						"email":          "test@example.com",
						"email_verified": true,
					}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"sub":            "user123",
				"name":           "Test User",
				"email":          "test@example.com",
				"email_verified": true,
			},
		},
		{
			name:   "user not authenticated",
			userID: "",
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "User not authenticated",
			},
		},
		{
			name:   "internal server error",
			userID: "user123",
			mockSetup: func() {
				mockService.On("GetUserInfo", mock.Anything, "user123").
					Return(nil, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInternal,
				Message: "Failed to get user info",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			req := httptest.NewRequest("GET", "/userinfo", nil)
			if tt.userID != "" {
				ctx := context.WithValue(req.Context(), "sub", tt.userID)
				req = req.WithContext(ctx)
			}

			rr := httptest.NewRecorder()
			handler.GetUserInfoHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestOIDCHandler_TokenHandler(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name: "successful authorization code exchange",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "auth_code_123",
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURI:  "http://localhost:3000/callback",
				CodeVerifier: "code_verifier_123",
			},
			mockSetup: func() {
				mockService.On("ExchangeCode", mock.Anything, "auth_code_123", "code_verifier_123").
					Return(&domain.TokenPair{
						AccessToken:  "access_token_123",
						RefreshToken: "refresh_token_123",
					}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: &domain.TokenPair{
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
			},
		},
		{
			name: "successful refresh token exchange",
			requestBody: TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "refresh_token_123",
				ClientID:     "client123",
				ClientSecret: "secret123",
			},
			mockSetup: func() {
				mockService.On("RefreshToken", mock.Anything, "refresh_token_123").
					Return(&domain.TokenPair{
						AccessToken:  "new_access_token_123",
						RefreshToken: "new_refresh_token_123",
					}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: &domain.TokenPair{
				AccessToken:  "new_access_token_123",
				RefreshToken: "new_refresh_token_123",
			},
		},
		{
			name: "missing client credentials",
			requestBody: TokenRequest{
				GrantType: "authorization_code",
				Code:      "auth_code_123",
				// missing client_id and client_secret
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeValidation,
				Message: "Missing client credentials",
			},
		},
		{
			name: "missing authorization code",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				ClientID:     "client123",
				ClientSecret: "secret123",
				// missing code
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeValidation,
				Message: "Missing authorization code",
			},
		},
		{
			name: "missing redirect URI",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "auth_code_123",
				ClientID:     "client123",
				ClientSecret: "secret123",
				// missing redirect_uri
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeValidation,
				Message: "Missing redirect URI",
			},
		},
		{
			name: "missing code verifier",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "auth_code_123",
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURI:  "http://localhost:3000/callback",
				// missing code_verifier
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "PKCE is required",
			},
		},
		{
			name: "invalid authorization code",
			requestBody: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "invalid_code",
				ClientID:     "client123",
				ClientSecret: "secret123",
				RedirectURI:  "http://localhost:3000/callback",
				CodeVerifier: "code_verifier_123",
			},
			mockSetup: func() {
				mockService.On("ExchangeCode", mock.Anything, "invalid_code", "code_verifier_123").
					Return(nil, domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "Invalid credentials",
			},
		},
		{
			name: "invalid refresh token",
			requestBody: TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "invalid_token",
				ClientID:     "client123",
				ClientSecret: "secret123",
			},
			mockSetup: func() {
				mockService.On("RefreshToken", mock.Anything, "invalid_token").
					Return(nil, domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "Invalid credentials",
			},
		},
		{
			name: "unsupported grant type",
			requestBody: TokenRequest{
				GrantType:    "unsupported",
				ClientID:     "client123",
				ClientSecret: "secret123",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported grant type",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			req := httptest.NewRequest("POST", "/oauth2/token", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.TokenHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response domain.TokenPair
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(*domain.TokenPair), &response)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(httperrors.ErrorResponse), response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestOIDCHandler_GetJWKSHandler(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name           string
		mockSetup      func()
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name: "successful JWKS retrieval",
			mockSetup: func() {
				mockService.On("GetJWKS", mock.Anything).
					Return(map[string]interface{}{
						"keys": []interface{}{
							map[string]interface{}{
								"kty": "RSA",
								"alg": "RS256",
								"use": "sig",
								"kid": "1",
								"n":   "test_n",
								"e":   "test_e",
							},
						},
					}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"keys": []interface{}{
					map[string]interface{}{
						"kty": "RSA",
						"alg": "RS256",
						"use": "sig",
						"kid": "1",
						"n":   "test_n",
						"e":   "test_e",
					},
				},
			},
		},
		{
			name: "internal server error",
			mockSetup: func() {
				mockService.On("GetJWKS", mock.Anything).
					Return(nil, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInternal,
				Message: "Failed to get JWKS",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
			rr := httptest.NewRecorder()
			handler.GetJWKSHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestOIDCHandler_GetOpenIDConfigurationHandler(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name           string
		mockSetup      func()
		expectedStatus int
		expectedBody   interface{}
	}{
		{
			name: "successful configuration retrieval",
			mockSetup: func() {
				mockService.On("GetOpenIDConfiguration", mock.Anything).
					Return(map[string]interface{}{
						"issuer":                                "http://localhost:8080",
						"authorization_endpoint":                "http://localhost:8080/oauth2/authorize",
						"token_endpoint":                        "http://localhost:8080/oauth2/token",
						"userinfo_endpoint":                     "http://localhost:8080/oauth2/userinfo",
						"jwks_uri":                              "http://localhost:8080/.well-known/jwks.json",
						"response_types_supported":              []interface{}{"code", "token", "id_token"},
						"subject_types_supported":               []interface{}{"public"},
						"id_token_signing_alg_values_supported": []interface{}{"RS256"},
						"scopes_supported":                      []interface{}{"openid", "profile", "email"},
						"token_endpoint_auth_methods_supported": []interface{}{"client_secret_basic", "client_secret_post"},
						"claims_supported":                      []interface{}{"sub", "iss", "name", "email"},
					}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"issuer":                                "http://localhost:8080",
				"authorization_endpoint":                "http://localhost:8080/oauth2/authorize",
				"token_endpoint":                        "http://localhost:8080/oauth2/token",
				"userinfo_endpoint":                     "http://localhost:8080/oauth2/userinfo",
				"jwks_uri":                              "http://localhost:8080/.well-known/jwks.json",
				"response_types_supported":              []interface{}{"code", "token", "id_token"},
				"subject_types_supported":               []interface{}{"public"},
				"id_token_signing_alg_values_supported": []interface{}{"RS256"},
				"scopes_supported":                      []interface{}{"openid", "profile", "email"},
				"token_endpoint_auth_methods_supported": []interface{}{"client_secret_basic", "client_secret_post"},
				"claims_supported":                      []interface{}{"sub", "iss", "name", "email"},
			},
		},
		{
			name: "internal server error",
			mockSetup: func() {
				mockService.On("GetOpenIDConfiguration", mock.Anything).
					Return(nil, domain.ErrInternal)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInternal,
				Message: "Failed to get OpenID configuration",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
			rr := httptest.NewRecorder()
			handler.GetOpenIDConfigurationHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestOIDCHandler_AuthorizeHandler(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockOIDCService)
	handler := NewOIDCHandler(mockService, logger)

	tests := []struct {
		name             string
		queryParams      map[string]string
		mockSetup        func()
		expectedStatus   int
		expectedBody     interface{}
		expectedRedirect string
	}{
		{
			name: "successful authorization",
			queryParams: map[string]string{
				"client_id":             "client123",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
			mockSetup: func() {
				mockService.On("Authorize", mock.Anything, "client123", "http://localhost:3000/callback", "state123", "openid profile").
					Return("auth_code_123", nil)
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "http://localhost:3000/callback?code=auth_code_123&state=state123",
		},
		{
			name: "missing response type",
			queryParams: map[string]string{
				"client_id":    "client123",
				"redirect_uri": "http://localhost:3000/callback",
				"state":        "state123",
				"scope":        "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported response type",
			},
		},
		{
			name: "unsupported response type",
			queryParams: map[string]string{
				"client_id":     "client123",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "token",
				"state":         "state123",
				"scope":         "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported response type",
			},
		},
		{
			name: "missing required parameters",
			queryParams: map[string]string{
				"response_type": "code",
				"state":         "state123",
				"scope":         "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeValidation,
				Message: "Validation failed",
				Details: []httperrors.ErrorDetail{
					{
						Field:   "client_id",
						Message: "client_id is required",
					},
					{
						Field:   "redirect_uri",
						Message: "redirect_uri is required",
					},
				},
			},
		},
		{
			name: "invalid client",
			queryParams: map[string]string{
				"client_id":             "invalid_client",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
			mockSetup: func() {
				mockService.On("Authorize", mock.Anything, "invalid_client", "http://localhost:3000/callback", "state123", "openid profile").
					Return("", domain.ErrInvalidClient)
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeAuthentication,
				Message: "Invalid client",
			},
		},
		{
			name: "successful authorization with PKCE",
			queryParams: map[string]string{
				"client_id":             "client123",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
			mockSetup: func() {
				mockService.On("Authorize", mock.Anything, "client123", "http://localhost:3000/callback", "state123", "openid profile").
					Return("auth_code_123", nil)
			},
			expectedStatus:   http.StatusFound,
			expectedRedirect: "http://localhost:3000/callback?code=auth_code_123&state=state123",
		},
		{
			name: "missing code challenge",
			queryParams: map[string]string{
				"client_id":     "client123",
				"redirect_uri":  "http://localhost:3000/callback",
				"response_type": "code",
				"state":         "state123",
				"scope":         "openid profile",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "PKCE code challenge is required",
			},
		},
		{
			name: "unsupported code challenge method",
			queryParams: map[string]string{
				"client_id":             "client123",
				"redirect_uri":          "http://localhost:3000/callback",
				"response_type":         "code",
				"state":                 "state123",
				"scope":                 "openid profile",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "unsupported",
			},
			mockSetup: func() {
				// No mock setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: httperrors.ErrorResponse{
				Code:    httperrors.ErrCodeInvalidRequest,
				Message: "Unsupported code challenge method",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock before each test
			mockService.ExpectedCalls = nil
			tt.mockSetup()

			// Create request with query parameters
			req := httptest.NewRequest("GET", "/oauth2/authorize", nil)
			q := req.URL.Query()
			for key, value := range tt.queryParams {
				q.Set(key, value)
			}
			req.URL.RawQuery = q.Encode()

			// Add user ID to context
			ctx := context.WithValue(req.Context(), "sub", "user123")
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.AuthorizeHandler(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusFound {
				// Check redirect URL
				location := rr.Header().Get("Location")
				assert.Equal(t, tt.expectedRedirect, location)
			} else {
				var response httperrors.ErrorResponse
				err := json.NewDecoder(rr.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody.(httperrors.ErrorResponse), response)
			}

			mockService.AssertExpectations(t)
		})
	}
}
