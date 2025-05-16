package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type MockJWT struct {
	mock.Mock
}

func (m *MockJWT) GenerateTokenPair(userID string, roles []string) (*jwt.TokenPair, error) {
	args := m.Called(userID, roles)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.TokenPair), args.Error(1)
}

func (m *MockJWT) ValidateToken(token string) (*jwt.Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.Claims), args.Error(1)
}

func (m *MockJWT) GetJWKS() ([]interface{}, error) {
	args := m.Called()
	return args.Get(0).([]interface{}), args.Error(1)
}

func TestAuthMiddleware_Authenticator(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		mockSetup      func(*MockJWT)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:  "missing token",
			token: "",
			mockSetup: func(m *MockJWT) {
				// No setup needed
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":"ERR_002","message":"Unauthorized"}`,
		},
		{
			name:  "invalid token",
			token: "invalid-token",
			mockSetup: func(m *MockJWT) {
				m.On("ValidateToken", "invalid-token").Return(nil, assert.AnError)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":"ERR_002","message":"Invalid token"}`,
		},
		{
			name:  "valid token",
			token: "valid-token",
			mockSetup: func(m *MockJWT) {
				m.On("ValidateToken", "valid-token").Return(&jwt.Claims{
					Roles: []string{"admin"},
				}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := new(MockJWT)
			tt.mockSetup(mockJWT)

			// Use the mock for the middleware (now accepted as JWTValidator)
			middleware := NewAuthMiddleware(mockJWT, zap.NewNop())

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"message":"success"}`))
			})

			req := httptest.NewRequest("GET", "/", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			w := httptest.NewRecorder()
			middleware.Authenticator(handler).ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.JSONEq(t, tt.expectedBody, w.Body.String())
		})
	}
}

func TestAuthMiddleware_RequireRole(t *testing.T) {
	tests := []struct {
		name           string
		requiredRole   string
		userRoles      []string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "no roles in context",
			requiredRole:   "admin",
			userRoles:      nil,
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"code":"ERR_001","message":"Forbidden"}`,
		},
		{
			name:           "role not found",
			requiredRole:   "admin",
			userRoles:      []string{"user"},
			expectedStatus: http.StatusForbidden,
			expectedBody:   `{"code":"ERR_001","message":"Forbidden"}`,
		},
		{
			name:           "role found",
			requiredRole:   "admin",
			userRoles:      []string{"admin", "user"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a real JWT instance for the middleware
			realJWT, err := jwt.New(15*60, 24*60*60)
			if err != nil {
				t.Fatalf("Failed to create JWT service: %v", err)
			}

			middleware := NewAuthMiddleware(realJWT, zap.NewNop())

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"message":"success"}`))
			})

			req := httptest.NewRequest("GET", "/", nil)
			if tt.userRoles != nil {
				ctx := context.WithValue(req.Context(), "roles", tt.userRoles)
				req = req.WithContext(ctx)
			}

			w := httptest.NewRecorder()
			middleware.RequireRole(tt.requiredRole)(handler).ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.JSONEq(t, tt.expectedBody, w.Body.String())
		})
	}
}

func TestAuthMiddleware_ExtractToken(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedToken string
	}{
		{
			name:          "empty header",
			authHeader:    "",
			expectedToken: "",
		},
		{
			name:          "invalid format",
			authHeader:    "invalid",
			expectedToken: "",
		},
		{
			name:          "valid bearer token",
			authHeader:    "Bearer valid-token",
			expectedToken: "valid-token",
		},
	}

	// Create a real JWT instance for the middleware
	realJWT, err := jwt.New(15*60, 24*60*60)
	if err != nil {
		t.Fatalf("Failed to create JWT service: %v", err)
	}

	middleware := NewAuthMiddleware(realJWT, zap.NewNop())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			token := middleware.extractToken(req)
			assert.Equal(t, tt.expectedToken, token)
		})
	}
}
