package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type mockUserService struct {
	mock.Mock
}

func (m *mockUserService) Register(ctx context.Context, name, email, password, phone string) (*domain.User, error) {
	args := m.Called(ctx, name, email, password, phone)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserService) Login(ctx context.Context, email, password string) (*domain.User, *domain.TokenPair, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*domain.User), args.Get(1).(*domain.TokenPair), args.Error(2)
}

func (m *mockUserService) GetUser(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *mockUserService) UpdateUser(ctx context.Context, id ulid.ULID, name, phone string) error {
	args := m.Called(ctx, id, name, phone)
	return args.Error(0)
}

func (m *mockUserService) ListUsers(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.User), args.Error(1)
}

func TestUserHandler_Register(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockUserService)
	handler := New(mockService, logger)

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
	}{
		{
			name: "successful registration",
			requestBody: map[string]string{
				"name":     "Test User",
				"email":    "test@example.com",
				"password": "password123",
				"phone":    "1234567890",
			},
			mockSetup: func() {
				mockService.On("Register", mock.Anything, "Test User", "test@example.com", "password123", "1234567890").
					Return(&domain.User{
						ID:    domain.MustParseULID("01H9Z7K3Y4D5E6F7G8H9J0K1L2"),
						Name:  "Test User",
						Email: "test@example.com",
						Phone: "1234567890",
					}, nil)
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "invalid credentials",
			requestBody: map[string]string{
				"name": "Test User",
			},
			mockSetup: func() {
				mockService.On("Register", mock.Anything, "Test User", "", "", "").
					Return(nil, nil, domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid request body",
			requestBody: map[string]string{
				"name": "Test User",
				// missing email and password
			},
			mockSetup: func() {
				// No mock setup needed for invalid request body
				// as the handler should return 400 before calling the service
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.HandleRegister(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			if tt.expectedStatus == http.StatusCreated {
				mockService.AssertExpectations(t)
			}
		})
	}
}

func TestUserHandler_Login(t *testing.T) {
	logger, _ := zap.NewProduction()
	mockService := new(mockUserService)
	handler := New(mockService, logger)

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
	}{
		{
			name: "successful login",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "password123",
			},
			mockSetup: func() {
				mockService.On("Login", mock.Anything, "test@example.com", "password123").
					Return(
						&domain.User{
							ID:    domain.MustParseULID("01H9Z7K3Y4D5E6F7G8H9J0K1L2"),
							Name:  "Test User",
							Email: "test@example.com",
						},
						&domain.TokenPair{
							AccessToken:  "access_token",
							RefreshToken: "refresh_token",
						},
						nil,
					)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid credentials",
			requestBody: map[string]string{
				"email":    "test@example.com",
				"password": "wrongpassword",
			},
			mockSetup: func() {
				mockService.On("Login", mock.Anything, "test@example.com", "wrongpassword").
					Return(nil, nil, domain.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/users/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.HandleLogin(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			mockService.AssertExpectations(t)
		})
	}
}
