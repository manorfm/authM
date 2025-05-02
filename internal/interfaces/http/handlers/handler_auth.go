package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ipede/user-manager-service/internal/domain"
	"go.uber.org/zap"
)

type AuthService interface {
	Register(ctx context.Context, name, email, password, phone string) (*domain.User, error)
	Login(ctx context.Context, email, password string) (*domain.TokenPair, error)
}

type HandlerAuth struct {
	authService AuthService
	logger      *zap.Logger
}

func NewAuthHandler(authService AuthService, logger *zap.Logger) *HandlerAuth {
	return &HandlerAuth{
		authService: authService,
		logger:      logger,
	}
}

// func validateRequest(w http.ResponseWriter, r *http.Request, req interface{}) error {
// 	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 		return err
// 	}

// 	var validate = validator.New()
// 	if err := validate.Struct(req); err != nil {
// 		http.Error(w, "Validation failed: "+err.Error(), http.StatusBadRequest)
// 		return err
// 	}
// 	return nil
// }

func (h *HandlerAuth) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Phone    string `json:"phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	_, err := h.authService.Register(r.Context(), req.Name, req.Email, req.Password, req.Phone)
	if err != nil {
		h.logger.Error("failed to register user", zap.Error(err))
		if err == domain.ErrInvalidCredentials {
			http.Error(w, "invalid credentials", http.StatusBadRequest)
			return
		}
		http.Error(w, "failed to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *HandlerAuth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	tokenPair, err := h.authService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.Error("failed to login user", zap.Error(err))
		if err == domain.ErrInvalidCredentials {
			http.Error(w, "invalid credentials", http.StatusBadRequest)
			return
		}
		http.Error(w, "failed to login user", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(tokenPair); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}
