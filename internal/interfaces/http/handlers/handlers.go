package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type Handler struct {
	service domain.UserService
	logger  *zap.Logger
}

func New(service domain.UserService, logger *zap.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

func validateRequest(w http.ResponseWriter, r *http.Request, req interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return err
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		http.Error(w, "Validation failed: "+err.Error(), http.StatusBadRequest)
		return err
	}
	return nil
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name" validate:"required"`
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
		Phone    string `json:"phone"`
	}

	if err := validateRequest(w, r, &req); err != nil {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	user, err := h.service.Register(r.Context(), req.Name, req.Email, req.Password, req.Phone)
	if err != nil {
		h.logger.Error("failed to register user", zap.Error(err))
		if err == domain.ErrUserAlreadyExists {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if err := validateRequest(w, r, &req); err != nil {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	user, tokens, err := h.service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.Error("failed to login user", zap.Error(err))
		if err == domain.ErrInvalidCredentials {
			http.Error(w, "Invalid credentials", http.StatusBadRequest)
			return
		}
		http.Error(w, "Failed to login", http.StatusInternalServerError)
		return
	}

	response := struct {
		User   *domain.User      `json:"user"`
		Tokens *domain.TokenPair `json:"tokens"`
	}{
		User:   user,
		Tokens: tokens,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.service.GetUser(r.Context(), domain.ULID(id))
	if err != nil {
		h.logger.Error("failed to get user", zap.Error(err))
		if err == domain.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Name  string `json:"name"`
		Phone string `json:"phone"`
	}

	if err := validateRequest(w, r, &req); err != nil {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateUser(r.Context(), domain.ULID(id), req.Name, req.Phone); err != nil {
		h.logger.Error("failed to update user", zap.Error(err))
		if err == domain.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	limit := 10 // Default limit
	offset := 0 // Default offset

	users, err := h.service.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("failed to list users", zap.Error(err))
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(users); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}
