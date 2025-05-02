package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/interfaces/http/dto"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type HandlerUser struct {
	userService *application.UserService
	logger      *zap.Logger
}

func NewUserHandler(userService *application.UserService, logger *zap.Logger) *HandlerUser {
	return &HandlerUser{
		userService: userService,
		logger:      logger,
	}
}

func (h *HandlerUser) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		http.Error(w, "user ID is required", http.StatusBadRequest)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.userService.GetUser(r.Context(), id)
	if err != nil {
		h.logger.Error("failed to get user", zap.Error(err))
		http.Error(w, "failed to get user", http.StatusInternalServerError)
		return
	}

	response := dto.NewUserResponse(user)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerUser) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	// Default values for pagination
	limit := 10
	offset := 0

	users, err := h.userService.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("failed to list users", zap.Error(err))
		http.Error(w, "failed to list users", http.StatusInternalServerError)
		return
	}

	response := make([]*dto.UserResponse, len(users))
	for i, user := range users {
		response[i] = dto.NewUserResponse(user)
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *HandlerUser) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		http.Error(w, "user ID is required", http.StatusBadRequest)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	var updateUser struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateUser); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.userService.UpdateUser(r.Context(), id, updateUser.Name, updateUser.Email); err != nil {
		h.logger.Error("failed to update user", zap.Error(err))
		http.Error(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
