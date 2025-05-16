package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/interfaces/http/dto"
	"github.com/ipede/user-manager-service/internal/interfaces/http/errors"
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

func (h *HandlerUser) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if userID == "" {
		errors.RespondWithError(w, errors.ErrCodeValidation, "user ID is required", nil, http.StatusBadRequest)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		errors.RespondWithError(w, errors.ErrCodeValidation, "invalid user ID", nil, http.StatusBadRequest)
		return
	}

	user, err := h.userService.GetUser(r.Context(), id)
	if err != nil {
		h.logger.Error("failed to get user", zap.Error(err))
		errors.RespondWithError(w, errors.ErrCodeInternal, "failed to get user", nil, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := dto.NewUserResponse(user)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, errors.ErrCodeInternal, "failed to encode response", nil, http.StatusInternalServerError)
		return
	}
}

func (h *HandlerUser) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	limit := 10
	offset := 0

	users, err := h.userService.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("failed to list users", zap.Error(err))
		errors.RespondWithError(w, errors.ErrCodeInternal, "failed to list users", nil, http.StatusInternalServerError)
		return
	}

	response := make([]*dto.UserResponse, len(users))
	for i, user := range users {
		response[i] = dto.NewUserResponse(user)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, errors.ErrCodeInternal, "failed to encode response", nil, http.StatusInternalServerError)
		return
	}
}

func (h *HandlerUser) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if userID == "" {
		errors.RespondWithError(w, errors.ErrCodeValidation, "user ID is required", nil, http.StatusBadRequest)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		errors.RespondWithError(w, errors.ErrCodeValidation, "invalid user ID", nil, http.StatusBadRequest)
		return
	}

	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Phone string `json:"phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, errors.ErrCodeInvalidRequest, "invalid request body", nil, http.StatusBadRequest)
		return
	}

	if err := h.userService.UpdateUser(r.Context(), id, req.Name, req.Email); err != nil {
		h.logger.Error("failed to update user", zap.Error(err))
		errors.RespondWithError(w, errors.ErrCodeInternal, "failed to update user", nil, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
