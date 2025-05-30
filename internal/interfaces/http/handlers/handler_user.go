package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/domain"
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
	userID := chi.URLParam(r, "id")
	if userID == "" {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	user, err := h.userService.GetUser(r.Context(), id)
	if err != nil {
		h.logger.Error("failed to get user", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := dto.NewUserResponse(user)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func getQueryParam(r *http.Request, key string, defaultValue int) (int, error) {
	value := r.URL.Query().Get(key)
	if value == "" {
		return defaultValue, nil
	}
	return strconv.Atoi(value)
}

func (h *HandlerUser) ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	limit, err := getQueryParam(r, "limit", 10)
	if err != nil {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	offset, err := getQueryParam(r, "offset", 0)
	if err != nil {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	users, err := h.userService.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("failed to list users", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	response := make([]*dto.UserResponse, len(users))
	for i, user := range users {
		response[i] = dto.NewUserResponse(user)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}
}

func (h *HandlerUser) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if userID == "" {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	id, err := ulid.Parse(userID)
	if err != nil {
		errors.RespondWithError(w, domain.ErrInvalidField)
		return
	}

	var req domain.UpdateUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, domain.ErrInvalidRequestBody)
		return
	}

	if err := h.userService.UpdateUser(r.Context(), id, req.Name, req.Phone); err != nil {
		h.logger.Error("failed to update user", zap.Error(err))
		errors.RespondWithError(w, domain.ErrInternal)
		return
	}

	w.WriteHeader(http.StatusOK)
}
