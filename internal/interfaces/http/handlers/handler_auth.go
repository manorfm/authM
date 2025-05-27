package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

type HandlerAuth struct {
	authService domain.AuthService
	logger      *zap.Logger
}

func NewAuthHandler(authService domain.AuthService, logger *zap.Logger) *HandlerAuth {
	return &HandlerAuth{
		authService: authService,
		logger:      logger,
	}
}

func (h *HandlerAuth) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateUserRequest

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, errors.ErrCodeInvalidRequest, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	user, err := h.authService.Register(r.Context(), req.Name, req.Email, req.Password, req.Phone)
	if err != nil {
		h.logger.Error("failed to register user", zap.Error(err))
		if err == domain.ErrInvalidCredentials {
			errors.RespondWithError(w, errors.ErrCodeAuthentication, "Invalid credentials", nil, http.StatusBadRequest)
			return
		}
		if err == domain.ErrUserAlreadyExists {
			errors.RespondWithError(w, errors.ErrCodeConflict, "User already exists", nil, http.StatusConflict)
			return
		}
		errors.RespondWithError(w, errors.ErrCodeInternal, "Failed to register user", nil, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

func (h *HandlerAuth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, errors.ErrCodeInvalidRequest, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	var validate = validator.New()
	if err := validate.Struct(req); err != nil {
		createErrorMessage(w, err)
		return
	}

	tokenPair, err := h.authService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.Error("failed to login user", zap.Error(err))
		if err == domain.ErrInvalidCredentials {
			errors.RespondWithError(w, errors.ErrCodeAuthentication, "Invalid credentials", nil, http.StatusBadRequest)
			return
		}
		if err == domain.ErrUserNotFound {
			errors.RespondWithError(w, errors.ErrCodeNotFound, "User not found", nil, http.StatusNotFound)
			return
		}
		errors.RespondWithError(w, errors.ErrCodeInternal, "Failed to login user", nil, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenPair); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
		errors.RespondWithError(w, errors.ErrCodeInternal, "Failed to encode response", nil, http.StatusInternalServerError)
		return
	}
}

func createErrorMessage(w http.ResponseWriter, err error) {
	var details []errors.ErrorDetail
	for _, fe := range err.(validator.ValidationErrors) {
		details = append(details, errors.ErrorDetail{
			Field:   fe.Field(),
			Message: validationMessage(fe),
		})
	}

	errors.RespondWithError(w, errors.ErrCodeValidation, "Validation error", details, http.StatusBadRequest)
}

func validationMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fe.Field() + " is required"
	case "email":
		return "Invalid email format"
	case "min":
		return fe.Field() + " must be at least " + fe.Param() + " long"
	default:
		return fe.Field() + " is invalid"
	}
}
