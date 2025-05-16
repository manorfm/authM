package handlers

import (
	"encoding/json"
	"net/http"

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

func (h *HandlerAuth) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Phone    string `json:"phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, errors.ErrCodeInvalidRequest, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	var validationErrors errors.ValidationErrors
	if req.Email == "" {
		validationErrors.Add("email", "Email is required")
	}
	if req.Password == "" {
		validationErrors.Add("password", "Password is required")
	}
	if req.Name == "" {
		validationErrors.Add("name", "Name is required")
	}
	if req.Phone == "" {
		validationErrors.Add("phone", "Phone is required")
	}

	if validationErrors.HasErrors() {
		errors.RespondWithError(w, errors.ErrCodeValidation, "Validation error", validationErrors.ToErrorDetails(), http.StatusBadRequest)
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
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.RespondWithError(w, errors.ErrCodeInvalidRequest, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	var validationErrors errors.ValidationErrors
	if req.Email == "" {
		validationErrors.Add("email", "email is required")
	}
	if req.Password == "" {
		validationErrors.Add("password", "password is required")
	}

	if validationErrors.HasErrors() {
		errors.RespondWithError(w, errors.ErrCodeValidation, "Validation failed", validationErrors.ToErrorDetails(), http.StatusBadRequest)
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
