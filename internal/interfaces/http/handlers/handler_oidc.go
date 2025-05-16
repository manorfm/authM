package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/ipede/user-manager-service/internal/domain"
	httperrors "github.com/ipede/user-manager-service/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

type OIDCHandler struct {
	service domain.OIDCService
	logger  *zap.Logger
}

func NewOIDCHandler(service domain.OIDCService, logger *zap.Logger) *OIDCHandler {
	return &OIDCHandler{
		service: service,
		logger:  logger,
	}
}

func (h *OIDCHandler) GetUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		httperrors.RespondWithError(w, httperrors.ErrCodeAuthentication, "User not authenticated", nil, http.StatusUnauthorized)
		return
	}

	userInfo, err := h.service.GetUserInfo(r.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get user info", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to get user info", nil, http.StatusInternalServerError)
		return
	}

	if userInfo == nil {
		h.logger.Error("User info is nil")
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to get user info", nil, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		h.logger.Error("Failed to encode user info response", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to encode response", nil, http.StatusInternalServerError)
		return
	}
}

func (h *OIDCHandler) GetJWKSHandler(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.service.GetJWKS(r.Context())
	if err != nil {
		h.logger.Error("Failed to get JWKS", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to get JWKS", nil, http.StatusInternalServerError)
		return
	}

	if jwks == nil {
		h.logger.Error("JWKS is nil")
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to get JWKS", nil, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Error("Failed to encode JWKS response", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to encode response", nil, http.StatusInternalServerError)
		return
	}
}

func (h *OIDCHandler) GetOpenIDConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	config, err := h.service.GetOpenIDConfiguration(r.Context())
	if err != nil {
		h.logger.Error("Failed to get OpenID configuration",
			zap.Error(err),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
		)

		if err == domain.ErrInternal {
			httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to get OpenID configuration", nil, http.StatusInternalServerError)
			return
		}

		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to get OpenID configuration", nil, http.StatusInternalServerError)
		return
	}

	if config == nil {
		h.logger.Error("OpenID configuration is nil",
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
		)
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to get OpenID configuration", nil, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		h.logger.Error("Failed to encode OpenID configuration response",
			zap.Error(err),
			zap.String("path", r.URL.Path),
			zap.String("method", r.Method),
		)
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to encode OpenID configuration response", nil, http.StatusInternalServerError)
		return
	}
}

func (h *OIDCHandler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInvalidRequest, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	h.logger.Debug("Received token request",
		zap.String("grant_type", req.GrantType),
		zap.String("code", req.Code),
		zap.String("client_id", req.ClientID))

	var tokens *domain.TokenPair
	var err error

	switch req.GrantType {
	case "authorization_code":
		if req.Code == "" {
			details := []httperrors.ErrorDetail{
				{
					Field:   "code",
					Message: "Authorization code is required",
				},
			}
			httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Validation failed", details, http.StatusBadRequest)
			return
		}
		if req.ClientID == "" || req.ClientSecret == "" {
			details := []httperrors.ErrorDetail{
				{
					Field:   "client_id",
					Message: "Client credentials are required",
				},
			}
			httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Validation failed", details, http.StatusBadRequest)
			return
		}
		tokens, err = h.service.ExchangeCode(r.Context(), req.Code)
		if err != nil {
			h.logger.Error("ExchangeCode failed", zap.Error(err))
			switch err {
			case domain.ErrInvalidCredentials:
				httperrors.RespondWithError(w, httperrors.ErrCodeAuthentication, "Invalid credentials", nil, http.StatusBadRequest)
			case domain.ErrInvalidClient:
				httperrors.RespondWithError(w, httperrors.ErrCodeAuthentication, "Invalid client", nil, http.StatusBadRequest)
			default:
				httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Token exchange failed", nil, http.StatusInternalServerError)
			}
			return
		}
	case "refresh_token":
		if req.RefreshToken == "" {
			details := []httperrors.ErrorDetail{
				{
					Field:   "refresh_token",
					Message: "Refresh token is required",
				},
			}
			httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Validation failed", details, http.StatusBadRequest)
			return
		}
		tokens, err = h.service.RefreshToken(r.Context(), req.RefreshToken)
		if err != nil {
			h.logger.Error("RefreshToken failed", zap.Error(err))
			switch err {
			case domain.ErrInvalidCredentials:
				httperrors.RespondWithError(w, httperrors.ErrCodeAuthentication, "Invalid credentials", nil, http.StatusBadRequest)
			default:
				httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Token refresh failed", nil, http.StatusInternalServerError)
			}
			return
		}
	default:
		details := []httperrors.ErrorDetail{
			{
				Field:   "grant_type",
				Message: "Unsupported grant type",
			},
		}
		httperrors.RespondWithError(w, httperrors.ErrCodeInvalidRequest, "Unsupported grant type", details, http.StatusBadRequest)
		return
	}

	if tokens == nil {
		h.logger.Error("Token exchange returned nil tokens")
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Token exchange failed", nil, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokens); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to encode response", nil, http.StatusInternalServerError)
		return
	}
}

func (h *OIDCHandler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")

	if clientID == "" || redirectURI == "" {
		details := []httperrors.ErrorDetail{
			{
				Field:   "client_id",
				Message: "client_id is required",
			},
			{
				Field:   "redirect_uri",
				Message: "redirect_uri is required",
			},
		}
		httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Validation failed", details, http.StatusBadRequest)
		return
	}

	code, err := h.service.Authorize(r.Context(), clientID, redirectURI, state, scope)
	if err != nil {
		h.logger.Error("Authorization failed", zap.Error(err))
		switch err {
		case domain.ErrInvalidClient:
			httperrors.RespondWithError(w, httperrors.ErrCodeAuthentication, "Invalid client", nil, http.StatusBadRequest)
		default:
			httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Authorization failed", nil, http.StatusInternalServerError)
		}
		return
	}

	http.Redirect(w, r, redirectURI+"?code="+code+"&state="+state, http.StatusFound)
}
