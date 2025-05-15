package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/ipede/user-manager-service/internal/domain"
	"go.uber.org/zap"
)

type OIDCHandler struct {
	authService domain.AuthService
	logger      *zap.Logger
}

func NewOIDCHandler(authService domain.AuthService, logger *zap.Logger) *OIDCHandler {
	return &OIDCHandler{
		authService: authService,
		logger:      logger,
	}
}

type OpenIDConfiguration struct {
	Issuer                   string   `json:"issuer"`
	AuthorizationEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint            string   `json:"token_endpoint"`
	UserInfoEndpoint         string   `json:"userinfo_endpoint"`
	JWKSURI                  string   `json:"jwks_uri"`
	ResponseTypes            []string `json:"response_types_supported"`
	SubjectTypes             []string `json:"subject_types_supported"`
	IDTokenSigningAlgs       []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported          []string `json:"scopes_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported          []string `json:"claims_supported"`
}

// HandleOpenIDConfiguration handles the OpenID Connect discovery endpoint
func (h *OIDCHandler) HandleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	config := OpenIDConfiguration{
		Issuer:                   "http://localhost:8080",
		AuthorizationEndpoint:    "http://localhost:8080/oauth2/authorize",
		TokenEndpoint:            "http://localhost:8080/oauth2/token",
		UserInfoEndpoint:         "http://localhost:8080/oauth2/userinfo",
		JWKSURI:                  "http://localhost:8080/.well-known/jwks.json",
		ResponseTypes:            []string{"code", "token", "id_token"},
		SubjectTypes:             []string{"public"},
		IDTokenSigningAlgs:       []string{"RS256"},
		ScopesSupported:          []string{"openid", "profile", "email"},
		TokenEndpointAuthMethods: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported:          []string{"sub", "iss", "name", "email"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(config); err != nil {
		h.logger.Error("Failed to encode OpenID configuration", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// HandleJWKS handles the JSON Web Key Set endpoint
func (h *OIDCHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement JWKS endpoint
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// HandleAuthorize handles the OAuth2 authorization endpoint
func (h *OIDCHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement authorization endpoint
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// HandleToken handles the OAuth2 token endpoint
func (h *OIDCHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement token endpoint
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// HandleUserInfo handles the OpenID Connect userinfo endpoint
func (h *OIDCHandler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement userinfo endpoint
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}
