package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	infrajwt "github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

type OIDCHandler struct {
	authService  domain.AuthService
	oauthService domain.OAuth2Service
	jwtService   *infrajwt.JWT
	logger       *zap.Logger
	userRepo     domain.UserRepository
}

func NewOIDCHandler(
	authService domain.AuthService,
	oauthService domain.OAuth2Service,
	jwtService *infrajwt.JWT,
	logger *zap.Logger,
	userRepo domain.UserRepository,
) *OIDCHandler {
	return &OIDCHandler{
		authService:  authService,
		oauthService: oauthService,
		jwtService:   jwtService,
		logger:       logger,
		userRepo:     userRepo,
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

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// HandleJWKS handles the JSON Web Key Set endpoint
func (h *OIDCHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	publicKey := h.jwtService.GetPublicKey()
	if publicKey == nil {
		h.logger.Error("Public key not available")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Convert RSA public key to JWK format
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		Kid: "1", // You might want to generate a unique key ID
		N:   n,
		E:   e,
	}

	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Error("Failed to encode JWKS", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

type AuthorizationRequest struct {
	ResponseType string `json:"response_type"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
}

// HandleAuthorize handles the OAuth2 authorization endpoint
func (h *OIDCHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Parse and validate request parameters
	req := AuthorizationRequest{
		ResponseType: r.URL.Query().Get("response_type"),
		ClientID:     r.URL.Query().Get("client_id"),
		RedirectURI:  r.URL.Query().Get("redirect_uri"),
		Scope:        r.URL.Query().Get("scope"),
		State:        r.URL.Query().Get("state"),
		Nonce:        r.URL.Query().Get("nonce"),
	}

	// Validate required parameters
	if req.ResponseType == "" {
		http.Error(w, "response_type is required", http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if req.RedirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}

	// Validate response_type
	validResponseTypes := map[string]bool{
		"code":     true,
		"token":    true,
		"id_token": true,
	}
	if !validResponseTypes[req.ResponseType] {
		http.Error(w, "invalid response_type", http.StatusBadRequest)
		return
	}

	// Validate client and redirect URI
	client, err := h.oauthService.ValidateClient(r.Context(), req.ClientID, req.RedirectURI)
	if err != nil {
		h.logger.Error("Failed to validate client", zap.Error(err))
		http.Error(w, "Invalid client", http.StatusBadRequest)
		return
	}

	// Check if user is authenticated
	userID, err := h.getAuthenticatedUser(r)
	if err != nil {
		// User is not authenticated, redirect to login page
		loginURL := "/login?redirect=" + r.URL.String()
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Parse scopes
	scopes := strings.Split(req.Scope, " ")
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	// Generate authorization code
	code, err := h.oauthService.GenerateAuthorizationCode(r.Context(), client.ID, userID, scopes)
	if err != nil {
		h.logger.Error("Failed to generate authorization code", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Redirect with authorization code
	redirectURL := req.RedirectURI
	if req.State != "" {
		redirectURL += "?state=" + req.State + "&code=" + code
	} else {
		redirectURL += "?code=" + code
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// getAuthenticatedUser extracts the user ID from the session or token
func (h *OIDCHandler) getAuthenticatedUser(r *http.Request) (string, error) {
	// First try to get from Authorization header
	auth := r.Header.Get("Authorization")
	if auth != "" {
		parts := strings.Split(auth, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			claims, err := h.jwtService.ValidateToken(parts[1])
			if err != nil {
				h.logger.Error("Failed to validate token", zap.Error(err))
				return "", err
			}
			return claims.Subject, nil
		}
	}

	// Then try to get from session cookie
	_, err := r.Cookie("session")
	if err == nil {
		// TODO: Implement session validation
		// For now, return error
		return "", errors.New("not authenticated")
	}

	return "", errors.New("session validation not implemented")
}

// TokenRequest represents the request to exchange an authorization code for tokens
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// TokenResponse represents the response from the token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// HandleToken handles the token endpoint
func (h *OIDCHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate grant type
	if req.GrantType != "authorization_code" {
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Code == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}
	if req.RedirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if req.ClientSecret == "" {
		http.Error(w, "client_secret is required", http.StatusBadRequest)
		return
	}

	// Validate the authorization code
	client, userIDStr, scopes, err := h.oauthService.ValidateAuthorizationCode(r.Context(), req.Code)
	if err != nil {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	// Parse user ID
	userID, err := ulid.Parse(userIDStr)
	if err != nil {
		h.logger.Error("Failed to parse user ID", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Validate client credentials
	if client.ID != req.ClientID || client.Secret != req.ClientSecret {
		http.Error(w, "Invalid client credentials", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == req.RedirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	// Generate tokens
	tokenPair, err := h.jwtService.GenerateTokenPair(userID, scopes)
	if err != nil {
		h.logger.Error("Failed to generate tokens", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate ID token
	idToken, err := h.generateIDToken(userID, client.ID, scopes)
	if err != nil {
		h.logger.Error("Failed to generate ID token", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return tokens
	w.Header().Set("Content-Type", "application/json")
	response := TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: tokenPair.RefreshToken,
		IDToken:      idToken,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// generateIDToken generates an ID token for the user
func (h *OIDCHandler) generateIDToken(userID ulid.ULID, clientID string, scopes []string) (string, error) {
	// Get user information
	user, err := h.userRepo.FindByID(context.Background(), userID)
	if err != nil {
		return "", err
	}

	// Create claims
	claims := jwt.MapClaims{
		"sub":            userID.String(),
		"name":           user.Name,
		"email":          user.Email,
		"phone":          user.Phone,
		"email_verified": true,
		"iss":            "http://localhost:8080",
		"aud":            clientID,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"jti":            ulid.Make().String(),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign token
	return token.SignedString(h.jwtService.GetPrivateKey())
}

// HandleUserInfo handles the OpenID Connect userinfo endpoint
func (h *OIDCHandler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Get access token from Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "Missing access token", http.StatusUnauthorized)
		return
	}

	// Validate Bearer token format
	parts := strings.Split(auth, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid token format", http.StatusUnauthorized)
		return
	}

	// Validate token
	claims, err := h.jwtService.ValidateToken(parts[1])
	if err != nil {
		h.logger.Error("Failed to validate token", zap.Error(err))
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Parse user ID
	userID, err := ulid.Parse(claims.Subject)
	if err != nil {
		h.logger.Error("Failed to parse user ID", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get user information
	user, err := h.userRepo.FindByID(r.Context(), userID)
	if err != nil {
		h.logger.Error("Failed to get user", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return user information
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":            userID.String(),
		"name":           user.Name,
		"email":          user.Email,
		"phone":          user.Phone,
		"email_verified": true,
	})
}
