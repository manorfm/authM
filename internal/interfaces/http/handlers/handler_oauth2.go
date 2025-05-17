package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	httperrors "github.com/ipede/user-manager-service/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

// OAuth2ClientRequest represents the request to create/update an OAuth2 client
type OAuth2ClientRequest struct {
	ID           string   `json:"id" validate:"required"`
	Secret       string   `json:"secret" validate:"required"`
	RedirectURIs []string `json:"redirect_uris" validate:"required,min=1"`
	GrantTypes   []string `json:"grant_types" validate:"required,min=1"`
	Scopes       []string `json:"scopes" validate:"required,min=1"`
}

// OAuth2Handler handles OAuth2 client management
type OAuth2Handler struct {
	oauthRepo domain.OAuth2Repository
	logger    *zap.Logger
}

// NewOAuth2Handler creates a new OAuth2Handler
func NewOAuth2Handler(oauthRepo domain.OAuth2Repository, logger *zap.Logger) *OAuth2Handler {
	return &OAuth2Handler{
		oauthRepo: oauthRepo,
		logger:    logger,
	}
}

// CreateClientHandler handles the creation of a new OAuth2 client
func (h *OAuth2Handler) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	var req OAuth2ClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInvalidRequest, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	// Validate request
	if err := validateOAuth2ClientRequest(req); err != nil {
		h.logger.Error("Invalid request", zap.Any("validation_errors", err))
		httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Validation failed", err.ToErrorDetails(), http.StatusBadRequest)
		return
	}

	// Check if client already exists
	existingClient, err := h.oauthRepo.FindClientByID(r.Context(), req.ID)
	if err == nil && existingClient != nil {
		h.logger.Error("Client already exists", zap.String("client_id", req.ID))
		httperrors.RespondWithError(w, httperrors.ErrCodeConflict, "Client already exists", nil, http.StatusConflict)
		return
	}

	// Create OAuth2 client
	client := &domain.OAuth2Client{
		ID:           req.ID,
		Secret:       req.Secret,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		Scopes:       req.Scopes,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Save client to repository
	if err := h.oauthRepo.CreateClient(r.Context(), client); err != nil {
		h.logger.Error("Failed to create OAuth2 client", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to create OAuth2 client", nil, http.StatusInternalServerError)
		return
	}

	h.logger.Info("OAuth2 client created successfully", zap.String("client_id", client.ID))

	// Return created client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(client)
}

// UpdateClientHandler handles updating an existing OAuth2 client
func (h *OAuth2Handler) UpdateClientHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "id")
	if clientID == "" {
		h.logger.Error("Missing client ID in URL")
		httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Client ID is required", nil, http.StatusBadRequest)
		return
	}

	var req OAuth2ClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Error("Failed to decode request body", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInvalidRequest, "Invalid request body", nil, http.StatusBadRequest)
		return
	}

	// Validate request
	if err := validateOAuth2ClientRequest(req); err != nil {
		h.logger.Error("Invalid request", zap.Any("validation_errors", err))
		httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Validation failed", err.ToErrorDetails(), http.StatusBadRequest)
		return
	}

	// Check if client exists
	existingClient, err := h.oauthRepo.FindClientByID(r.Context(), clientID)
	if err != nil {
		h.logger.Error("Failed to find client", zap.String("client_id", clientID), zap.Error(err))
		if err == domain.ErrInvalidClient {
			httperrors.RespondWithError(w, httperrors.ErrCodeNotFound, "Client not found", nil, http.StatusNotFound)
		} else {
			httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to find client", nil, http.StatusInternalServerError)
		}
		return
	}

	// Update client
	existingClient.Secret = req.Secret
	existingClient.RedirectURIs = req.RedirectURIs
	existingClient.GrantTypes = req.GrantTypes
	existingClient.Scopes = req.Scopes
	existingClient.UpdatedAt = time.Now()

	if err := h.oauthRepo.UpdateClient(r.Context(), existingClient); err != nil {
		h.logger.Error("Failed to update OAuth2 client", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to update OAuth2 client", nil, http.StatusInternalServerError)
		return
	}

	h.logger.Info("OAuth2 client updated successfully", zap.String("client_id", clientID))

	// Return updated client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(existingClient)
}

// DeleteClientHandler handles deleting an OAuth2 client
func (h *OAuth2Handler) DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "id")
	if clientID == "" {
		h.logger.Error("Missing client ID in URL")
		httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Client ID is required", nil, http.StatusBadRequest)
		return
	}

	// Check if client exists
	_, err := h.oauthRepo.FindClientByID(r.Context(), clientID)
	if err != nil {
		h.logger.Error("Failed to find client", zap.String("client_id", clientID), zap.Error(err))
		if err == domain.ErrInvalidClient {
			httperrors.RespondWithError(w, httperrors.ErrCodeNotFound, "Client not found", nil, http.StatusNotFound)
		} else {
			httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to find client", nil, http.StatusInternalServerError)
		}
		return
	}

	// Delete client
	if err := h.oauthRepo.DeleteClient(r.Context(), clientID); err != nil {
		h.logger.Error("Failed to delete OAuth2 client", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to delete OAuth2 client", nil, http.StatusInternalServerError)
		return
	}

	h.logger.Info("OAuth2 client deleted successfully", zap.String("client_id", clientID))

	w.WriteHeader(http.StatusNoContent)
}

// ListClientsHandler handles listing all OAuth2 clients
func (h *OAuth2Handler) ListClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients, err := h.oauthRepo.ListClients(r.Context())
	if err != nil {
		h.logger.Error("Failed to list OAuth2 clients", zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeInternal, "Failed to list OAuth2 clients", nil, http.StatusInternalServerError)
		return
	}

	h.logger.Info("Successfully listed OAuth2 clients", zap.Int("count", len(clients)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

// GetClientHandler handles getting a single OAuth2 client
func (h *OAuth2Handler) GetClientHandler(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "id")
	if clientID == "" {
		h.logger.Error("Missing client ID in URL")
		httperrors.RespondWithError(w, httperrors.ErrCodeValidation, "Client ID is required", nil, http.StatusBadRequest)
		return
	}

	client, err := h.oauthRepo.FindClientByID(r.Context(), clientID)
	if err != nil {
		h.logger.Error("Failed to find client", zap.String("client_id", clientID), zap.Error(err))
		httperrors.RespondWithError(w, httperrors.ErrCodeNotFound, "Client ID not found", nil, http.StatusNotFound)
		return
	}

	h.logger.Info("Successfully retrieved OAuth2 client", zap.String("client_id", clientID))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// validateOAuth2ClientRequest validates the OAuth2 client request
func validateOAuth2ClientRequest(req OAuth2ClientRequest) *httperrors.ValidationErrors {
	var errors httperrors.ValidationErrors

	if req.ID == "" {
		errors.Add("id", "Client ID is required")
	}
	if req.Secret == "" {
		errors.Add("secret", "Client secret is required")
	}
	if len(req.RedirectURIs) == 0 {
		errors.Add("redirect_uris", "At least one redirect URI is required")
	}
	if len(req.GrantTypes) == 0 {
		errors.Add("grant_types", "At least one grant type is required")
	}
	if len(req.Scopes) == 0 {
		errors.Add("scopes", "At least one scope is required")
	}

	if errors.HasErrors() {
		return &errors
	}
	return nil
}
