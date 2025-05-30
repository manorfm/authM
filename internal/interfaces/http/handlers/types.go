package handlers

// TokenRequest represents the token request structure
type TokenRequest struct {
	GrantType    string `json:"grantType" validate:"required"`
	Code         string `json:"code"`
	RefreshToken string `json:"refreshToken"`
	ClientID     string `json:"clientId" validate:"required"`
	ClientSecret string `json:"clientSecret" validate:"required"`
	RedirectURI  string `json:"redirectUri"`
	CodeVerifier string `json:"codeVerifier"`
}
