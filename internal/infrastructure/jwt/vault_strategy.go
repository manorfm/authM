package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
	"github.com/ipede/user-manager-service/internal/domain"
	"go.uber.org/zap"
)

// vaultStrategy implements JWTStrategy using HashiCorp Vault
type vaultStrategy struct {
	client       *api.Client
	config       *domain.VaultConfig
	logger       *zap.Logger
	keyID        string
	lastRotation time.Time
	mu           sync.RWMutex
}

// NewVaultStrategy creates a new Vault strategy for JWT signing
func NewVaultStrategy(config *domain.VaultConfig, logger *zap.Logger) (domain.JWTStrategy, error) {
	if config == nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	// Create Vault client
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.Address

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, domain.ErrInvalidClient
	}

	// Set token
	client.SetToken(config.Token)

	// Create strategy
	strategy := &vaultStrategy{
		client:       client,
		config:       config,
		logger:       logger,
		lastRotation: time.Now(),
	}

	// Apenas carrega o key ID atual sem rotacionar
	if err := strategy.loadCurrentKeyID(); err != nil {
		logger.Error("Failed to load key ID from Vault", zap.Error(err))
		return nil, domain.ErrInvalidKeyConfig
	}

	// // Initialize key ID
	// if err := strategy.RotateKey(); err != nil {
	// 	return nil, domain.ErrInvalidKeyConfig
	// }

	return strategy, nil
}

// Sign signs a JWT token using Vault's transit engine
func (v *vaultStrategy) Sign(claims *domain.Claims) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.client == nil {
		return "", domain.NewJWTError("sign token", domain.ErrInvalidClient)
	}

	// Cria o token sem assinatura
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = v.keyID

	unsignedToken, err := token.SigningString()
	if err != nil {
		v.logger.Error("failed to get signing string", zap.Error(err))
		return "", domain.NewJWTError("sign token", domain.ErrTokenGeneration)
	}

	// Solicita assinatura ao Vault
	signPath := fmt.Sprintf("%s/sign/%s", v.config.MountPath, v.config.KeyName)
	payload := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(unsignedToken)),
	}

	secret, err := v.client.Logical().Write(signPath, payload)
	if err != nil {
		v.logger.Error("failed to sign token with vault", zap.Error(err))
		return "", domain.NewJWTError("sign token", domain.ErrTokenGeneration)
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		v.logger.Error("missing or invalid signature format from Vault")
		return "", domain.NewJWTError("sign token", domain.ErrInvalidSignature)
	}

	// Extrai versão da assinatura no formato "vault:vX:<signature>"
	parts := strings.SplitN(signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		v.logger.Error("unexpected signature format", zap.String("raw_signature", signature))
		return "", domain.NewJWTError("sign token", domain.ErrInvalidSignature)
	}

	version := parts[1]      // Ex: "v18"
	rawSignature := parts[2] // Base64url da assinatura

	// Gera token final: unsignedToken.signature
	decodedSig, err := base64.StdEncoding.DecodeString(rawSignature)
	if err != nil {
		v.logger.Error("failed to decode base64 signature", zap.Error(err))
		return "", domain.NewJWTError("sign token", domain.ErrInvalidSignature)
	}

	signatureB64URL := base64.RawURLEncoding.EncodeToString(decodedSig)
	signedToken := fmt.Sprintf("%s.%s", unsignedToken, signatureB64URL)

	v.logger.Debug("JWT signed with Vault", zap.String("version", version), zap.String("token_id", claims.ID))

	return signedToken, nil
}

// GetPublicKey returns the public key from Vault
func (v *vaultStrategy) GetPublicKey() *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.client == nil {
		v.logger.Error("vault client is nil")
		return nil
	}

	// Get public key from Vault
	path := fmt.Sprintf("%s/keys/%s", v.config.MountPath, v.config.KeyName)
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		v.logger.Error("failed to get public key from vault", zap.Error(err))
		return nil
	}

	// Parse public key
	keyData, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		v.logger.Error("invalid key data from vault", zap.Any("data", secret.Data))
		return nil
	}

	// Get the latest version
	var latestVersion int
	for versionStr := range keyData {
		version, err := strconv.Atoi(versionStr)
		if err == nil && version > latestVersion {
			latestVersion = version
		}
	}

	// Get key info for the latest version
	keyInfo, ok := keyData[strconv.Itoa(latestVersion)].(map[string]interface{})
	if !ok {
		v.logger.Error("invalid key info from vault", zap.Any("key_data", keyData))
		return nil
	}

	publicKeyPEM, ok := keyInfo["public_key"].(string)
	if !ok {
		v.logger.Error("invalid public key from vault", zap.Any("key_info", keyInfo))
		return nil
	}

	// Parse PEM
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		v.logger.Error("failed to decode PEM block")
		return nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		v.logger.Error("failed to parse public key", zap.Error(err))
		return nil
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		v.logger.Error("public key is not RSA")
		return nil
	}

	return rsaPublicKey
}

// GetKeyID returns the current key ID
func (v *vaultStrategy) GetKeyID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keyID
}

// RotateKey rotates the key in Vault
func (v *vaultStrategy) RotateKey() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.client == nil {
		return domain.NewJWTError("rotate key", domain.ErrInvalidClient)
	}

	// Get current key version from Vault
	path := fmt.Sprintf("%s/keys/%s", v.config.MountPath, v.config.KeyName)
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		v.logger.Error("failed to get key info from vault", zap.Error(err))
		return domain.NewJWTError("rotate key", domain.ErrInvalidKeyConfig)
	}

	// Get latest version
	keys, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		v.logger.Error("invalid key data from vault")
		return domain.NewJWTError("rotate key", domain.ErrInvalidKeyConfig)
	}

	// Find the latest version
	var latestVersion int
	for versionStr := range keys {
		version, err := strconv.Atoi(versionStr)
		if err == nil && version > latestVersion {
			latestVersion = version
		}
	}

	// Only rotate if we don't have a key ID or if it's been more than 24 hours
	if v.keyID == "" || time.Since(v.lastRotation) > 24*time.Hour {
		// Rotate key in Vault
		rotatePath := fmt.Sprintf("%s/keys/%s/rotate", v.config.MountPath, v.config.KeyName)
		_, err := v.client.Logical().Write(rotatePath, nil)
		if err != nil {
			v.logger.Error("failed to rotate key in vault", zap.Error(err))
			return domain.NewJWTError("rotate key", domain.ErrInvalidKeyConfig)
		}

		// Update key ID and rotation time
		v.keyID = fmt.Sprintf("vault:v%d", latestVersion+1)
		v.lastRotation = time.Now()
	}

	return nil
}

// GetLastRotation returns the last key rotation time
func (v *vaultStrategy) GetLastRotation() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastRotation
}

// GetAccessDuration returns the access token duration
func (v *vaultStrategy) GetAccessDuration() time.Duration {
	if v.config != nil && v.config.AccessDuration > 0 {
		return v.config.AccessDuration
	}
	return domain.DefaultAccessTokenDuration
}

// GetRefreshDuration returns the refresh token duration
func (v *vaultStrategy) GetRefreshDuration() time.Duration {
	if v.config != nil && v.config.RefreshDuration > 0 {
		return v.config.RefreshDuration
	}
	return domain.DefaultRefreshTokenDuration
}

func (v *vaultStrategy) loadCurrentKeyID() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	path := fmt.Sprintf("%s/keys/%s", v.config.MountPath, v.config.KeyName)
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		v.logger.Error("failed to read key metadata from vault", zap.Error(err))
		return err
	}

	keys, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		v.logger.Error("unexpected Vault key metadata format", zap.Any("data", secret.Data))
		return domain.ErrInvalidKeyConfig
	}

	var latestVersion int
	for versionStr := range keys {
		version, err := strconv.Atoi(versionStr)
		if err == nil && version > latestVersion {
			latestVersion = version
		}
	}

	// Set keyID based on latest version
	v.keyID = fmt.Sprintf("vault:v%d", latestVersion)

	// Extrai creation_time da versão mais recente
	keyInfoRaw, ok := keys[strconv.Itoa(latestVersion)]
	if !ok {
		v.logger.Warn("missing latest version key info", zap.Int("version", latestVersion))
		v.lastRotation = time.Now()
		return nil
	}

	keyInfo, ok := keyInfoRaw.(map[string]interface{})
	if !ok {
		v.logger.Warn("invalid key info type", zap.Any("keyInfoRaw", keyInfoRaw))
		v.lastRotation = time.Now()
		return nil
	}

	creationTimeRaw, ok := keyInfo["creation_time"]
	if !ok {
		v.logger.Warn("missing creation_time field", zap.Any("keyInfo", keyInfo))
		v.lastRotation = time.Now()
		return nil
	}

	creationTimeStr, ok := creationTimeRaw.(string)
	if !ok {
		v.logger.Warn("creation_time field is not string", zap.Any("creation_time", creationTimeRaw))
		v.lastRotation = time.Now()
		return nil
	}

	creationTime, err := time.Parse(time.RFC3339, creationTimeStr)
	if err != nil {
		v.logger.Warn("failed to parse creation_time", zap.String("creation_time", creationTimeStr), zap.Error(err))
		v.lastRotation = time.Now()
		return nil
	}

	v.lastRotation = creationTime
	v.logger.Info("Loaded Vault key ID and last rotation time", zap.String("key_id", v.keyID), zap.Time("last_rotation", v.lastRotation))

	return nil
}

// Verify verifies a JWT token using Vault's transit engine
func (v *vaultStrategy) Verify(tokenString string) (*domain.Claims, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.client == nil {
		return nil, domain.ErrInvalidClient
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		v.logger.Error("Invalid token format")
		return nil, domain.ErrInvalidToken
	}

	// Decodificar o header do token
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		v.logger.Error("Failed to decode JWT header", zap.Error(err))
		return nil, domain.ErrInvalidToken
	}

	// Parse o header JSON para pegar o 'kid'
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		v.logger.Error("Failed to parse JWT header", zap.Error(err))
		return nil, domain.ErrInvalidToken
	}

	// Obter o 'kid' do header
	kid, ok := header["kid"].(string)
	if !ok {
		v.logger.Error("Missing 'kid' in JWT header")
		return nil, domain.ErrInvalidToken
	}

	claims := &domain.Claims{}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		v.logger.Error("Failed to decode payload", zap.Error(err))
		return nil, domain.ErrInvalidToken
	}

	if err := json.Unmarshal(payload, claims); err != nil {
		v.logger.Error("Failed to parse claims", zap.Error(err))
		return nil, domain.ErrInvalidClaims
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		v.logger.Error("Token expired", zap.Time("expires_at", claims.ExpiresAt.Time))
		return nil, domain.ErrTokenExpired
	}

	// Decodifica assinatura (base64url)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		v.logger.Error("Failed to decode signature", zap.Error(err))
		return nil, domain.ErrInvalidSignature
	}

	// Re-encode em base64 padrão para Vault
	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	v.logger.Debug("Verifying token with Vault",
		zap.String("token_id", claims.ID),
		zap.String("subject", claims.Subject))

	path := fmt.Sprintf("%s/verify/%s", v.config.MountPath, v.config.KeyName)
	data := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString([]byte(parts[0] + "." + parts[1])),
		"signature": kid + ":" + encodedSignature,
	}

	secret, err := v.client.Logical().Write(path, data)
	if err != nil {
		v.logger.Error("Failed to verify token with vault", zap.Error(err))
		return nil, domain.ErrInvalidSignature
	}

	valid, ok := secret.Data["valid"].(bool)
	if !ok || !valid {
		v.logger.Error("Invalid token signature")
		return nil, domain.ErrInvalidSignature
	}

	v.logger.Debug("Token verified successfully",
		zap.String("token_id", claims.ID),
		zap.String("subject", claims.Subject))

	return claims, nil
}
