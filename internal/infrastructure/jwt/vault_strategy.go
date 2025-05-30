package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/api"
	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"go.uber.org/zap"
)

// vaultStrategy implements JWTStrategy using HashiCorp Vault
type vaultStrategy struct {
	client       *api.Client
	config       *config.Config
	logger       *zap.Logger
	keyID        string
	lastRotation time.Time
	mu           sync.RWMutex
}

// NewVaultStrategy creates a new Vault strategy for JWT signing
func NewVaultStrategy(config *config.Config, logger *zap.Logger) (domain.JWTStrategy, error) {
	if config == nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	// Create Vault client
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.VaultAddress

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, domain.ErrInvalidClient
	}

	// Set token
	client.SetToken(config.VaultToken)

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

	// Initialize key ID
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
		return "", domain.ErrInvalidClient
	}

	// Cria o token sem assinatura
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = v.keyID

	unsignedToken, err := token.SigningString()
	if err != nil {
		v.logger.Error("failed to get signing string", zap.Error(err))
		return "", domain.ErrTokenGeneration
	}

	// Solicita assinatura ao Vault
	signature, err := v.signWithVault(unsignedToken)
	if err != nil {
		return "", err
	}

	// Gera token final: unsignedToken.signature
	signedToken := fmt.Sprintf("%s.%s", unsignedToken, signature)

	v.logger.Debug("JWT signed with Vault",
		zap.String("token_id", claims.ID),
		zap.String("signed_token", signedToken))

	return signedToken, nil
}

// signWithVault solicita assinatura ao Vault
func (v *vaultStrategy) signWithVault(input string) (string, error) {
	signPath := fmt.Sprintf("%s/sign/%s", v.config.VaultMountPath, v.config.VaultKeyName)
	payload := v.getVaultPayload(base64.StdEncoding.EncodeToString([]byte(input)))

	secret, err := v.client.Logical().Write(signPath, payload)
	if err != nil {
		v.logger.Error("failed to sign token with vault", zap.Error(err))
		return "", domain.ErrTokenGeneration
	}

	signature, ok := secret.Data["signature"].(string)
	if !ok {
		v.logger.Error("missing or invalid signature format from Vault")
		return "", domain.ErrInvalidSignature
	}

	// Extrai versão da assinatura no formato "vault:vX:<signature>"
	parts := strings.SplitN(signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		v.logger.Error("unexpected signature format", zap.String("raw_signature", signature))
		return "", domain.ErrInvalidSignature
	}

	// Decodifica a assinatura do Vault
	decodedSig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		v.logger.Error("failed to decode base64 signature", zap.Error(err))
		return "", domain.ErrInvalidSignature
	}

	// Converte para base64url sem padding
	return base64.RawURLEncoding.EncodeToString(decodedSig), nil
}

// getVaultPayload retorna o payload padrão para operações do Vault
func (v *vaultStrategy) getVaultPayload(input string) map[string]interface{} {
	return map[string]interface{}{
		"input":                input,
		"algorithm":            "sha2-256",
		"prehashed":            false,
		"marshaling_algorithm": "asn1",
		"signature_algorithm":  "pkcs1v15",
	}
}

// parseTokenParts divide o token em suas partes e valida o formato
func (v *vaultStrategy) parseTokenParts(tokenString string) ([]string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		v.logger.Error("Invalid token format")
		return nil, domain.ErrInvalidToken
	}
	return parts, nil
}

// decodeTokenHeader decodifica e valida o header do token
func (v *vaultStrategy) decodeTokenHeader(headerB64 string) (map[string]interface{}, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		v.logger.Error("Failed to decode JWT header", zap.Error(err))
		return nil, domain.ErrInvalidToken
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		v.logger.Error("Failed to parse JWT header", zap.Error(err))
		return nil, domain.ErrInvalidToken
	}

	if _, ok := header["kid"].(string); !ok {
		v.logger.Error("Missing 'kid' in JWT header")
		return nil, domain.ErrInvalidToken
	}

	return header, nil
}

// decodeTokenPayload decodifica e valida o payload do token
func (v *vaultStrategy) decodeTokenPayload(payloadB64 string) (*domain.Claims, error) {
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		v.logger.Error("Failed to decode payload", zap.Error(err))
		return nil, domain.ErrInvalidToken
	}

	claims := &domain.Claims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		v.logger.Error("Failed to parse claims", zap.Error(err))
		return nil, domain.ErrInvalidClaims
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		v.logger.Error("Token expired", zap.Time("expires_at", claims.ExpiresAt.Time))
		return nil, domain.ErrTokenExpired
	}

	return claims, nil
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
	path := fmt.Sprintf("%s/keys/%s", v.config.VaultMountPath, v.config.VaultKeyName)
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

	latestVersion, ok := secret.Data["latest_version"].(json.Number)
	if !ok {
		v.logger.Error("invalid key data from vault", zap.Any("data", secret.Data))
		return nil
	}

	versionStr := latestVersion.String()
	keyInfo, ok := keyData[versionStr].(map[string]interface{})
	if !ok {
		v.logger.Error("invalid key info from vault", zap.Any("key_data", keyData))
		return nil
	}

	publicKeyPEM, ok := keyInfo["public_key"].(string)
	if !ok {
		v.logger.Error("invalid public key from vault", zap.String("key_name", v.config.VaultKeyName), zap.Any("key_info", keyInfo))
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
		return domain.ErrInvalidClient
	}

	// Get current key version from Vault
	path := fmt.Sprintf("%s/keys/%s", v.config.VaultMountPath, v.config.VaultKeyName)
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		v.logger.Error("failed to get key info from vault", zap.Error(err))
		return domain.ErrInvalidKeyConfig
	}

	latestVersion, ok := secret.Data["latest_version"].(json.Number)
	if !ok {
		v.logger.Error("invalid key data from vault", zap.Any("data", secret.Data))
		return nil
	}

	version, err := latestVersion.Int64()
	if err != nil {
		v.logger.Error("failed to convert latest version to int", zap.Error(err))
		return nil
	}

	// Only rotate if we don't have a key ID or if it's been more than 24 hours
	if v.keyID == "" || time.Since(v.lastRotation) > 24*time.Hour {
		// Rotate key in Vault
		rotatePath := fmt.Sprintf("%s/keys/%s/rotate", v.config.VaultMountPath, v.config.VaultKeyName)
		_, err := v.client.Logical().Write(rotatePath, nil)
		if err != nil {
			v.logger.Error("failed to rotate key in vault", zap.Error(err))
			return domain.ErrInvalidKeyConfig
		}

		// Update key ID and rotation time
		v.keyID = fmt.Sprintf("vault:v%d", version+1)
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

func (v *vaultStrategy) loadCurrentKeyID() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	path := fmt.Sprintf("%s/keys/%s", v.config.VaultMountPath, v.config.VaultKeyName)
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		v.logger.Error("failed to read key metadata from vault", zap.Error(err))
		return err
	}

	latestVersion, ok := secret.Data["latest_version"].(json.Number)
	if !ok {
		v.logger.Error("invalid key data from vault", zap.Any("data", secret.Data))
		return nil
	}

	version := latestVersion.String()

	// Set keyID based on latest version
	v.keyID = fmt.Sprintf("vault:v%s", version)

	// Extrai creation_time da versão mais recente
	keyInfoRaw, ok := secret.Data["keys"].(map[string]interface{})[version]
	if !ok {
		v.logger.Warn("missing latest version key info", zap.String("version", version))
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

	// Divide o token em partes
	parts, err := v.parseTokenParts(tokenString)
	if err != nil {
		return nil, err
	}

	// Decodifica o header
	header, err := v.decodeTokenHeader(parts[0])
	if err != nil {
		return nil, err
	}

	// Decodifica o payload
	claims, err := v.decodeTokenPayload(parts[1])
	if err != nil {
		return nil, err
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
		zap.String("subject", claims.Subject),
		zap.String("kid", header["kid"].(string)))

	// Verifica a assinatura
	path := fmt.Sprintf("%s/verify/%s", v.config.VaultMountPath, v.config.VaultKeyName)
	data := v.getVaultPayload(base64.StdEncoding.EncodeToString([]byte(parts[0] + "." + parts[1])))
	data["signature"] = header["kid"].(string) + ":" + encodedSignature

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
