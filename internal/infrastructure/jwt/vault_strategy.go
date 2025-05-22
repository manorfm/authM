package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	vaultConfig.Timeout = config.Timeout

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

	// Initialize key ID
	if err := strategy.RotateKey(); err != nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	return strategy, nil
}

// Sign signs a JWT token using Vault's transit engine
func (v *vaultStrategy) Sign(claims *domain.Claims) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.client == nil {
		return "", domain.NewJWTError("sign token", domain.ErrInvalidClient)
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = v.keyID

	// Get token string without signature
	unsignedToken, err := token.SigningString()
	if err != nil {
		v.logger.Error("failed to get signing string", zap.Error(err))
		return "", domain.NewJWTError("sign token", domain.ErrTokenGeneration)
	}

	// Sign with Vault
	path := fmt.Sprintf("%s/sign/%s", v.config.MountPath, v.config.KeyName)
	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(unsignedToken)),
	}

	secret, err := v.client.Logical().Write(path, data)
	if err != nil {
		v.logger.Error("failed to sign token with vault", zap.Error(err))
		return "", domain.NewJWTError("sign token", domain.ErrTokenGeneration)
	}

	// Get signature from response
	signature, ok := secret.Data["signature"].(string)
	if !ok {
		v.logger.Error("invalid signature from vault")
		return "", domain.NewJWTError("sign token", domain.ErrInvalidSignature)
	}

	// Remove any vault version prefix (e.g., "vault:v1:", "vault:v2:", etc.)
	if strings.HasPrefix(signature, "vault:v") {
		parts := strings.SplitN(signature, ":", 3)
		if len(parts) == 3 {
			signature = parts[2]
		}
	}

	// Base64 decode the signature
	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		v.logger.Error("failed to decode signature", zap.Error(err))
		return "", domain.NewJWTError("sign token", domain.ErrInvalidSignature)
	}

	// Create a proper RSA signature
	hash := sha256.New()
	hash.Write([]byte(unsignedToken))
	hashed := hash.Sum(nil)

	// Verify the signature is valid RSA
	err = rsa.VerifyPKCS1v15(v.GetPublicKey(), crypto.SHA256, hashed, decodedSignature)
	if err != nil {
		v.logger.Error("invalid RSA signature", zap.Error(err))
		return "", domain.NewJWTError("sign token", domain.ErrInvalidSignature)
	}

	// Base64URL encode the signature (JWT standard)
	encodedSignature := base64.RawURLEncoding.EncodeToString(decodedSignature)

	// Combine token and signature
	return fmt.Sprintf("%s.%s", unsignedToken, encodedSignature), nil
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
		v.keyID = fmt.Sprintf("vault-%d", latestVersion+1)
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
