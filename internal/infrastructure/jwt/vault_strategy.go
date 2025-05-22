package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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
		return "", domain.ErrInvalidClient
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = v.keyID

	// Get token string without signature
	unsignedToken, err := token.SigningString()
	if err != nil {
		return "", domain.ErrTokenGeneration
	}

	// Sign with Vault
	path := fmt.Sprintf("%s/sign/%s", v.config.MountPath, v.config.KeyName)
	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString([]byte(unsignedToken)),
	}

	secret, err := v.client.Logical().Write(path, data)
	if err != nil {
		return "", domain.ErrTokenGeneration
	}

	// Get signature from response
	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", domain.ErrTokenGeneration
	}

	// Combine token and signature
	return fmt.Sprintf("%s.%s", unsignedToken, signature), nil
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
		v.logger.Error("invalid key data from vault")
		return nil
	}

	keyInfo, ok := keyData[v.keyID].(map[string]interface{})
	if !ok {
		v.logger.Error("invalid key info from vault")
		return nil
	}

	publicKeyPEM, ok := keyInfo["public_key"].(string)
	if !ok {
		v.logger.Error("invalid public key from vault")
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

	// Rotate key in Vault
	path := fmt.Sprintf("%s/keys/%s/rotate", v.config.MountPath, v.config.KeyName)
	_, err := v.client.Logical().Write(path, nil)
	if err != nil {
		v.logger.Error("failed to rotate key in vault", zap.Error(err))
		return domain.ErrInvalidKeyConfig
	}

	// Update key ID and rotation time
	v.keyID = fmt.Sprintf("vault-%d", time.Now().Unix())
	v.lastRotation = time.Now()

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
