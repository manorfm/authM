package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ipede/user-manager-service/internal/domain"
	"go.uber.org/zap"
)

// localStrategy implements JWTStrategy using local RSA key pair
type localStrategy struct {
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	config       *domain.LocalConfig
	logger       *zap.Logger
	keyID        string
	lastRotation time.Time
	mu           sync.RWMutex
}

// NewLocalStrategy creates a new local strategy for JWT signing
func NewLocalStrategy(config *domain.LocalConfig, logger *zap.Logger) (domain.JWTStrategy, error) {
	if config == nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	strategy := &localStrategy{
		config:       config,
		logger:       logger,
		lastRotation: time.Now(),
	}

	// Load or generate key pair
	if err := strategy.loadOrGenerateKeyPair(); err != nil {
		return nil, domain.ErrInvalidKeyConfig
	}

	// Generate initial key ID
	strategy.keyID = generateKeyID(strategy.privateKey)

	return strategy, nil
}

// loadOrGenerateKeyPair loads the key pair from file or generates a new one
func (l *localStrategy) loadOrGenerateKeyPair() error {
	// Ensure directory exists
	dir := filepath.Dir(l.config.KeyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return domain.ErrInvalidKeyConfig
	}

	// Try to load existing key pair
	if err := l.loadKeyPair(); err == nil {
		return nil
	}

	// Generate new key pair
	return l.generateKeyPair()
}

// loadKeyPair loads the key pair from file
func (l *localStrategy) loadKeyPair() error {
	// Read private key
	privateKeyPEM, err := os.ReadFile(l.config.KeyPath)
	if err != nil {
		return domain.ErrInvalidKeyConfig
	}

	// Decode PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return domain.ErrInvalidKeyConfig
	}

	// Parse private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return domain.ErrInvalidKeyConfig
	}

	l.privateKey = privateKey
	l.publicKey = &privateKey.PublicKey
	return nil
}

// generateKeyPair generates a new RSA key pair
func (l *localStrategy) generateKeyPair() error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, domain.RSAKeySize)
	if err != nil {
		return domain.ErrInvalidKeyConfig
	}

	// Encode private key
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Write private key to file
	if err := ioutil.WriteFile(l.config.KeyPath, privateKeyPEM, 0600); err != nil {
		return domain.ErrInvalidKeyConfig
	}

	l.privateKey = privateKey
	l.publicKey = &privateKey.PublicKey
	return nil
}

// Sign signs a JWT token using the local private key
func (l *localStrategy) Sign(claims *domain.Claims) (string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = l.keyID

	return token.SignedString(l.privateKey)
}

// GetPublicKey returns the public key
func (l *localStrategy) GetPublicKey() *rsa.PublicKey {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.publicKey
}

// GetKeyID returns the current key ID
func (l *localStrategy) GetKeyID() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.keyID
}

// RotateKey generates a new key pair
func (l *localStrategy) RotateKey() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Generate new key pair
	if err := l.generateKeyPair(); err != nil {
		return domain.ErrInvalidKeyConfig
	}

	// Update key ID and rotation time
	l.keyID = generateKeyID(l.privateKey)
	l.lastRotation = time.Now()

	return nil
}

// GetLastRotation returns the last key rotation time
func (l *localStrategy) GetLastRotation() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastRotation
}

// generateKeyID generates a unique key ID from the private key
func generateKeyID(key *rsa.PrivateKey) string {
	// Use the public key components to generate a unique ID
	modulus := key.N.Bytes()
	exponent := []byte{byte(key.E)}

	// Combine modulus and exponent
	data := append(modulus, exponent...)

	// Generate SHA-256 hash
	hash := sha256.Sum256(data)

	// Encode as base64url without padding
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GetAccessDuration returns the access token duration
func (l *localStrategy) GetAccessDuration() time.Duration {
	if l.config.AccessDuration > 0 {
		return l.config.AccessDuration
	}
	return domain.DefaultAccessTokenDuration
}

// GetRefreshDuration returns the refresh token duration
func (l *localStrategy) GetRefreshDuration() time.Duration {
	if l.config.RefreshDuration > 0 {
		return l.config.RefreshDuration
	}
	return domain.DefaultRefreshTokenDuration
}
