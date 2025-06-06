package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

type Config struct {
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string

	JWTAccessDuration  time.Duration
	JWTRefreshDuration time.Duration
	JWTKeyPath         string

	EnableVault    bool
	VaultAddress   string
	VaultToken     string
	VaultMountPath string
	VaultKeyName   string

	ServerPort        int
	ServerURL         string
	RSAKeySize        int
	JWKSCacheDuration time.Duration

	SMTPHost           string
	SMTPPort           int
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
	SMTPAuthValidation bool
}

// LoadConfig loads configuration from environment variables, logging with zap
func LoadConfig(logger *zap.Logger) (*Config, error) {
	if err := godotenv.Load(); err != nil {
		logger.Warn("No .env file found, relying on system environment")
	}

	getInt := func(key string, defaultVal int) (int, error) {
		valStr := getEnv(key, "")
		if valStr == "" {
			logger.Info("Using default value", zap.String("key", key), zap.Int("default", defaultVal))
			return defaultVal, nil
		}
		val, err := strconv.Atoi(valStr)
		if err != nil {
			return 0, fmt.Errorf("invalid int value for %s: %w", key, err)
		}
		return val, nil
	}

	getDuration := func(key string, defaultVal time.Duration) (time.Duration, error) {
		valStr := getEnv(key, "")
		if valStr == "" {
			logger.Info("Using default duration", zap.String("key", key), zap.String("default", defaultVal.String()))
			return defaultVal, nil
		}
		val, err := time.ParseDuration(valStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration value for %s: %w", key, err)
		}
		return val, nil
	}

	cfg := &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBUser:     getEnv("DB_USER", "owner"),
		DBPassword: getEnv("DB_PASSWORD", "ownerTest"),
		DBName:     getEnv("DB_NAME", "users"),

		JWTKeyPath: getEnv("JWT_KEY_PATH", ""),

		EnableVault:    getEnv("ENABLE_VAULT", "true") == "true",
		VaultAddress:   getEnv("VAULT_ADDRESS", "http://localhost:8200"),
		VaultToken:     getEnv("VAULT_TOKEN", ""),
		VaultMountPath: getEnv("VAULT_MOUNT_PATH", "transit/user-manager-service"),
		VaultKeyName:   getEnv("VAULT_KEY_NAME", "jwt-signing-key"),

		ServerURL: getEnv("SERVER_URL", "http://localhost:8080"),

		SMTPHost:           getEnv("SMTP_HOST", "localhost"),
		SMTPUsername:       getEnv("SMTP_USERNAME", ""),
		SMTPPassword:       getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:           getEnv("SMTP_FROM", "noreply@example.com"),
		SMTPAuthValidation: getEnv("SMTP_AUTH_VALIDATION", "true") == "true",
	}

	// Load numeric and duration values with error handling
	var err error
	if cfg.DBPort, err = getInt("DB_PORT", 5432); err != nil {
		return nil, err
	}
	if cfg.JWTAccessDuration, err = getDuration("JWT_ACCESS_TOKEN_DURATION", 15*time.Minute); err != nil {
		return nil, err
	}
	if cfg.JWTRefreshDuration, err = getDuration("JWT_REFRESH_TOKEN_DURATION", 24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.ServerPort, err = getInt("PORT", 8080); err != nil {
		return nil, err
	}
	if cfg.RSAKeySize, err = getInt("RSA_KEY_SIZE", 2048); err != nil {
		return nil, err
	}
	if cfg.JWKSCacheDuration, err = getDuration("JWKS_CACHE_DURATION", time.Hour); err != nil {
		return nil, err
	}
	if cfg.SMTPPort, err = getInt("SMTP_PORT", 1025); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		logger.Error("Invalid configuration", zap.Error(err))
		return nil, err
	}

	logger.Info("Configuration loaded successfully")
	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Validate ensures configuration values are valid
func (c *Config) Validate() error {
	if c.JWTAccessDuration <= 0 {
		return errors.New("JWTAccessDuration must be positive")
	}
	if c.JWTRefreshDuration <= 0 {
		return errors.New("JWTRefreshDuration must be positive")
	}
	if c.ServerPort <= 0 || c.ServerPort > 65535 {
		return fmt.Errorf("ServerPort must be valid: got %d", c.ServerPort)
	}
	if c.SMTPPort <= 0 || c.SMTPPort > 65535 {
		return fmt.Errorf("SMTPPort must be valid: got %d", c.SMTPPort)
	}
	if c.RSAKeySize < 2048 {
		return fmt.Errorf("RSAKeySize must be at least 2048 bits: got %d", c.RSAKeySize)
	}
	return nil
}
