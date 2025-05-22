package config

import (
	"os"
	"strconv"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/joho/godotenv"
)

// Config holds the application configuration
type Config struct {
	// Database configuration
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string

	// JWT configuration
	JWTAccessDuration  time.Duration
	JWTRefreshDuration time.Duration
	JWTKeyPath         string
	JWTKeyPassword     string

	// Vault configuration
	VaultAddress    string
	VaultToken      string
	VaultMountPath  string
	VaultKeyName    string
	VaultRoleName   string
	VaultAuthMethod string
	VaultRetryCount int
	VaultRetryDelay time.Duration
	VaultTimeout    time.Duration

	// Server configuration
	ServerPort int
	ServerHost string
}

// NewConfig creates a new configuration with default values
func NewConfig() *Config {
	return &Config{
		// Database defaults
		DBHost:     "localhost",
		DBPort:     5432,
		DBUser:     "postgres",
		DBPassword: "postgres",
		DBName:     "user_manager",

		// JWT defaults
		JWTAccessDuration:  domain.DefaultAccessTokenDuration,
		JWTRefreshDuration: domain.DefaultRefreshTokenDuration,
		JWTKeyPath:         "~/.ssh/jwt-signing-key",
		JWTKeyPassword:     "",

		// Vault defaults
		VaultAddress:    "http://localhost:8200",
		VaultToken:      "",
		VaultMountPath:  "transit",
		VaultKeyName:    "jwt-signing-key",
		VaultRoleName:   "jwt-signing",
		VaultAuthMethod: "token",
		VaultRetryCount: 3,
		VaultRetryDelay: time.Second,
		VaultTimeout:    time.Second * 5,

		// Server defaults
		ServerPort: 8080,
		ServerHost: "localhost",
	}
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	// Load .env from project root
	_ = godotenv.Load()

	dbPort, err := strconv.Atoi(getEnv("DB_PORT", "5432"))
	if err != nil {
		return nil, err
	}

	accessDuration, err := time.ParseDuration(getEnv("JWT_ACCESS_TOKEN_DURATION", "15m"))
	if err != nil {
		return nil, err
	}

	refreshDuration, err := time.ParseDuration(getEnv("JWT_REFRESH_TOKEN_DURATION", "24h"))
	if err != nil {
		return nil, err
	}

	return &Config{
		DBHost:             getEnv("DB_HOST", "localhost"),
		DBPort:             dbPort,
		DBUser:             getEnv("DB_USER", "postgres"),
		DBPassword:         getEnv("DB_PASSWORD", "postgres"),
		DBName:             getEnv("DB_NAME", "user_manager"),
		JWTAccessDuration:  accessDuration,
		JWTRefreshDuration: refreshDuration,
		JWTKeyPath:         getEnv("JWT_KEY_PATH", "~/.ssh/jwt-signing-key"),
		JWTKeyPassword:     getEnv("JWT_KEY_PASSWORD", ""),
		VaultAddress:       getEnv("VAULT_ADDRESS", "http://localhost:8200"),
		VaultToken:         getEnv("VAULT_TOKEN", ""),
		VaultMountPath:     getEnv("VAULT_MOUNT_PATH", "transit"),
		VaultKeyName:       getEnv("VAULT_KEY_NAME", "jwt-signing-key"),
		VaultRoleName:      getEnv("VAULT_ROLE_NAME", "jwt-signing"),
		VaultAuthMethod:    getEnv("VAULT_AUTH_METHOD", "token"),
		VaultRetryCount:    getEnvInt("VAULT_RETRY_COUNT", 3),
		VaultRetryDelay:    time.Second * time.Duration(getEnvInt("VAULT_RETRY_DELAY", 1)),
		VaultTimeout:       time.Second * time.Duration(getEnvInt("VAULT_TIMEOUT", 5)),
		ServerPort:         getEnvInt("PORT", 8080),
		ServerHost:         getEnv("SERVER_HOST", "localhost"),
	}, nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvInt gets an environment variable as an integer or returns a default value
func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		intValue, err := strconv.Atoi(value)
		if err == nil {
			return intValue
		}
	}
	return defaultValue
}
