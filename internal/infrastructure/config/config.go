package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string

	JWTSecret          string
	JWTAccessDuration  time.Duration
	JWTRefreshDuration time.Duration

	ServerPort  string
	Environment string
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
		DBUser:             getEnv("DB_USER", "usuarios"),
		DBPassword:         getEnv("DB_PASSWORD", "senha"),
		DBName:             getEnv("DB_NAME", "users"),
		JWTSecret:          getEnv("JWT_SECRET", ""),
		JWTAccessDuration:  accessDuration,
		JWTRefreshDuration: refreshDuration,
		ServerPort:         getEnv("PORT", "8080"),
		Environment:        getEnv("ENVIRONMENT", "development"),
	}, nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
