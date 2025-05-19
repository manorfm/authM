package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Set up test environment variables
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "postgres")
	os.Setenv("DB_NAME", "user_manager_test")
	os.Setenv("JWT_SECRET", "test_secret")
	os.Setenv("JWT_ACCESS_TOKEN_DURATION", "15m")
	os.Setenv("JWT_REFRESH_TOKEN_DURATION", "24h")
	os.Setenv("PORT", "8080")
	os.Setenv("ENVIRONMENT", "test")

	tests := []struct {
		name    string
		setup   func()
		wantErr bool
	}{
		{
			name: "valid config",
			setup: func() {
				// Environment variables already set
			},
			wantErr: false,
		},
		{
			name: "invalid db port",
			setup: func() {
				os.Setenv("DB_PORT", "invalid")
			},
			wantErr: true,
		},
		{
			name: "invalid jwt durations",
			setup: func() {
				os.Setenv("JWT_ACCESS_TOKEN_DURATION", "invalid")
				os.Setenv("JWT_REFRESH_TOKEN_DURATION", "invalid")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset environment variables to default values
			os.Setenv("DB_PORT", "5432")
			os.Setenv("JWT_ACCESS_TOKEN_DURATION", "15m")
			os.Setenv("JWT_REFRESH_TOKEN_DURATION", "24h")

			// Run test-specific setup
			tt.setup()

			cfg, err := LoadConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Validate config values
				if cfg.DBHost != "localhost" {
					t.Errorf("LoadConfig() DBHost = %v, want %v", cfg.DBHost, "localhost")
				}
				if cfg.DBPort != 5432 {
					t.Errorf("LoadConfig() DBPort = %v, want %v", cfg.DBPort, 5432)
				}
				if cfg.DBUser != "postgres" {
					t.Errorf("LoadConfig() DBUser = %v, want %v", cfg.DBUser, "postgres")
				}
				if cfg.DBPassword != "postgres" {
					t.Errorf("LoadConfig() DBPassword = %v, want %v", cfg.DBPassword, "postgres")
				}
				if cfg.DBName != "user_manager_test" {
					t.Errorf("LoadConfig() DBName = %v, want %v", cfg.DBName, "user_manager_test")
				}
				if cfg.JWTSecret != "test_secret" {
					t.Errorf("LoadConfig() JWTSecret = %v, want %v", cfg.JWTSecret, "test_secret")
				}
				if cfg.JWTAccessDuration != 15*time.Minute {
					t.Errorf("LoadConfig() JWTAccessDuration = %v, want %v", cfg.JWTAccessDuration, 15*time.Minute)
				}
				if cfg.JWTRefreshDuration != 24*time.Hour {
					t.Errorf("LoadConfig() JWTRefreshDuration = %v, want %v", cfg.JWTRefreshDuration, 24*time.Hour)
				}
				if cfg.ServerPort != "8080" {
					t.Errorf("LoadConfig() ServerPort = %v, want %v", cfg.ServerPort, "8080")
				}
				if cfg.Environment != "test" {
					t.Errorf("LoadConfig() Environment = %v, want %v", cfg.Environment, "test")
				}
			}
		})
	}
}
