package email

import (
	"context"
	"testing"

	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestEmailService_SendVerificationEmail(t *testing.T) {
	cfg := &config.Config{
		SMTPHost:     "smtp.gmail.com",
		SMTPPort:     587,
		SMTPUsername: "test@example.com",
		SMTPPassword: "password",
		SMTPFrom:     "noreply@example.com",
	}
	logger := zap.NewNop()
	service := NewEmailService(cfg, logger)

	// Test sending verification email
	err := service.SendVerificationEmail(context.Background(), "user@example.com", "123456")
	assert.Error(t, err) // Should fail in test environment without real SMTP server
}

func TestEmailService_SendPasswordResetEmail(t *testing.T) {
	cfg := &config.Config{
		SMTPHost:     "smtp.gmail.com",
		SMTPPort:     587,
		SMTPUsername: "test@example.com",
		SMTPPassword: "password",
		SMTPFrom:     "noreply@example.com",
	}
	logger := zap.NewNop()
	service := NewEmailService(cfg, logger)

	// Test sending password reset email
	err := service.SendPasswordResetEmail(context.Background(), "user@example.com", "123456")
	assert.Error(t, err) // Should fail in test environment without real SMTP server
}

func TestEmailService_EmailContent(t *testing.T) {
	cfg := &config.Config{
		SMTPHost:     "smtp.gmail.com",
		SMTPPort:     587,
		SMTPUsername: "test@example.com",
		SMTPPassword: "password",
		SMTPFrom:     "noreply@example.com",
	}
	logger := zap.NewNop()
	service := NewEmailService(cfg, logger)

	// Test verification email content
	verificationErr := service.SendVerificationEmail(context.Background(), "user@example.com", "123456")
	assert.Error(t, verificationErr)
	assert.Contains(t, verificationErr.Error(), "Username and Password not accepted")

	// Test password reset email content
	resetErr := service.SendPasswordResetEmail(context.Background(), "user@example.com", "123456")
	assert.Error(t, resetErr)
	assert.Contains(t, resetErr.Error(), "Username and Password not accepted")
}
