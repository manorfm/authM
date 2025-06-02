package email

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"go.uber.org/zap"
)

type EmailService struct {
	config *config.Config
	logger *zap.Logger
}

func NewEmailService(cfg *config.Config, logger *zap.Logger) *EmailService {
	return &EmailService{
		config: cfg,
		logger: logger,
	}
}

func (s *EmailService) SendVerificationEmail(ctx context.Context, email, code string) error {
	subject := "Welcome! Please verify your email"
	body := fmt.Sprintf(`
Hi there! 👋

Welcome to our platform! We're excited to have you on board.

To get started, please verify your email address by entering this code:
%s

This code will expire in 24 hours.

If you didn't request this verification, you can safely ignore this email.

Best regards,
The Team
`, code)

	return s.sendEmail(email, subject, body)
}

func (s *EmailService) SendPasswordResetEmail(ctx context.Context, email, code string) error {
	subject := "Reset your password"
	body := fmt.Sprintf(`
Hi there! 👋

We received a request to reset your password. To proceed, please use this code:
%s

This code will expire in 1 hour.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

Stay secure,
The Team
`, code)

	return s.sendEmail(email, subject, body)
}

func (s *EmailService) sendEmail(to, subject, body string) error {
	// Create email message
	message := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"\r\n"+
		"%s", s.config.SMTPFrom, to, subject, body)

	// Set up authentication information
	auth := smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step
	err := smtp.SendMail(
		fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort),
		auth,
		s.config.SMTPFrom,
		[]string{to},
		[]byte(message),
	)

	if err != nil {
		s.logger.Error("Failed to send email",
			zap.String("to", to),
			zap.String("subject", subject),
			zap.Error(err))
		return err
	}

	s.logger.Info("Email sent successfully",
		zap.String("to", to),
		zap.String("subject", subject))
	return nil
}
