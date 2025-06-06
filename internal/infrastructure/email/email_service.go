package email

import (
	"context"
	"fmt"
	"net/mail"
	"net/smtp"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"go.uber.org/zap"
)

type EmailService struct {
	config     *config.Config
	logger     *zap.Logger
	smtpClient SMTPClient
}

type EmailMessage struct {
	From    string
	To      string
	Subject string
	Body    string
}

func (e *EmailMessage) Build() string {
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		e.From, e.To, e.Subject, e.Body)
}

// Interface para facilitar testes e mocks
type SMTPClient interface {
	SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// Implementação real do SMTPClient
type realSMTPClient struct{}

func (c *realSMTPClient) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}

func NewEmailService(cfg *config.Config, logger *zap.Logger) *EmailService {
	return &EmailService{
		config:     cfg,
		logger:     logger,
		smtpClient: &realSMTPClient{},
	}
}

func (s *EmailService) isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func (s *EmailService) validateConfig() error {
	var missing []string

	if s.config.SMTPHost == "" {
		missing = append(missing, "SMTP_HOST")
	}
	if s.config.SMTPUsername == "" {
		missing = append(missing, "SMTP_USERNAME")
	}
	if s.config.SMTPPassword == "" {
		missing = append(missing, "SMTP_PASSWORD")
	}
	if s.config.SMTPFrom == "" {
		missing = append(missing, "SMTP_FROM")
	}
	if s.config.SMTPAuthValidation && len(missing) > 0 {
		s.logger.Error("Missing SMTP configuration", zap.Strings("missing_fields", missing))
		return domain.ErrMissingSMTPConfiguration
	}
	return nil
}

func (s *EmailService) sendEmail(ctx context.Context, email, subject, template, code string) error {
	if !s.isValidEmail(email) {
		s.logger.Error("Invalid email address", zap.String("email", email))
		return domain.ErrInvalidEmail
	}

	body := fmt.Sprintf(template, code)

	if err := s.validateConfig(); err != nil {
		s.logger.Error("Invalid SMTP configuration", zap.Error(err))
		return err
	}

	msg := &EmailMessage{
		From:    s.config.SMTPFrom,
		To:      email,
		Subject: subject,
		Body:    body,
	}

	auth := smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)
	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)

	err := s.smtpClient.SendMail(addr, auth, s.config.SMTPFrom, []string{email}, []byte(msg.Build()))
	if err != nil {
		s.logger.Error("Failed to send email",
			zap.String("to", email),
			zap.String("subject", subject),
			zap.String("smtp_host", s.config.SMTPHost),
			zap.Int("smtp_port", s.config.SMTPPort),
			zap.Error(err),
			zap.String("request_id", getRequestID(ctx)),
		)
		return err
	}

	s.logger.Info("Email sent successfully",
		zap.String("to", email),
		zap.String("subject", subject),
		zap.String("request_id", getRequestID(ctx)),
	)
	return nil
}

func (s *EmailService) SendVerificationEmail(ctx context.Context, email, code string) error {
	subject := "Welcome! Please verify your email"
	template := `
Hi there! 👋

Welcome to our platform! We're excited to have you on board.

To get started, please verify your email address by entering this code:
%s

This code will expire in 24 hours.

If you didn't request this verification, you can safely ignore this email.

Best regards,
The Team
`
	return s.sendEmail(ctx, email, subject, template, code)
}

func (s *EmailService) SendPasswordResetEmail(ctx context.Context, email, code string) error {
	subject := "Reset your password"
	template := `
Hi there! 👋

We received a request to reset your password. To proceed, please use this code:
%s

This code will expire in 1 hour.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

Stay secure,
The Team
`
	return s.sendEmail(ctx, email, subject, template, code)
}

// Recupera o request ID do contexto, se presente
func getRequestID(ctx context.Context) string {
	if v := ctx.Value("request_id"); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}
