package domain

import "context"

// EmailSender defines the interface for sending emails
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, email, code string) error
	SendPasswordResetEmail(ctx context.Context, email, code string) error
}

// EmailService defines the interface for email service operations
type EmailCommand interface {
	SendEmail(ctx context.Context, email, subject, template, code string) error
}
