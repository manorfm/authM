package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo     domain.UserRepository
	jwtService   domain.JWTService
	emailService domain.EmailService
	logger       *zap.Logger
}

func NewAuthService(userRepo domain.UserRepository, jwtService domain.JWTService, emailService domain.EmailService, logger *zap.Logger) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		jwtService:   jwtService,
		emailService: emailService,
		logger:       logger,
	}
}

// Register creates a new user
func (s *AuthService) Register(ctx context.Context, name, email, password, phone string) (*domain.User, error) {
	// Check if user already exists
	exists, err := s.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Generate verification code
	verificationCode := generateRandomCode(6)
	verificationExp := time.Now().Add(24 * time.Hour)

	// Create user
	user := &domain.User{
		ID:               ulid.Make(),
		Name:             name,
		Email:            email,
		Password:         string(hashedPassword),
		Phone:            phone,
		Roles:            []string{"user"},
		EmailVerified:    false,
		VerificationCode: verificationCode,
		VerificationExp:  verificationExp,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(ctx, email, verificationCode); err != nil {
		s.logger.Error("Failed to send verification email", zap.Error(err))
		return nil, domain.ErrEmailSendFailed
	}

	return user, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*domain.TokenPair, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, domain.ErrEmailNotVerified
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	return s.jwtService.GenerateTokenPair(user.ID, user.Roles)
}

func (s *AuthService) VerifyEmail(ctx context.Context, email, code string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if user.EmailVerified {
		return nil // Already verified
	}

	if user.VerificationCode != code {
		return domain.ErrInvalidVerificationCode
	}

	if time.Now().After(user.VerificationExp) {
		return domain.ErrVerificationCodeExpired
	}

	user.EmailVerified = true
	user.VerificationCode = ""
	user.VerificationExp = time.Time{}
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(ctx, user)
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	// Generate reset code
	resetCode := generateRandomCode(6)
	resetExp := time.Now().Add(1 * time.Hour)

	user.PasswordResetCode = resetCode
	user.PasswordResetExp = resetExp
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	// Send reset email
	if err := s.emailService.SendPasswordResetEmail(ctx, email, resetCode); err != nil {
		s.logger.Error("Failed to send password reset email", zap.Error(err))
		return domain.ErrEmailSendFailed
	}

	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, email, code, newPassword string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return domain.ErrUserNotFound
	}

	if user.PasswordResetCode != code {
		return domain.ErrInvalidPasswordChangeCode
	}

	if time.Now().After(user.PasswordResetExp) {
		return domain.ErrPasswordChangeCodeExpired
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashedPassword)
	user.PasswordResetCode = ""
	user.PasswordResetExp = time.Time{}
	user.UpdatedAt = time.Now()

	return s.userRepo.Update(ctx, user)
}

func generateRandomCode(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}
