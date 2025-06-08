package totp

import (
	"net/http"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

// TOTPMiddleware creates a middleware that verifies TOTP codes
func TOTPMiddleware(totpService domain.TOTPService, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context
			userID := r.Context().Value("sub").(string)
			if userID == "" {
				logger.Error("User not authenticated")
				errors.RespondWithError(w, domain.ErrUnauthorized)
				return
			}

			// Get TOTP code from header
			code := r.Header.Get("X-TOTP-Code")
			if code == "" {
				logger.Error("Missing TOTP code")
				errors.RespondWithError(w, domain.ErrTOTPVerificationRequired)
				return
			}

			// Verify TOTP code
			err := totpService.VerifyTOTP(userID, code)
			if err != nil {
				logger.Error("Failed to verify TOTP code",
					zap.String("user_id", userID),
					zap.Error(err))
				errors.RespondWithError(w, err.(domain.Error))
				return
			}

			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}
