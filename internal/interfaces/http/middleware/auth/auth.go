package auth

import (
	"net/http"
	"strings"

	"github.com/ipede/user-manager-service/internal/domain"
	httperrors "github.com/ipede/user-manager-service/internal/interfaces/http/errors"
	"go.uber.org/zap"
)

type AuthMiddleware struct {
	jwt    domain.JWTService
	logger *zap.Logger
}

func NewAuthMiddleware(jwt domain.JWTService, logger *zap.Logger) *AuthMiddleware {
	return &AuthMiddleware{jwt: jwt, logger: logger}
}

func (m *AuthMiddleware) Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			httperrors.RespondWithError(w, domain.ErrUnauthorized)
			return
		}

		claims, err := m.jwt.ValidateToken(token)
		if err != nil {
			m.logger.Error("Failed to validate token", zap.Error(err))
			httperrors.RespondWithError(w, err.(domain.Error))
			return
		}

		m.logger.Debug("Token validated successfully",
			zap.String("subject", claims.Subject),
			zap.Strings("roles", claims.Roles))

		ctx := domain.WithSubject(r.Context(), claims.Subject)
		ctx = domain.WithRoles(ctx, claims.Roles)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) RequireRole(role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, ok := domain.GetRoles(r.Context())
			if !ok {
				httperrors.RespondWithError(w, domain.ErrForbidden)
				return
			}

			for _, userRole := range roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			httperrors.RespondWithError(w, domain.ErrForbidden)
		})
	}
}

func (m *AuthMiddleware) extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	if len(strings.Split(bearToken, " ")) == 2 {
		return strings.Split(bearToken, " ")[1]
	}
	return ""
}
