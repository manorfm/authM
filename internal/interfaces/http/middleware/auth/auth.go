package auth

import (
	"context"
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
			httperrors.RespondWithError(w, httperrors.ErrCodeAuthentication, "Unauthorized", nil, http.StatusUnauthorized)
			return
		}

		claims, err := m.jwt.ValidateToken(token)
		if err != nil {
			m.logger.Error("Failed to validate token", zap.Error(err))
			httperrors.RespondWithError(w, httperrors.ErrCodeAuthentication, "Invalid token", nil, http.StatusUnauthorized)
			return
		}

		m.logger.Debug("Token validated successfully",
			zap.String("subject", claims.Subject),
			zap.Strings("roles", claims.Roles))

		ctx := context.WithValue(r.Context(), "sub", claims.Subject)
		ctx = context.WithValue(ctx, "roles", claims.Roles)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) RequireRole(role string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, ok := r.Context().Value("roles").([]string)
			if !ok {
				httperrors.RespondWithError(w, httperrors.ErrCodeAuthorization, "Forbidden", nil, http.StatusForbidden)
				return
			}

			for _, userRole := range roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			httperrors.RespondWithError(w, httperrors.ErrCodeAuthorization, "Forbidden", nil, http.StatusForbidden)
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
