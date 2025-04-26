package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"go.uber.org/zap"
)

type AuthMiddleware struct {
	jwt    *jwt.JWT
	logger *zap.Logger
}

func NewAuthMiddleware(jwt *jwt.JWT, logger *zap.Logger) *AuthMiddleware {
	return &AuthMiddleware{jwt: jwt, logger: logger}
}

func (m *AuthMiddleware) Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := m.jwt.ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", claims.UserID.String())
		ctx = context.WithValue(ctx, "roles", claims.Roles)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			roles, ok := r.Context().Value("roles").([]string)
			if !ok {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			for _, userRole := range roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
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
