package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/jwtauth/v5"
	"go.uber.org/zap"
)

type AuthMiddleware struct {
	auth   *jwtauth.JWTAuth
	logger *zap.Logger
}

func NewAuthMiddleware(secret string, logger *zap.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		auth:   jwtauth.New("HS256", []byte(secret), nil),
		logger: logger,
	}
}

func (m *AuthMiddleware) Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := m.validateToken(token)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", claims["user_id"])
		ctx = context.WithValue(ctx, "roles", claims["roles"])
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

func (m *AuthMiddleware) validateToken(tokenString string) (map[string]interface{}, error) {
	token, err := m.auth.Decode(tokenString)
	if err != nil {
		return nil, err
	}

	if token == nil {
		return nil, errors.New("invalid token")
	}

	claims := token.PrivateClaims()
	if claims == nil {
		return nil, errors.New("invalid claims")
	}

	return claims, nil
}
