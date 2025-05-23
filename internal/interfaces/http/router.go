package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/repository"
	"github.com/ipede/user-manager-service/internal/interfaces/http/handlers"
	"github.com/ipede/user-manager-service/internal/interfaces/http/middleware/auth"
	"github.com/ipede/user-manager-service/internal/interfaces/http/middleware/ratelimit"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
)

type Router struct {
	router *chi.Mux
}

func NewRouter(
	db *database.Postgres,
	cfg *config.Config,
	logger *zap.Logger,
) *Router {

	jwtService := jwt.NewJWTService(cfg, logger)
	authMiddleware := auth.NewAuthMiddleware(jwtService, logger)
	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuth2Repository(db, logger)
	userService := application.NewUserService(userRepo, logger)
	authService := application.NewAuthService(userRepo, jwtService, logger)
	oidcService := application.NewOIDCService(authService, jwtService, userRepo, oauthRepo, logger)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	oidcHandler := handlers.NewOIDCHandler(oidcService, jwtService, logger)

	// Swagger documentation
	router := createRouter()

	rateLimiter := ratelimit.NewRateLimiter(100, 200, 3*time.Minute)
	router.Use(rateLimiter.Middleware)

	router.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/swagger/doc.json"),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	// Serve Swagger JSON
	router.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "docs/swagger.json")
	})

	// Public routes
	router.Group(func(r chi.Router) {
		r.Post("/register", authHandler.RegisterHandler)
		r.Post("/auth/login", authHandler.LoginHandler)
	})

	// OIDC routes
	router.Group(func(r chi.Router) {
		r.Get("/.well-known/openid-configuration", oidcHandler.GetOpenIDConfigurationHandler)
		r.Get("/.well-known/jwks.json", oidcHandler.GetJWKSHandler)
	})

	// Admin routes
	router.Group(func(r chi.Router) {
		r.Use(authMiddleware.Authenticator, authMiddleware.RequireRole("admin"))
		r.Get("/users", userHandler.ListUsersHandler)
	})

	// Protected routes
	router.Group(func(r chi.Router) {
		r.Use(authMiddleware.Authenticator)
		r.Get("/users/{id}", userHandler.GetUserHandler)
		r.Put("/users/{id}", userHandler.UpdateUserHandler)
		r.Get("/oauth2/authorize", oidcHandler.AuthorizeHandler)
		r.Post("/oauth2/token", oidcHandler.TokenHandler)
		r.Get("/oauth2/userinfo", oidcHandler.GetUserInfoHandler)

		// OAuth2 client management routes
		oauth2Handler := handlers.NewOAuth2Handler(oauthRepo, logger)
		r.Post("/oauth2/clients", oauth2Handler.CreateClientHandler)
		r.Get("/oauth2/clients", oauth2Handler.ListClientsHandler)
		r.Get("/oauth2/clients/{id}", oauth2Handler.GetClientHandler)
		r.Put("/oauth2/clients/{id}", oauth2Handler.UpdateClientHandler)
		r.Delete("/oauth2/clients/{id}", oauth2Handler.DeleteClientHandler)
	})

	return &Router{router: router}
}

func createRouter() *chi.Mux {
	router := chi.NewRouter()

	// Add middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Timeout(60 * time.Second))

	return router
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.router.ServeHTTP(w, req)
}
