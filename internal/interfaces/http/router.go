package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/ipede/user-manager-service/internal/infrastructure/email"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/repository"
	"github.com/ipede/user-manager-service/internal/infrastructure/totp"
	"github.com/ipede/user-manager-service/internal/interfaces/http/handlers"
	"github.com/ipede/user-manager-service/internal/interfaces/http/middleware/auth"
	"github.com/ipede/user-manager-service/internal/interfaces/http/middleware/ratelimit"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
)

type Router struct {
	router *chi.Mux
	db     *database.Postgres
}

func NewRouter(
	db *database.Postgres,
	cfg *config.Config,
	logger *zap.Logger,
) *Router {
	strategy := jwt.NewCompositeStrategy(cfg, logger)
	jwtService := jwt.NewJWTService(strategy, cfg, logger)
	authMiddleware := auth.NewAuthMiddleware(jwtService, logger)
	userRepo := repository.NewUserRepository(db, logger)
	oauthRepo := repository.NewOAuth2Repository(db, logger)
	verificationRepo := repository.NewVerificationCodeRepository(db, logger)
	emailTemplate := email.NewEmailTemplate(&cfg.SMTP, logger)
	userService := application.NewUserService(userRepo, logger)
	authService := application.NewAuthService(userRepo, verificationRepo, jwtService, emailTemplate, logger)
	oauth2Service := application.NewOAuth2Service(oauthRepo, logger)
	oidcService := application.NewOIDCService(oauth2Service, jwtService, userRepo, cfg, logger)

	totpRepo := repository.NewTOTPRepository(db, logger)
	totpGenerator := totp.NewGenerator(logger)
	totpService := application.NewTOTPService(totpRepo, totpGenerator, logger)
	totpHandler := handlers.NewTOTPHandler(totpService, logger)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)
	oidcHandler := handlers.NewOIDCHandler(oidcService, jwtService, logger)
	oauth2Handler := handlers.NewOAuth2Handler(oauthRepo, logger)

	// Create router with middleware
	router := createRouter()

	rateLimiter := ratelimit.NewRateLimiter(100, 200, 3*time.Minute)
	router.Use(rateLimiter.Middleware)

	// Health check endpoints
	router.Group(func(r chi.Router) {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})

		r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
			// Check database connection
			if err := db.Ping(); err != nil {
				logger.Error("Database health check failed", zap.Error(err))
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("Database connection failed"))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Ready"))
		})

		r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Alive"))
		})
	})

	// Swagger UI configuration
	router.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
		httpSwagger.DocExpansion("list"),
		httpSwagger.DomID("swagger-ui"),
		httpSwagger.DeepLinking(true),
		httpSwagger.PersistAuthorization(true),
	))

	// Serve Swagger JSON with CORS headers
	router.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		w.Header().Set("Content-Type", "application/json")
		http.ServeFile(w, r, "docs/swagger.json")
	})

	// API routes without version in URL
	router.Route("/api", func(r chi.Router) {
		// Public routes
		r.Group(func(r chi.Router) {
			r.Post("/register", authHandler.RegisterHandler)
			r.Post("/auth/login", authHandler.LoginHandler)
			r.Post("/auth/verify-email", authHandler.VerifyEmailHandler)
			r.Post("/auth/request-password-reset", authHandler.RequestPasswordResetHandler)
			r.Post("/auth/reset-password", authHandler.ResetPasswordHandler)
		})

		// OIDC routes
		r.Group(func(r chi.Router) {
			r.Get("/.well-known/openid-configuration", oidcHandler.GetOpenIDConfigurationHandler)
			r.Get("/.well-known/jwks.json", oidcHandler.GetJWKSHandler)
		})

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator, authMiddleware.RequireRole("admin"))
			r.Get("/users", userHandler.ListUsersHandler)
			r.Get("/oauth2/clients", oauth2Handler.ListClientsHandler)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator)
			r.Get("/users/{id}", userHandler.GetUserHandler)
			r.Put("/users/{id}", userHandler.UpdateUserHandler)
			r.Get("/oauth2/authorize", oidcHandler.AuthorizeHandler)
			r.Post("/oauth2/token", oidcHandler.TokenHandler)
			r.Get("/oauth2/userinfo", oidcHandler.GetUserInfoHandler)

			// OAuth2 client management routes
			r.Post("/oauth2/clients", oauth2Handler.CreateClientHandler)
			r.Get("/oauth2/clients/{id}", oauth2Handler.GetClientHandler)
			r.Put("/oauth2/clients/{id}", oauth2Handler.UpdateClientHandler)
			r.Delete("/oauth2/clients/{id}", oauth2Handler.DeleteClientHandler)

			// TOTP routes
			r.Post("/totp/enable", totpHandler.EnableTOTP)
			r.Post("/totp/verify", totpHandler.VerifyTOTP)
			r.Post("/totp/verify-backup", totpHandler.VerifyBackupCode)
			r.Post("/totp/disable", totpHandler.DisableTOTP)
		})
	})

	return &Router{router: router, db: db}
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
