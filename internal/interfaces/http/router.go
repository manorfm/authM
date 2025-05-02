package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/interfaces/http/handlers"
	"github.com/ipede/user-manager-service/internal/interfaces/http/middleware/auth"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
)

type Router struct {
	router *chi.Mux
}

func NewRouter(
	authService *application.AuthService,
	userService *application.UserService,
	authMiddleware *auth.AuthMiddleware,
	logger *zap.Logger,
) *Router {
	r := chi.NewRouter()

	// Add middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(60 * time.Second))

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, logger)
	userHandler := handlers.NewUserHandler(userService, logger)

	// Swagger documentation
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("http://localhost:8080/swagger/doc.json"),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	// Serve Swagger JSON
	r.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "docs/swagger.json")
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Post("/register", authHandler.HandleRegister)
		r.Post("/login", authHandler.HandleLogin)
	})

	// Admin routes
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.Authenticator, authMiddleware.RequireRole("admin"))
		r.Get("/users", userHandler.HandleListUsers)
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.Authenticator)
		r.Get("/users/{id}", userHandler.HandleGetUser)
		r.Put("/users/{id}", userHandler.HandleUpdateUser)
	})

	return &Router{router: r}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.router.ServeHTTP(w, req)
}
