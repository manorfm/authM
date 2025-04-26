package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/interfaces/http/handlers"
	"github.com/ipede/user-manager-service/internal/interfaces/http/middleware/auth"
	httpSwagger "github.com/swaggo/http-swagger"
	"go.uber.org/zap"
)

// @title User Manager Service API
// @version 1.0
// @description This is a user management service with JWT authentication
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Create database connection
	ctx := context.Background()
	db, err := database.NewPostgres(ctx, cfg, logger)
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()

	// Initialize JWT service
	jwtService := jwt.New(cfg.JWTSecret, 24*time.Hour, 7*24*time.Hour) // 24h access token, 7d refresh token

	// Initialize auth middleware
	authMiddleware := auth.NewAuthMiddleware(jwtService, logger)

	// Initialize user service
	userService := application.NewUserService(db, jwtService, logger)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userService, logger)

	// Create router
	r := chi.NewRouter()

	// Add middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set default content type if not specified
			if r.Header.Get("Accept") == "" {
				r.Header.Set("Accept", "application/vnd.user-manager.v1+json")
			}
			next.ServeHTTP(w, r)
		})
	})

	// Swagger documentation
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL(fmt.Sprintf("http://localhost:%s/swagger/doc.json", cfg.ServerPort)),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	))

	// Serve Swagger JSON
	r.Get("/swagger/doc.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "docs/swagger.json")
	})

	// API routes
	r.Route("/", func(r chi.Router) {
		// Public routes
		r.Group(func(r chi.Router) {
			r.Post("/users/register", userHandler.Register)
			r.Post("/users/login", userHandler.Login)
		})

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator)

			r.Get("/users/me", userHandler.GetCurrentUser)
			r.Put("/users/me", userHandler.UpdateCurrentUser)
		})

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticator)
			r.Use(authMiddleware.RequireRole("admin"))

			r.Get("/users", userHandler.ListUsers)
			r.Get("/users/{id}", userHandler.GetUser)
			r.Put("/users/{id}", userHandler.UpdateUser)
		})
	})

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.ServerPort),
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Starting server", zap.String("port", cfg.ServerPort))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Server exited properly")
}
