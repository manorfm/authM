package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ipede/user-manager-service/internal/application"
	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/ipede/user-manager-service/internal/infrastructure/jwt"
	"github.com/ipede/user-manager-service/internal/infrastructure/repository"
	httprouter "github.com/ipede/user-manager-service/internal/interfaces/http"
	"github.com/ipede/user-manager-service/internal/interfaces/http/middleware/auth"
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

	// Initialize services
	jwtService := jwt.New(
		cfg.JWTSecret,
		cfg.JWTAccessDuration,
		cfg.JWTRefreshDuration,
	)

	userRepo := repository.NewUserRepository(db)
	userService := application.NewUserService(userRepo, logger)
	authService := application.NewAuthService(userRepo, jwtService, logger)

	// Initialize auth middleware
	authMiddleware := auth.NewAuthMiddleware(jwtService, logger)

	// Create router
	router := httprouter.NewRouter(authService, userService, authMiddleware, logger)

	// Start server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.ServerPort),
		Handler:      router,
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
