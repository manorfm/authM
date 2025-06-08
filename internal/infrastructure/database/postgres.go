package database

import (
	"context"
	"fmt"
	"time"

	"github.com/ipede/user-manager-service/internal/infrastructure/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// Postgres represents a PostgreSQL database connection
type Postgres struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

// NewPostgres creates a new PostgreSQL connection
func NewPostgres(ctx context.Context, cfg *config.Config, log *zap.Logger) (*Postgres, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName,
	)

	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing database config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating connection pool: %w", err)
	}

	// Test the connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("error connecting to database: %w", err)
	}

	return &Postgres{
		pool: pool,
		log:  log,
	}, nil
}

// Close closes the database connection
func (p *Postgres) Close() {
	p.pool.Close()
}

// BeginTx starts a new transaction
func (p *Postgres) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return p.pool.BeginTx(ctx, pgx.TxOptions{})
}

// Exec executes a query without returning any rows
func (p *Postgres) Exec(ctx context.Context, sql string, args ...interface{}) error {
	_, err := p.pool.Exec(ctx, sql, args...)
	if err != nil {
		p.log.Error("Exec error", zap.String("sql", sql), zap.Any("args", args), zap.Error(err))
	}
	return err
}

// Query executes a query that returns rows
func (p *Postgres) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return p.pool.Query(ctx, sql, args...)
}

// QueryRow executes a query that is expected to return at most one row
func (p *Postgres) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return p.pool.QueryRow(ctx, sql, args...)
}

// Ping checks if the database connection is alive
func (p *Postgres) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.pool.Ping(ctx)
}

// ExecRaw executes a raw SQL query without returning any rows
func (p *Postgres) ExecRaw(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return p.pool.Exec(ctx, sql, args...)
}
