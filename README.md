# User Manager Service

[![Go Version](https://img.shields.io/badge/Go-1.23-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](https://github.com/ipede/user-manager-service/releases)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/ipede/user-manager-service/actions)
[![Coverage](https://img.shields.io/badge/Coverage-80%25-brightgreen.svg)](https://github.com/ipede/user-manager-service/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/r/ipede/user-manager-service)

A RESTful service for user management with authentication, authorization, and OAuth2/OpenID Connect support.

## Features

- User registration and management
- JWT-based authentication with key rotation
- Role-based access control (RBAC)
- OAuth2/OpenID Connect support
- Token blacklisting
- Rate limiting
- Refresh token mechanism
- JWKS endpoint for public key distribution
- Email verification system
- Password reset functionality
- Vault integration for key management
- OpenTelemetry integration for observability
- Swagger/OpenAPI documentation

## Architecture

The project follows a hexagonal architecture with the following layers:

- `domain`: Core business entities, interfaces, and domain-specific errors
- `application`: Use cases and business logic
- `infrastructure`: Database, JWT, and other external service implementations
- `interfaces/http`: HTTP handlers, middlewares, and OpenAPI/Swagger documentation

## Getting Started

### Prerequisites

- Go 1.23 or later
- PostgreSQL
- Make
- Docker (optional)

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=usuario
DB_PASSWORD=senha
DB_NAME=usuarios

# JWT Configuration
JWT_ACCESS_DURATION=15m
JWT_REFRESH_DURATION=168h  # 7 days

# Server Configuration
SERVER_PORT=8080
SERVER_HOST=localhost

# Vault Configuration (Optional)
ENABLE_VAULT=true
VAULT_ADDRESS=http://localhost:8200
VAULT_TOKEN=your-token
VAULT_MOUNT_PATH=transit/user-manager-service
VAULT_KEY_NAME=jwt-signing-key

# SMTP Configuration
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=noreply@example.com
SMTP_AUTH_VALIDATION=true
SMTP_USE_TLS=true
SMTP_SKIP_VERIFY=false
```

### Running the Application

```bash
# Install dependencies
make deps

# Run migrations
make migrate-up

# Start the application
make run

# Run tests
make test

# Run linter
make lint

# Generate Swagger documentation
make swagger
```

### Docker Support

```bash
# Build Docker image
docker build -t user-manager-service .

# Run with Docker
docker run -p 8080:8080 --env-file .env user-manager-service
```

## API Documentation

The API documentation is available through Swagger UI. Once the application is running, you can access it at:

```
http://localhost:8080/swagger/index.html
```

### Authentication

The API uses JWT (JSON Web Tokens) for authentication with the following features:

- Access and refresh token pairs
- Token blacklisting for revocation
- Key rotation support with Vault integration
- JWKS endpoint for public key distribution
- Rate limiting to prevent abuse

To access protected endpoints:

1. Register a new user using the `/api/v1/users/register` endpoint
2. Login using the `/api/v1/users/login` endpoint to get your access token
3. Include the token in the `Authorization` header of subsequent requests:
   ```
   Authorization: Bearer <your-access-token>
   ```

### OAuth2/OpenID Connect

The service implements OAuth2 and OpenID Connect protocols with the following endpoints:

- `/oauth2/authorize` - Authorization endpoint
- `/oauth2/token` - Token endpoint
- `/oauth2/userinfo` - UserInfo endpoint
- `/.well-known/openid-configuration` - OpenID Provider Configuration
- `/.well-known/jwks.json` - JSON Web Key Set

### Available Endpoints

#### Public Endpoints
- `POST /api/v1/users/register` - Register a new user
- `POST /api/v1/users/login` - Login and get access token
- `POST /auth/verify-email` - Verify email address
- `POST /auth/request-password-reset` - Request password reset
- `POST /auth/reset-password` - Reset password
- `POST /oauth2/token` - OAuth2 token endpoint
- `GET /.well-known/openid-configuration` - OpenID Provider Configuration
- `GET /.well-known/jwks.json` - JSON Web Key Set

#### Protected Endpoints (Requires Authentication)
- `GET /users/{id}` - Get user by ID
- `PUT /users/{id}` - Update user by ID
- `GET /oauth2/authorize` - OAuth2 authorization endpoint
- `POST /oauth2/token` - OAuth2 token endpoint
- `GET /oauth2/userinfo` - Get user information

#### Admin Endpoints (Requires Admin Role)
- `GET /users` - List all users
- `GET /oauth2/clients` - List OAuth2 clients
- `POST /oauth2/clients` - Create OAuth2 client
- `GET /oauth2/clients/{id}` - Get OAuth2 client
- `PUT /oauth2/clients/{id}` - Update OAuth2 client
- `DELETE /oauth2/clients/{id}` - Delete OAuth2 client

### Error Responses

The API uses standard HTTP status codes and returns error details in the following format:

```json
{
  "message": "Error message",
  "details": "Additional error details (optional)",
  "code": "ERROR_CODE"
}
```

Common error codes:
- `VALIDATION_ERROR` - Invalid input data
- `UNAUTHORIZED` - Missing or invalid authentication
- `NOT_FOUND` - Requested resource not found
- `CONFLICT` - Resource already exists
- `INTERNAL_ERROR` - Server error
- `RATE_LIMIT_EXCEEDED` - Too many requests
- `TOKEN_EXPIRED` - JWT token has expired
- `TOKEN_BLACKLISTED` - JWT token has been revoked

## Project Structure

```
.
├── cmd/                    # Application entry points
│   ├── main.go            # Main application
│   └── migrate/           # Migration tool
├── internal/              # Private application code
│   ├── domain/           # Domain entities and interfaces
│   ├── application/      # Use cases and business logic
│   ├── infrastructure/   # External services implementation
│   │   ├── jwt/         # JWT service implementation
│   │   ├── postgres/    # PostgreSQL implementation
│   │   ├── email/       # Email service implementation
│   │   └── vault/       # Vault integration
│   └── interfaces/       # HTTP handlers and middlewares
├── migrations/           # Database migrations
├── docs/                # Documentation and Swagger files
└── bin/                 # Compiled binaries
```

## Development

### Database Migrations

```bash
# Run all pending migrations
make migrate-up

# Rollback the last migration
make migrate-down

# Reset migrations (rollback all and run up)
make migrate-reset

# Force migration to specific version
make migrate-force VERSION=<version>
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
go test -cover ./...

# Run specific test
go test -run TestName ./...
```

### Code Quality

```bash
# Run linter
make lint

# Run all checks (lint + test)
make check
```

## Observability

The service includes OpenTelemetry integration for:

- Distributed tracing
- Metrics collection
- Structured logging
- Performance monitoring

## Security Features

- JWT key rotation with Vault integration
- Rate limiting
- Input validation
- Secure password hashing
- Email verification
- Token blacklisting
- Role-based access control

## License

MIT 