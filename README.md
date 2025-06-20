# AuthM

[![Go Version](https://img.shields.io/badge/Go-1.23-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](https://github.com/manorfm/authM/releases)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/manorfm/authM/actions)
[![Coverage](https://img.shields.io/badge/Coverage-80%25-brightgreen.svg)](https://github.com/manorfm/authM/actions)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/r/manorfm/authM)

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
- Header-based API versioning
- Comprehensive error handling
- Configurable JWT strategies
- Multi-factor authentication (MFA) with TOTP
- Backup codes for MFA recovery
- MFA ticket-based verification flow

## Architecture

The project follows a hexagonal architecture with the following layers:

- `domain`: Core business entities, interfaces, and domain-specific errors
- `application`: Use cases and business logic
- `infrastructure`: Database, JWT, and other external service implementations
- `interfaces/http`: HTTP handlers, middlewares, and OpenAPI/Swagger documentation

### API Versioning

The service uses header-based versioning through the `Accept` header:

```http
Accept: application/vnd.manorfm.v1+json
```

This approach:
- Keeps URLs clean and stable
- Allows for multiple API versions to coexist
- Provides better separation of concerns
- Follows REST best practices

### Error Handling

The service implements a comprehensive error handling system with:

- Domain-specific error types (`BusinessError` and `InfraError`)
- Standardized error codes (U0001-U0044)
- Detailed error messages and codes
- Proper error wrapping and context
- HTTP status code mapping

Example error response:
```json
{
  "code": "U0001",
  "message": "Invalid credentials"
}
```

### JWT Strategy

The service implements a composite JWT strategy that:

- Supports multiple signing strategies (Vault and Local)
- Provides automatic fallback mechanisms
- Implements key rotation
- Handles token verification with proper error handling
- Supports JWKS for public key distribution

The strategy automatically falls back to local signing if Vault is unavailable, ensuring high availability.

## Getting Started

### Prerequisites

- Go 1.23 or later
- PostgreSQL
- Make
- Docker (optional)
- Vault (optional, for key management)

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
RSA_KEY_SIZE=2048
JWKS_CACHE_DURATION=1h

# Server Configuration
SERVER_PORT=8080
SERVER_HOST=localhost
SERVER_URL=http://localhost:8080

# Vault Configuration (Optional)
ENABLE_VAULT=true
VAULT_ADDRESS=http://localhost:8200
VAULT_TOKEN=your-token
VAULT_MOUNT_PATH=transit/authM
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

# TOTP Configuration
TOTP_ISSUER=AuthM
TOTP_ALGORITHM=SHA1
TOTP_DIGITS=6
TOTP_PERIOD=30
TOTP_BACKUP_CODES_COUNT=10
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
docker build -t authM .

# Run with Docker
docker run -p 8080:8080 --env-file .env authM
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

1. Register a new user using the `/api/users/register` endpoint
2. Login using the `/api/auth/login` endpoint to get your access token
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
- `POST /api/users/register` - Register a new user
- `POST /api/auth/login` - Login and get access token
- `POST /api/auth/verify-email` - Verify email address
- `POST /api/auth/request-password-reset` - Request password reset
- `POST /api/auth/reset-password` - Reset password
- `POST /api/auth/verify-mfa` - Verify MFA code
- `POST /api/oauth2/token` - OAuth2 token endpoint
- `GET /.well-known/openid-configuration` - OpenID Provider Configuration
- `GET /.well-known/jwks.json` - JSON Web Key Set

#### Protected Endpoints (Requires Authentication)
- `GET /api/users/{id}` - Get user by ID
- `PUT /api/users/{id}` - Update user by ID
- `GET /api/oauth2/authorize` - OAuth2 authorization endpoint
- `POST /api/oauth2/token` - OAuth2 token endpoint
- `GET /api/oauth2/userinfo` - Get user information
- `POST /api/totp/enable` - Enable TOTP for user
- `POST /api/totp/verify` - Verify TOTP code
- `POST /api/totp/verify-backup` - Verify TOTP backup code
- `POST /api/totp/disable` - Disable TOTP for user

#### Admin Endpoints (Requires Admin Role)
- `GET /api/users` - List all users
- `GET /api/oauth2/clients` - List OAuth2 clients
- `POST /api/oauth2/clients` - Create OAuth2 client
- `GET /api/oauth2/clients/{id}` - Get OAuth2 client
- `PUT /api/oauth2/clients/{id}` - Update OAuth2 client
- `DELETE /api/oauth2/clients/{id}` - Delete OAuth2 client

### Error Responses

The API uses standard HTTP status codes and returns error details in the following format:

```json
{
  "code": "ERROR_CODE",
  "message": "Error message"
}
```

Common error codes:
- `U0001` - Invalid credentials
- `U0002` - Invalid client
- `U0003` - Invalid authorization code
- `U0004` - Authorization code expired
- `U0005` - Invalid PKCE
- `U0006` - Invalid user ID
- `U0007` - Resource not found
- `U0008` - Invalid resource
- `U0009` - Resource already exists
- `U0010` - Invalid scope
- `U0011` - Invalid field
- `U0012` - Path parameter not found
- `U0013` - Invalid request body
- `U0014` - Unauthorized
- `U0015` - Internal server error
- `U0016` - Failed to generate token
- `U0017` - Database query error
- `U0018` - Forbidden
- `U0019` - Invalid token
- `U0020` - Invalid duration
- `U0021` - Token expired
- `U0022` - Token not yet valid
- `U0023` - Token has no roles
- `U0024` - Token subject required
- `U0025`