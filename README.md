# User Manager Service

A RESTful service for user management with authentication, authorization, and organization features.

## Features

- User registration and management
- JWT-based authentication
- Role-based access control (RBAC)
- Password recovery
- Organization management
- Refresh token mechanism

## Architecture

The project follows a hexagonal architecture with the following layers:

- `domain`: Core business entities and interfaces
- `application`: Use cases and business logic
- `infrastructure`: Database, email, JWT implementations
- `interfaces/http`: HTTP handlers and middlewares

## Getting Started

### Prerequisites

- Go 1.21 or later
- PostgreSQL
- Make

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=usuario
DB_PASSWORD=senha
DB_NAME=usuarios
JWT_SECRET=your-secret-key
```

### Running the Application

```bash
# Install dependencies
make deps

# Run migrations
make migrate

# Start the application
make run

# Run tests
make test
```

## API Documentation

The API documentation is available through Swagger UI. Once the application is running, you can access it at:

```
http://localhost:8080/swagger/index.html
```

### Authentication

The API uses JWT (JSON Web Tokens) for authentication. To access protected endpoints:

1. Register a new user using the `/api/v1/users/register` endpoint
2. Login using the `/api/v1/users/login` endpoint to get your access token
3. Include the token in the `Authorization` header of subsequent requests:
   ```
   Authorization: Bearer <your-access-token>
   ```

### Available Endpoints

#### Public Endpoints
- `POST /api/v1/users/register` - Register a new user
- `POST /api/v1/users/login` - Login and get access token

#### Protected Endpoints (Requires Authentication)
- `GET /api/v1/users/me` - Get current user details
- `PUT /api/v1/users/me` - Update current user details

#### Admin Endpoints (Requires Admin Role)
- `GET /api/v1/users` - List all users
- `GET /api/v1/users/{id}` - Get user by ID
- `PUT /api/v1/users/{id}` - Update user by ID

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

## Project Structure

```
.
├── cmd/                 # Application entry points
├── config/             # Configuration files
├── docs/              # Swagger documentation
├── internal/          # Private application code
│   ├── domain/       # Domain entities and interfaces
│   ├── application/  # Use cases
│   ├── infrastructure/ # External services
│   └── interfaces/   # HTTP handlers
├── migrations/        # Database migrations
└── pkg/              # Public packages
```

## Testing

Run the test suite with:

```bash
make test
```

## License

MIT 