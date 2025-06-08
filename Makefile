.PHONY: deps test build run clean lint swagger migrate migrate-up migrate-down migrate-force migrate-reset

# Variables
BINARY_NAME=user-manager-service
BIN_DIR=bin
BINARY_PATH=$(BIN_DIR)/$(BINARY_NAME)
MIGRATION_UP_DIR=migrations/up
MIGRATION_DOWN_DIR=migrations/down
MIGRATE_CMD=go run cmd/migrate/main.go

# Install dependencies
deps:
	go mod tidy
	go mod download

# Run tests
test:
	go test -timeout=240s -v ./... -cover

# Build the application (ensure bin/ exists)
build:
	mkdir -p $(BIN_DIR)
	go build -o $(BINARY_PATH) cmd/main.go

# Run the application (builds first)
run: build
	./$(BINARY_PATH)

# Clean build artifacts
clean:
	go clean
	rm -rf $(BIN_DIR)

# Lint the code
lint:
	golangci-lint run

# Generate Swagger documentation
swagger:
	swag init -g cmd/main.go -o docs

# Run database migrations
migrate:
	$(MIGRATE_CMD)

migrate-up:
	$(MIGRATE_CMD) -up -dir $(MIGRATION_UP_DIR)

migrate-down:
	$(MIGRATE_CMD) -down -dir $(MIGRATION_DOWN_DIR)

migrate-force:
	$(MIGRATE_CMD) -force $(VERSION) -dir $(MIGRATION_UP_DIR)

migrate-force-0:
	$(MIGRATE_CMD) -force 0 -dir $(MIGRATION_UP_DIR)

migrate-reset: migrate-force-0 migrate-up  ## Reset migrations to version 0 and run up

# Run all checks
check: lint test
