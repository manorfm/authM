package repository

import (
	"context"

	"github.com/ipede/user-manager-service/internal/domain"
	"github.com/ipede/user-manager-service/internal/infrastructure/database"
	"github.com/oklog/ulid/v2"
)

type UserRepository struct {
	db *database.Postgres
}

func NewUserRepository(db *database.Postgres) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	return r.db.Exec(ctx, `
		INSERT INTO users (id, name, email, password, phone, created_at, updated_at, roles)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, user.ID.String(), user.Name, user.Email, user.Password, user.Phone, user.CreatedAt, user.UpdatedAt, user.Roles)
}

func (r *UserRepository) FindByID(ctx context.Context, id ulid.ULID) (*domain.User, error) {
	user := &domain.User{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, email, password, phone, created_at, updated_at, roles
		FROM users WHERE id = $1
	`, id.String()).Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Phone, &user.CreatedAt, &user.UpdatedAt, &user.Roles)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	user := &domain.User{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, email, password, phone, created_at, updated_at, roles
		FROM users WHERE email = $1
	`, email).Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Phone, &user.CreatedAt, &user.UpdatedAt, &user.Roles)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *UserRepository) AddRole(ctx context.Context, userID ulid.ULID, role string) error {
	return r.db.Exec(ctx, `
		UPDATE users 
		SET roles = array_append(roles, $1)
		WHERE id = $2
	`, role, userID.String())
}

func (r *UserRepository) Delete(ctx context.Context, id ulid.ULID) error {
	return r.db.Exec(ctx, "DELETE FROM users WHERE id = $1", id.String())
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*domain.User, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, name, email, phone, created_at, updated_at, roles
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		user := &domain.User{}
		err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Phone, &user.CreatedAt, &user.UpdatedAt, &user.Roles)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	return r.db.Exec(ctx, `
		UPDATE users
		SET name = $1, phone = $2, updated_at = $3
		WHERE id = $4
	`, user.Name, user.Phone, user.UpdatedAt, user.ID.String())
}

func (r *UserRepository) RemoveRole(ctx context.Context, userID ulid.ULID, role string) error {
	return r.db.Exec(ctx, `
		UPDATE users 
		SET roles = array_remove(roles, $1)
		WHERE id = $2
	`, role, userID.String())
}
