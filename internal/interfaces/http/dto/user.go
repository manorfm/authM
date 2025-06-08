package dto

import (
	"github.com/ipede/user-manager-service/internal/domain"
)

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Phone string `json:"phone"`
}

func NewUserResponse(user *domain.User) *UserResponse {
	return &UserResponse{
		ID:    user.ID.String(),
		Email: user.Email,
		Name:  user.Name,
		Phone: user.Phone,
	}
}
