package storage

import (
	"auth/internal/models"
	"database/sql"
)

type UserRepository struct {
	DB *sql.DB
}

func (r *UserRepository) Create(user *models.User) error {
	_, err := r.DB.Exec(
		"INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
		user.Username, user.Email, user.PasswordHash,
	)
	return err
}

func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash, created_at, updated_at FROM users WHERE email=$1",
		email,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByID(id int) (*models.User, error) {
	var user models.User
	err := r.DB.QueryRow(
		"SELECT id, username, email, password_hash, created_at, updated_at FROM users WHERE id=$1",
		id,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Update(user *models.User) error {
	_, err := r.DB.Exec(
		"UPDATE users SET username=$1, email=$2, updated_at=NOW() WHERE id=$3",
		user.Username, user.Email, user.ID,
	)
	return err
}
