package storage

import (
	"auth/internal/models"
	"database/sql"
)

type RefreshTokenRepository struct {
	DB *sql.DB
}

func (r *RefreshTokenRepository) Create(token *models.RefreshToken) error {
	_, err := r.DB.Exec(
		"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
		token.UserID, token.Token, token.ExpiresAt,
	)
	return err
}

func (r *RefreshTokenRepository) Find(token string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	err := r.DB.QueryRow(
		"SELECT id, user_id, token, expires_at, created_at FROM refresh_tokens WHERE token=$1",
		token,
	).Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt, &rt.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *RefreshTokenRepository) Delete(token string) error {
	_, err := r.DB.Exec("DELETE FROM refresh_tokens WHERE token=$1", token)
	return err
}

func (r *RefreshTokenRepository) Update(oldToken, newToken string, expiresAt string) error {
	_, err := r.DB.Exec(
		"UPDATE refresh_tokens SET token=$1, expires_at=$2 WHERE token=$3",
		newToken, expiresAt, oldToken,
	)
	return err
}
