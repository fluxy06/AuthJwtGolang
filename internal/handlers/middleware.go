package handlers

import (
	"context"
	"net/http"
	"time"
)

type contextKey string

const userContextKey = contextKey("user_id")

func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessCookie, err := r.Cookie("access_token")
		if err == nil {
			if userID, valid := h.validateJWT(accessCookie.Value); valid {
				ctx := context.WithValue(r.Context(), userContextKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Проверяем refresh_token
		refreshCookie, err := r.Cookie("refresh_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		rt, err := h.refreshTokenRepo.Find(refreshCookie.Value)
		if err != nil || rt.ExpiresAt.Before(time.Now()) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Создаём новый access_token
		newAccess, err := h.createJWT(rt.UserID, 15*time.Minute)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    newAccess,
			HttpOnly: true,
			Secure:   false,
			Path:     "/",
			Expires:  time.Now().Add(15 * time.Minute),
			SameSite: http.SameSiteLaxMode,
		})

		ctx := context.WithValue(r.Context(), userContextKey, rt.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserIDFromContext(ctx context.Context) (int, bool) {
	userID, ok := ctx.Value(userContextKey).(int)
	return userID, ok
}
