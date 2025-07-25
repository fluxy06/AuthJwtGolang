package main

import (
	"auth/internal/handlers"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

func main() {
	db, err := sql.Open("postgres", "postgres://postgres:123@localhost:5432/users?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	handler := handlers.NewHandler(db)

	http.HandleFunc("/register", handler.Register)
	http.HandleFunc("/login", handler.Login)
	http.HandleFunc("/refresh", handler.Refresh)
	http.HandleFunc("/logout", handler.Logout)

	// Пример защищённого эндпоинта
	http.Handle("/profile", handler.AuthMiddleware(http.HandlerFunc(profileHandler)))

	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// profileHandler — пример защищённого ресурса, где доступ только при авторизации
func profileHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := handlers.GetUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Здесь можешь, например, получить данные пользователя из БД и вернуть их
	w.Write([]byte("Your user ID: " + fmt.Sprint(userID)))
}
