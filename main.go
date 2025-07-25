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
	// Подключение к базе данных
	db, err := sql.Open("postgres", "postgres://postgres:123@localhost:5432/users?sslmode=disable")
	if err != nil {
		log.Fatal("Ошибка подключения к базе данных:", err)
	}
	defer db.Close()

	// Проверяем соединение
	if err := db.Ping(); err != nil {
		log.Fatal("База данных недоступна:", err)
	}

	// Создаем обработчики
	handler := handlers.NewHandler(db)

	// Публичные маршруты
	http.HandleFunc("/register", handler.Register)
	http.HandleFunc("/login", handler.Login)
	http.HandleFunc("/logout", handler.Logout)

	// Пример защищенного маршрута
	http.Handle("/profile", handler.AuthMiddleware(http.HandlerFunc(profileHandler)))

	log.Println("Сервер запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// profileHandler — защищённый эндпоинт
func profileHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := handlers.GetUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Write([]byte("Ваш user ID: " + fmt.Sprint(userID)))
}
