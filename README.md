# Auth Service (Go + PostgreSQL + JWT)

Этот проект — пример реализации **аутентификации и авторизации** на Go с использованием:
- **PostgreSQL** для хранения пользователей и refresh-токенов
- **JWT (JSON Web Token)** для авторизации
- **Cookies** для хранения access и refresh токенов
- **bcrypt** для хэширования паролей
- **Middleware** для защиты маршрутов

---

## 📌 Возможности
- **Регистрация** пользователя (`/register`)
- **Логин** и получение `access_token` + `refresh_token` (`/login`)
- **Выход** (logout) с удалением токенов (`/logout`)
- **Защищённые маршруты** (пример `/profile`)
- Автоматическая проверка `access_token`, обновление его через `refresh_token`
- Пароли хранятся в базе в виде bcrypt-хэша

---

**Регистрация**
**POST /register**
```
{
  "username": "john",
  "email": "john@example.com",
  "password": "123456"
}
```
**Ответ: 201 Created**

**Логин**
**POST /login**
```
{
  "email": "john@example.com",
  "password": "123456"
}
```
**Ответ: 200 OK**

Устанавливает cookies:
    ```access_token (живет 15 минут)
    refresh_token (живет 7 дней)```
**Выход**
**POST /logout**
    ```Удаляет токены в БД и cookies.```
    
  **Ответ: 204 No Content**
    
**Профиль (защищённый маршрут)**
**GET /profile**

    ```
    Требует валидный access_token (в cookie).
    ```
    
**Ответ: Ваш user ID: <id>**
    
**🔑 Как работает авторизация?**
    ```---При логине выдается access_token (JWT) и refresh_token.
    ---access_token нужен для запросов к защищенным маршрутам.
    ---Если access_token истек, AuthMiddleware проверяет refresh_token и автоматически создает новый access_token.```
