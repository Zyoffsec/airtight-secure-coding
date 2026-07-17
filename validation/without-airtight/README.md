# Airtight Auth

Минимальный сайт на **Express** с регистрацией, входом и профилем.

## Стек

- **Express** — веб-сервер и роутинг
- **EJS** — серверные шаблоны
- **better-sqlite3** — хранилище пользователей (файл `data/app.sqlite`)
- **bcryptjs** — хеширование паролей (12 раундов)
- **express-session** + **connect-flash** — сессии и flash-сообщения
- **dotenv** — конфигурация через `.env`

## Запуск

```bash
npm install
cp .env.example .env      # затем поменяй SESSION_SECRET
npm start                 # или npm run dev — с авто-перезапуском
```

Открой http://localhost:3000

> Порт задаётся переменной `PORT` (по умолчанию 3000). Если он занят — запусти,
> например, `PORT=3100 npm start`.

## Что есть

| Маршрут            | Метод | Назначение                                   |
| ------------------ | ----- | -------------------------------------------- |
| `/`                | GET   | Главная                                      |
| `/register`        | GET/POST | Регистрация (авто-вход после успеха)      |
| `/login`           | GET/POST | Вход по имени пользователя **или** email  |
| `/logout`          | POST  | Выход                                         |
| `/profile`         | GET   | Профиль — только для залогиненных             |

## Безопасность

- Пароли хранятся только в виде bcrypt-хеша.
- Сессионная cookie: `httpOnly`, `sameSite=lax`, `secure` в production.
- `session.regenerate()` при входе/регистрации — защита от фиксации сессии.
- Одинаковый текст ошибки при неверном логине/пароле — не раскрываем, есть ли аккаунт.
- Параметризованные SQL-запросы (better-sqlite3 prepared statements).
- Валидация имени/email/пароля на сервере, вывод экранируется EJS (`<%= %>`).

## Структура

```
server.js            точка входа, middleware, сессии
db.js                инициализация SQLite + схема
models/user.js       работа с пользователями + bcrypt
lib/validate.js      валидация форм
middleware/auth.js   loadUser / requireAuth / requireGuest
routes/pages.js      главная и профиль
routes/auth.js       регистрация, вход, выход
views/               EJS-шаблоны
public/css/style.css стили
```
