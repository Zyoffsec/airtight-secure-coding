# Express Auth — registration, login, profile

Небольшое серверное приложение на Express: регистрация, вход, страница профиля.
Сессии на cookie, пароли — argon2id, хранение — SQLite (файл создаётся автоматически).

## Запуск

```bash
npm install
cp .env.example .env
# сгенерировать секрет сессии:
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
# вставить его в SESSION_SECRET в .env, затем:
npm start
```

Открыть http://localhost:3000 (или порт из `PORT`).

## Маршруты

| Метод | Путь         | Назначение                                  |
| ----- | ------------ | ------------------------------------------- |
| GET   | `/register`  | форма регистрации                           |
| POST  | `/register`  | создать аккаунт, войти                       |
| GET   | `/login`     | форма входа                                 |
| POST  | `/login`     | вход                                        |
| POST  | `/logout`    | выход (уничтожает сессию)                    |
| GET   | `/profile`   | профиль текущего пользователя (требует входа)|
| POST  | `/profile`   | сохранить имя и bio                          |

## Структура

```
server.js            точка входа, middleware, сессии, роутинг
config.js            чтение env (SESSION_SECRET обязателен, без фолбэка)
db.js                SQLite + схема
models/user.js       все запросы к users (параметризованные)
lib/password.js      argon2id: hash / verify + dummy-hash для единообразного тайминга
lib/validate.js      zod-схемы для тел запросов
lib/logger.js        структурные JSON-логи в stdout
middleware/auth.js   requireAuth / redirectIfAuthed (личность только из сессии)
middleware/csrf.js   синхронизирующий CSRF-токен
routes/auth.js       register / login / logout + rate-limit + lockout
routes/profile.js    просмотр и редактирование профиля
views/               EJS-шаблоны (авто-экранирование)
```

## Что заложено в безопасность

Код писался под secure-coding гейты (Airtight). Кратко:

- Пароли — **argon2id**, проверка через `argon2.verify` (не сравнение строк).
- Логин отвечает одинаково при «нет такого пользователя» и «неверный пароль»
  (в т.ч. по времени — прогоняется dummy-хэш), без утечки, какой аккаунт существует.
- **Rate-limit** на `/login` и `/register` + **блокировка аккаунта** после 5 неудач.
- Сессия **пересоздаётся** при входе и **уничтожается** при выходе; cookie —
  `httpOnly` + `sameSite=lax` (+ `secure` в production).
- Все SQL-запросы **параметризованы**; тела запросов валидируются zod, дальше
  используется только результат валидации (в т.ч. allowlist полей профиля).
- Секрет сессии — только из окружения, без хардкод-фолбэка; `.env` в `.gitignore`.
- CSRF-токен на всех изменяющих формах; структурные логи событий безопасности.

Это покрывает типовые ошибки-упущения в AI-коде, но **не** заменяет полный
аудит: бизнес-логика, уязвимости в зависимостях и вопросы архитектуры сюда не входят.
Для production также нужен HTTPS (`NODE_ENV=production` за TLS-прокси) и общий
store для rate-limit при нескольких воркерах.
