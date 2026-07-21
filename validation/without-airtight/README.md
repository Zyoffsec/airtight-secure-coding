# Control build — written WITHOUT Airtight

A minimal **Express** site with registration, login and a profile page. This is the
control arm of the A/B test: a Claude Code session given the same brief as the
Airtight build, with no skill loaded. The code is committed verbatim as evidence —
including its gaps.

> The app calls itself "Airtight Auth" in its own views and `package.json` — that is
> just the project name both sessions were handed in the brief. No Airtight gates were
> involved in writing this build.

## Stack

- **Express** — web server and routing
- **EJS** — server-side templates
- **better-sqlite3** — user store (file `data/app.sqlite`)
- **bcryptjs** — password hashing (12 rounds)
- **express-session** + **connect-flash** — sessions and flash messages
- **dotenv** — configuration via `.env`

## Run

```bash
npm install
cp .env.example .env      # then change SESSION_SECRET
npm start                 # or npm run dev — with auto-restart
```

Open http://localhost:3000

> The port comes from `PORT` (default 3000). If it is taken, run e.g.
> `PORT=3100 npm start`.

## Routes

| Route              | Method   | Purpose                                    |
| ------------------ | -------- | ------------------------------------------ |
| `/`                | GET      | Home                                       |
| `/register`        | GET/POST | Registration (auto-login on success)       |
| `/login`           | GET/POST | Login by username **or** email             |
| `/logout`          | POST     | Logout                                     |
| `/profile`         | GET      | Profile — authenticated users only         |

## What it got right

- Passwords stored only as bcrypt hashes.
- Session cookie: `httpOnly`, `sameSite=lax`, `secure` in production.
- `session.regenerate()` on login/registration — session-fixation protection.
- The same error text for a wrong username and a wrong password — no account
  enumeration through the message body.
- Parameterized SQL throughout (better-sqlite3 prepared statements).
- Server-side validation of username/email/password; output escaped by EJS (`<%= %>`).

## What it silently skipped

See [`validation/README.md`](../README.md) for the full comparison. In short: no rate
limit, no account lockout, no CSRF protection, no security event logging, no length
bounds, and a guessable session-secret fallback — none of which the brief asked for,
which is the point.

## Layout

```
server.js            entry point, middleware, sessions
db.js                SQLite init + schema
models/user.js       user queries + bcrypt
lib/validate.js      form validation
middleware/auth.js   loadUser / requireAuth / requireGuest
routes/pages.js      home and profile
routes/auth.js       register, login, logout
views/               EJS templates
public/css/style.css styles
```
