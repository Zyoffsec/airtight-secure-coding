# Airtight build — written WITH the skill loaded

A small server-side **Express** app: registration, login, profile page. This is the
treatment arm of the A/B test: a Claude Code session given the identical brief as the
control build, with the Airtight skill loaded. The code is committed verbatim as
evidence. Cookie sessions, argon2id passwords, SQLite storage (file created
automatically).

## Run

```bash
npm install
cp .env.example .env
# generate a session secret:
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
# put it in SESSION_SECRET in .env, then:
npm start
```

Open http://localhost:3000 (or the port from `PORT`).

## Routes

| Method | Path        | Purpose                                        |
| ------ | ----------- | ---------------------------------------------- |
| GET    | `/register` | registration form                              |
| POST   | `/register` | create an account, log in                      |
| GET    | `/login`    | login form                                     |
| POST   | `/login`    | log in                                         |
| POST   | `/logout`   | log out (destroys the session)                 |
| GET    | `/profile`  | current user's profile (login required)        |
| POST   | `/profile`  | save display name and bio                      |

## Layout

```
server.js            entry point, middleware, sessions, routing
config.js            env reading (SESSION_SECRET required, no fallback)
db.js                SQLite + schema
models/user.js       all user queries (parameterized)
lib/password.js      argon2id: hash / verify + dummy hash for timing uniformity
lib/validate.js      zod schemas for request bodies
lib/logger.js        structured JSON logs to stdout
middleware/auth.js   requireAuth / redirectIfAuthed (identity from session only)
middleware/csrf.js   synchronizer CSRF token
routes/auth.js       register / login / logout + rate limit + lockout
routes/profile.js    profile view and edit
views/               EJS templates (auto-escaping)
```

## What the gates put in

The code was written under Airtight's secure-coding gates. In short:

- Passwords — **argon2id**, verified via `argon2.verify` (never string comparison).
- Login answers identically for "no such user" and "wrong password" — including in
  timing, via a dummy-hash verify — leaking nothing about which accounts exist.
- **Rate limit** on `/login` and `/register` plus **account lockout** after 5 failures.
- The session is **regenerated** on login and **destroyed** on logout; the cookie is
  `httpOnly` + `sameSite=lax` (+ `secure` in production).
- Every SQL query is **parameterized**; request bodies are validated with zod and only
  the validator's output is used afterwards (including a field allowlist for the
  profile).
- The session secret comes only from the environment, with no hardcoded fallback;
  `.env` is gitignored.
- A CSRF token on every mutating form; structured security-event logs.

This covers the typical omission-style mistakes in AI-written code, but it does
**not** replace a full audit: business logic, vulnerable dependencies and
architecture are out of scope. Production additionally needs HTTPS
(`NODE_ENV=production` behind a TLS proxy) and a shared rate-limit store when
running multiple workers.
