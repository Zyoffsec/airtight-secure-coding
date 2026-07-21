# Credentials and authentication

Asked for "a login form," a model emits a plausible one: password stored as a SHA-256 digest, a session id minted once and never rotated, a bare cookie, an error that distinguishes "no such email" from "wrong password," a reset token that never expires. Each is what the request asked for and each is a defect. This file gates those emission decisions: how a password is stored and compared, how a session is minted, carried and ended, and how a token dies. Lead with the rule, apply the fix.

## Load this file when

- The request mentions login, signup, registration, sign-out, "auth", or a password reset flow.
- Any code path writes, reads or compares a user password — including seed scripts, fixtures and admin user creation.
- Code mints a value that later proves identity: session id, session token, API key, reset token, email-verification token, magic link.
- Code sets or reads a session cookie, or configures session middleware (`express-session`, `iron-session`, Django `SESSION_*`, Flask `session`).
- A handler compares a caller-supplied secret against a stored or expected value.
- A handler returns different responses for "user not found" and "wrong password", or for a known versus unknown email on a reset request.
- A password-change or account-recovery handler updates a credential.

## Gates

### Gate 1 — Auth response uniformity

> Code that answers a login or password-reset request MUST NOT ship unless the response for an unknown account and for a known account with a bad credential are identical in status code, body, shape **and in the password-hashing work performed**.

**Applies when:** a handler looks up a user by a caller-supplied identifier and branches on whether that user exists before checking the credential.

Fix: hash unconditionally. Compute one throwaway hash at startup with the same parameters as real ones, verify against it when the lookup misses, and collapse both outcomes into one 401 with one body. For reset requests, always answer "if that address has an account, a link has been sent" — after the same work either way.

```js
// A throwaway hash, computed once at startup with the same parameters as real ones.
const DUMMY_HASH = await argon2.hash(crypto.randomBytes(32).toString("hex"));

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.user.findUnique({ where: { email } });

  // Verify unconditionally — against the real hash, or the throwaway one when the
  // account does not exist — so both paths cost the same.
  const verified = await argon2.verify(user ? user.passwordHash : DUMMY_HASH, password);

  if (!user || !verified) return res.status(401).json({ error: "Invalid email or password" });
  return startSession(req, res, user);
});
```

Fails: `user && (await argon2.verify(...))` — the `&&` short-circuits, so an unknown email skips the KDF and returns in microseconds while a real account pays full cost, leaking a membership oracle by timing. Also fails: an early status branch (404 for unknown, 401 for wrong password). A uniform error message alone is only half the fix.

### Gate 2 — Constant-time secret comparison

> Code that compares a caller-presented secret against an expected value MUST NOT ship unless the comparison uses a constant-time function (`crypto.timingSafeEqual`, `hmac.compare_digest`, or the credential library's own verify function).

**Applies when:** an API key, session token, reset token, webhook signature or other bearer secret is checked against a stored or configured value.

Fix: compare with `crypto.timingSafeEqual` on equal-length buffers (Python: `hmac.compare_digest`). For passwords, do not compare at all — call the hashing library's verify, which is constant-time by construction (Gate 3).

```js
import { timingSafeEqual } from "node:crypto";

function keyMatches(presented, expected) {
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

Fails: `presented === expected`. `===` returns at the first differing byte, so its duration leaks how much of the guess was right.

### Gate 3 — Password storage

> Code that stores a password MUST NOT ship unless the password is hashed with bcrypt, argon2 or scrypt.

**Applies when:** any code path writes a user-supplied password to a database, file, cache or log — registration, password reset, admin user creation, seed and fixture scripts.

Fix: hash with argon2id (`argon2-cffi`), or bcrypt where argon2 is unavailable. Store the library's full encoded output — it carries the salt and parameters — and verify with the library's own verify function, never by re-hashing and comparing strings.

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

def register(email: str, password: str) -> None:
    db.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (email, ph.hash(password)),
    )
```

Fails: `hashlib.sha256(password.encode()).hexdigest()`. Fast, general-purpose hashes (SHA-256, MD5, unsalted) are cracked at enormous rates offline; password KDFs are deliberately slow and per-password salted.

### Gate 5 — Session lifecycle

> Code that establishes or ends an authenticated session MUST NOT ship unless it issues a new session identifier on successful login and destroys the server-side session record on logout.

**Applies when:** a login handler attaches a user to a session, or a logout handler ends one.

Fix: call the session store's regenerate on successful login and its destroy on logout, instead of assigning and clearing a `userId` field. Apply the same destroy to every session the user owns when their password changes.

```js
async function login(req, res, user) {
  req.session.regenerate(() => {
    req.session.userId = user.id;
    res.json({ ok: true });
  });
}

function logout(req, res) {
  req.session.destroy(() => res.json({ ok: true }));
}
```

Fails: setting `req.session.userId = user.id` without regenerate (a pre-login cookie survives into the authenticated session — fixation), or clearing `userId = null` on logout instead of destroying the record (a copied cookie keeps working).

### Gate 6 — Identity token entropy

> Code that generates a session token, reset token, API key or magic link MUST NOT ship unless the value comes from a cryptographic random source (`crypto.randomBytes`, `crypto.randomUUID`, `secrets`) with at least 128 bits of entropy.

**Applies when:** any code mints a value that will later be accepted as proof of identity.

Fix: use `crypto.randomBytes(32).toString("base64url")` (Python: `secrets.token_urlsafe(32)`). Where session middleware mints its own identifier, let it.

```js
import { randomBytes } from "node:crypto";

function newResetToken() {
  return randomBytes(32).toString("base64url");
}
```

Fails: `Math.random()` or `Date.now()`-derived tokens. A non-crypto PRNG's state is recoverable from a few outputs, so an attacker can predict the next token — the long, random-looking string hides it.

### Gate 7 — Session cookie flags

> Code that sets a cookie carrying a session identifier or auth token MUST NOT ship unless the cookie sets `httpOnly`, `secure` and `sameSite`.

**Applies when:** `res.cookie`, a raw `Set-Cookie` header, `cookies().set`, or session middleware config attaches a value that authenticates the request.

Fix: set all three. Each guards a distinct takeover path — `httpOnly` keeps injected script from reading the cookie, `secure` keeps it off plain HTTP, `sameSite` keeps other sites from sending it. If local dev runs without TLS, gate only `secure` on the environment — never the other two.

```js
res.cookie("sid", token, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  maxAge: 1000 * 60 * 60 * 24 * 7,
});
```

Fails: a cookie set with only `maxAge` (or any of the three flags missing).

### Gate 8 — Reset token expiry and single use

> Code that redeems a password-reset, magic-link or email-verification token MUST NOT ship unless it rejects the token once an expiry timestamp has passed and marks the token used inside the same transaction that applies the change.

**Applies when:** a handler accepts a token from a link and acts on the account it belongs to.

Fix: give the token row an `expiresAt` (an hour is generous) and a `usedAt`; reject when either check fails; write `usedAt` in the same transaction as the password update so two concurrent redemptions cannot both land.

```js
app.post("/reset/confirm", async (req, res) => {
  const { token, password } = req.body;
  const row = await db.resetToken.findUnique({ where: { token } });
  if (!row || row.usedAt || row.expiresAt < new Date()) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }
  const hash = await argon2.hash(password);
  await db.$transaction([
    db.resetToken.update({ where: { token }, data: { usedAt: new Date() } }),
    db.user.update({ where: { id: row.userId }, data: { passwordHash: hash } }),
  ]);
  res.json({ ok: true });
});
```

Fails: redeeming on existence alone, with no `expiresAt`/`usedAt` check — an emailed link stays a permanent, reusable key.

## Out of scope

- **Multi-factor authentication.** A product feature, not a default the model got wrong.
- **Password strength rules and breach-list checks.** Policy; nothing binary to gate.
- **Login rate limiting and lockout.** Presence is gated in `design.md` as Gates 120 and 121; the threshold, window, counter store and lockout duration are deployment values no line of code passes or fails. Cite Gate 120/121 for the absence.
- **"Email already registered" on signup.** A real enumeration channel but a deliberate product tradeoff — the remedy is a different flow (answer 202 unconditionally, move the news to the inbox), not a different line. Report it as an ungated finding and say so plainly: signup is usually the loudest membership oracle, louder than anything Gate 1 catches, so closing a `/login` timing gap while `/register` answers 409 per address buys nothing. Gate 1 stops at login and reset, where no such tradeoff exists.
- **OAuth and OIDC flow correctness** — `state`, PKCE, `redirect_uri`. Provider-specific; redirect handling generally belongs to Gates 40-49.
- **What an authenticated session may do.** Ownership and role checks are Gates 10-19; a signing key or DB password in source is Gates 30-39; the shape of the login body is Gates 40-49.

## Prove probes

- Gate 1 — POST the login endpoint twice with the same wrong password, once for a registered address and once for an unregistered one -> HELD if status, body and shape are byte-identical, FAILED if they differ at all.
- Gate 2 — not provable read-only. Separating a timing signal from network noise needs volume the rails do not allow. Reason from code.
- Gate 3 — not provable read-only. Reaching a stored hash requires a write through the endpoint under test. Reason from code.
- Gate 5 — not provable read-only. Login and logout both mutate session state. Reason from code.
- Gate 6 — not provable read-only. Entropy is not established by a handful of samples. Reason from code.
- Gate 7 — GET any unauthenticated page that issues a session cookie and read the `Set-Cookie` header -> HELD if it carries `HttpOnly`, `Secure` and `SameSite`, FAILED if any is absent. If no cookie is issued before login, report UNKNOWN and reason from code.
- Gate 8 — not provable read-only. Testing double-redemption rewrites a password. Reason from code.
