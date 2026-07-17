# Configuration and secrets

Covers the application's own credentials to other services — API keys, database URLs, signing secrets — and where they must not end up: source, git history, the browser bundle, error bodies. Each gate leads with its rule and its fix.

## Load this file when

- The request or diff involves an API key, token, database URL, connection string or signing secret.
- A `.env`, `.env.example`, `docker-compose.yml`, CI workflow, Kubernetes manifest or settings module is created or edited.
- Code reads `process.env`, `os.environ`, `os.getenv` or a config object.
- A credential value appears in the conversation.
- Client-side code makes an authenticated outbound call, or a `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` variable is introduced.
- An error handler returns anything derived from a caught exception to a caller.
- The change adds a third-party integration.

## Gates

### Gate 30 — Hardcoded credential literal

> Code that authenticates to a service MUST NOT be emitted with the credential written as a literal in the source, unless the value is one the service publishes for public use or a fixture credential for a localhost-only service.

**Fix:** Read the value from the environment at the point of use (`process.env.STRIPE_SECRET_KEY`) and let the process fail if absent (Gate 31). If it was already in source, it is leaked: Gate 33 applies.

**Applies when:** any key, token, password, connection string or signing secret is about to appear as a string in a tracked file (source, `docker-compose.yml`, CI workflow, test fixture, README, `.env.example`). A tracked template gets placeholders, never a copied value.

**Fails:** `require("stripe")("sk_live_...")`.

### Gate 31 — Secret fallback default

> Code that reads a signing, encryption or authentication secret from the environment MUST NOT be emitted with a fallback value, unless the fallback is to raise or exit.

**Fix:** Index the environment directly (`os.environ["SECRET_KEY"]`, or a schema that marks the field required) so a missing value stops the process at startup.

**Applies when:** a config module resolves `SECRET_KEY`, `JWT_SECRET`, `SESSION_SECRET`, `ENCRYPTION_KEY` or an API key via `os.getenv(name, default)`, `process.env.X || "..."`, `process.env.X ?? "..."`, or a settings default.

**Fails:** `os.getenv("SECRET_KEY", "dev-secret-change-in-production")` — a hardcoded secret, and silent: a deploy that forgets the variable boots on the public default.

### Gate 32 — Ignore rule before the file

> A file that will hold real secret values or credential material MUST NOT be created unless the same change contains a `.gitignore` rule matching its path, or an existing rule already matches it.

**Fix:** Write the `.gitignore` rule in the same change, before the file, with `!.env.example` so the template stays tracked. If the file is already tracked, Gate 33 applies.

`(example omitted)`

**Applies when:** emitting `.env`, `secrets.json`, a service-account JSON, a `*.pem`, or any local config holding a live value — **and equally when emitting the schema or connection for a file-backed datastore** (`*.db`, `*.sqlite`, `data/`, a dump or backup path). A SQLite file the app writes to holds every password hash and session token; committed alongside the `.env`, it is an offline cracking target. The gate applies when the file is named in source.

**Fails:** creating `.env` or `notes.db` while `.gitignore` is left untouched.

### Gate 33 — Removing a committed secret

> A change that removes a secret from a tracked file MUST NOT be reported as remediation unless it is accompanied by an instruction to revoke and reissue that secret at the issuing service.

**Fix:** Move the value to `os.environ[...]` **and** state that the key is compromised, naming the revocation step at the issuer. The key is in history and still live; deleting the line does not un-publish it, and rewriting history does not substitute for revocation.

**Applies when:** a fix takes a live credential out of source, config, a template, a notebook or a test fixture under version control.

**Fails:** reporting "moved the Stripe key out of source into an environment variable" with no revoke-and-reissue instruction.

### Gate 35 — Secrets in the client bundle

> Code that runs in the browser MUST NOT be emitted holding a credential, unless it is one the service publishes for client use (a Stripe publishable key, a Firebase web API key, a PostHog project key).

**Fix:** Put the call behind a server route that holds the key server-side and forward the result. The browser gets the answer, never the credential.

**Applies when:** a component, hook or any client-reachable module calls a third-party API directly; or a `NEXT_PUBLIC_*`, `VITE_*` or `REACT_APP_*` variable is introduced for a secret. The prefix is not a permission — the bundler inlines the value into JavaScript any visitor can read.

**Fails:** a client fetch to `https://api.openai.com/...` with `Authorization: Bearer ${process.env.NEXT_PUBLIC_OPENAI_API_KEY}`.

### Gate 37 — Secrets in error responses

> An error handler MUST NOT be emitted returning an exception's message, stack or repr to the client, unless the message is a literal written in the source.

**Fix:** Return a literal message and status code (`res.status(500).json({ error: "Internal server error" })`). Send the exception to the log instead.

**Applies when:** any `catch` or `except` returns something derived from the caught exception in an HTTP response body. Driver exceptions carry configuration: a connection failure puts the full DSN, password included, in `err.message`; a query error names tables and columns.

**Fails:** `res.status(500).json({ error: err.message, stack: err.stack })`.

## Out of scope

- **Rotation schedules, key lifetime policy, choice of secret manager.** Operations preference, not an emission decision; Gate 33 covers only the rotation an already-leaked key forces.
- **A key pasted into an AI chat, ticket or screenshot.** Not gateable; treat as published and reissue. The gateable half is Gate 30 — it must not be written back into the repo.
- **Purging a secret from git history** with `filter-repo` or BFG. Does not un-publish the key; cleanup after rotation, never instead of it.
- **Debug flags and permissive CORS.** `DEBUG=True`, `origin: "*"` are Gates 81 and 80 in `misconfig.md`. Gates 38 and 39 stay unallocated.
- **Secrets reaching log sinks.** Gate 100 in `logging.md`. Gate 36 stays unallocated; cite Gate 100.
- **Real values copied into a committed `.env.example`.** Gate 34 is held for it; Gate 30 already forbids the value in the tracked template.
- **The application's own users' passwords, session and reset tokens.** Credentials range, Gates 1-9.

## Prove probes

- Gate 30 — not provable read-only. Reason from code.
- Gate 31 — not provable read-only. Reason from code.
- Gate 32 — run `git check-ignore -v .env` -> HELD if it prints a matching rule, FAILED if it exits non-zero while a `.env` holding real values exists.
- Gate 33 — not provable read-only. `git log --all --oneline -- .env` shows a secret file is in history, but reissue is known only at the issuer. Reason from code.
- Gate 35 — request the client bundle the dev server serves and search it for the first eight characters of the key -> HELD if no match, FAILED if the value appears. Report reachability, never the value.
- Gate 37 — `GET` a local route with a nonexistent id, then a malformed id -> HELD if the body is a literal message with no stack frame, driver text or DSN; FAILED if it carries an exception message, stack, table name or DSN. If neither reaches the error path, UNKNOWN.
