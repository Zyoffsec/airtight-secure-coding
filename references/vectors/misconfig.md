# Security misconfiguration

Configuration is where a model optimises for the one thing it can see: the request that fails, the
port it cannot reach, the seed script that has to end in a working login. Ask it to fix a CORS error
and it returns `origin: true, credentials: true`, because that is the setting that makes the error
stop. Ask it to dockerise a Flask app and `debug=True` rides along from the dev command it was copied
from. Ask for a seed script and the admin account gets a password you can guess on the first try. Ask
for Redis in the compose file and the port is published on every interface the host has. None of it
is careless — each is the shortest configuration that makes the thing work, and it does work. This
file gates that surface: who the browser lets read a response, what the framework prints when it
breaks, which accounts exist with known passwords, what is reachable from outside the host, and who
can read the file the setup script just wrote.

## Load this file when

- CORS is configured or a CORS error is being fixed — `cors()`, `Access-Control-Allow-Origin`,
  `allow_origins`, `CORS_ORIGIN_WHITELIST`, a `next.config.js` headers block, an API gateway rule.
- A `Dockerfile`, `docker-compose.yml`, `Procfile`, systemd unit, deploy script, entrypoint or
  settings module is created or edited.
- Code calls `app.run(...)`, `uvicorn --reload`, or reads `DEBUG`, `NODE_ENV`, `FLASK_ENV`,
  `ENVIRONMENT`.
- A seed, migration, fixture or bootstrap script creates a user, admin account or database role.
- A service definition publishes a port, or a datastore, cache, broker or admin UI (Adminer,
  mongo-express, Bull Board, Redis Commander) is added to a stack.
- Setup, install or bootstrap code writes a file that will hold a secret — `.env`, a `*.pem`, a
  service-account JSON, a generated config.
- A binding address appears: `0.0.0.0`, `--bind_ip_all`, `--protected-mode no`, `listen 0.0.0.0`.

## Gates


### Gate 80 — CORS origin allowlist

> Code that configures CORS MUST NOT be emitted unless the set of allowed origins is a list of
> literal strings written in the source, or credentials are disabled and the resource is readable by
> anonymous callers.

**Applies when:** any middleware, decorator, framework option or hand-written header sets
`Access-Control-Allow-Origin` — including `cors()` with no arguments, `origin: true`, `origin: "*"`,
`allow_origins=["*"]`, and `res.header("Access-Control-Allow-Origin", req.headers.origin)`.


**Fix:** Enumerate the origins as literal strings in the source and let the middleware match the
request against that list. An allowlist holds because the header can only ever carry a value you
wrote; reflection does not, because the value is chosen by the page making the request, which is the
attacker. Where the set is genuinely dynamic — per-tenant subdomains — match the origin against a
pattern anchored at both ends and built in the source, never a substring test like
`origin.includes("example.com")`, which `https://example.com.evil.com` satisfies.


### Gate 81 — Debug mode in a deployed configuration

> Configuration that runs the application anywhere but a developer's own machine MUST NOT be emitted
> unless debug mode is off and the framework's environment is set explicitly to production.

**Applies when:** a `Dockerfile`, compose service, Procfile, systemd unit, deploy script or settings
module determines how the app starts — `app.run(debug=True)`, `DEBUG=True`, `FLASK_ENV=development`,
`uvicorn --reload`, or a Node image with no `NODE_ENV` set.


**Fix:** Start the app from a production server in the deployed configuration (`gunicorn`,
`uvicorn` without `--reload`, `node` with `NODE_ENV=production` set in the image) and leave
`app.run()` for the local dev command only. Setting the environment explicitly in the Dockerfile is
the part that matters: an unset variable is not a safe default, it is the development default. Gate
37 governs the error handler you write; this gate governs the one the framework supplies when you
write none.


### Gate 83 — Default account credential

> Code that creates a user, admin account or database role MUST NOT be emitted with its password
> written as a literal, unless the file is a test run by the test runner against a disposable
> database.

**Applies when:** a seed, migration, bootstrap or fixture script inserts an account — `prisma/seed.ts`,
a Django `createsuperuser` call, an `INSERT INTO users`, a `CREATE ROLE`, an admin bootstrap on first
boot.


**Fix:** Read the value from the environment with no fallback and let the seed refuse to run without
it (Gate 31). Note the difference from Gate 30: that gate forbids the literal in the file, and
deleting the line satisfies it. This gate is about what the literal created — an account that still
exists, with that password, after the file is fixed. Change it at the deployment, the way Gate 33
revokes a leaked key. A compose file's `POSTGRES_PASSWORD: postgres` is a different case: it is Gate
30's localhost-fixture escape, and it stays an escape only while Gate 85 keeps the port off the
host's public interfaces.


### Gate 85 — Datastore and admin surface exposure

> A service definition for a datastore, cache, broker or admin UI MUST NOT be emitted publishing a
> port on all interfaces, unless the published port is bound to `127.0.0.1` or the service is
> reachable only on the internal network.

**Applies when:** a compose service, Kubernetes Service, run command or config file decides what a
database, Redis, RabbitMQ, Elasticsearch or a web admin tool listens on — a bare `"6379:6379"`,
`--bind_ip 0.0.0.0`, `--bind_ip_all`, `--protected-mode no`, `type: LoadBalancer` on a datastore.


**Fix:** Drop the `ports` entry for anything only other services talk to, and prefix the rest with
`127.0.0.1:` so the binding is loopback-only. That works because the bind address is decided in the
kernel at listen time — nothing routes to it from outside — whereas a firewall rule is a second
system that has to agree with the first, and with Docker it does not. An admin router mounted inside
the application (`app.use("/admin/queues", ...)`) is not this gate: that one is reachable through the
app's own port and belongs to Gates 10-19.


### Gate 87 — Permissions on generated secret files

> Setup code that writes a file holding a secret MUST NOT be emitted unless the file is created with
> mode `0600`.

**Applies when:** an install script, bootstrap step, key-generation command or first-run routine
writes `.env`, a private key, a token cache or a generated config to disk.


**Fix:** Pass the mode at creation — `{ mode: 0o600 }` in Node, `os.open(path, os.O_WRONLY |
os.O_CREAT | os.O_TRUNC, 0o600)` wrapped in `os.fdopen` in Python. Create-time is the point: writing
the file and then calling `chmod` leaves a window in which the secret is on disk and world-readable,
and a reader only needs to be looping. Note that Node applies `mode` only when it creates the file —
if the path may already exist, unlink it first rather than assume the flag took.


## Out of scope

- **Security headers on HTML responses** — CSP, HSTS, `X-Frame-Options`, `Referrer-Policy`, or
  `helmet` in general. A model does omit them, but there is no canonical set to check against and a
  correct CSP is a property of the application's own markup, so nothing here is binary — and every
  one of these headers is a second layer under a hole that another gate already closes. A gate that
  cannot be failed on sight is advice with a number on it.
- **Directory listing.** Off by default everywhere that matters: Express serves no index without the
  separate `serve-index` package, and nginx ships `autoindex off`. A model has to be asked for it,
  which fails rule 5. Serving the project root instead of a public directory —
  `express.static(__dirname)`, which hands out `.env` and `.git` — is a real default and not yet
  gated; Gate 84 is held for it.
- **Disabling TLS verification** — `rejectUnauthorized: false`, `verify=False`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`. Gate 60 in `crypto.md`, which gates the client the model writes
  and takes the `NODE_TLS_REJECT_UNAUTHORIZED=0` form in a Dockerfile or start script with it — the
  env-var version is this file's shape and that gate's subject, so cite Gate 60 and read the image
  and the start script when you check it. Gate 88 stays unallocated.
- **Outdated packages and unpatched runtimes.** Which version is current is a fact about the world on
  the day the code is written, not something readable in the diff, and `SKILL.md` already places
  third-party flaws outside the scope. What *is* an emission decision is how the dependency is pinned
  and how it arrives — `dependencies.md`, Gates 110-118, which reaches the same conclusion about
  version judgements and gates the hygiene the real audit tools stand on. An install command in a
  Dockerfile is that file's gate, not this one's, even though the Dockerfile is this file's trigger.
- **Cloud infrastructure** — IAM policies, bucket ACLs, security-group CIDRs, Kubernetes RBAC. Real,
  and a model writes `0.0.0.0/0` into a Terraform ingress rule without blinking, but it is a distinct
  surface with its own file formats and failure modes. It needs its own range, not a corner of this
  one.
- **The application's credentials to other services.** Hardcoded keys (Gate 30), env fallbacks
  (Gate 31), the ignore rule before the file (Gate 32), values reaching the client bundle (Gate 35)
  and exception text in a response body (Gate 37) are all `vectors/secrets.md`. This file covers
  configuration that is wrong while holding no secret at all.
- **Range note.** `secrets.md` held Gates 38 and 39 for debug flags and permissive CORS while this
  was two spare numbers in someone else's range. It is not — it is five gates and a topic, so it
  claims 80-89 per the split rule in `gates.md`. Gates 38 and 39 were never published and stay
  unallocated; there is nothing to retire.

## Prove probes

- Gate 80 — send `OPTIONS` (or a `GET` on a read-only route) to the local endpoint with
  `Origin: https://airtight-probe.invalid` and read the response headers -> HELD if
  `Access-Control-Allow-Origin` is absent or carries a literal origin that is not the one sent;
  FAILED if it echoes `https://airtight-probe.invalid`, or is `*` while
  `Access-Control-Allow-Credentials: true` is present. The probe origin is a reserved TLD, so nothing
  resolves and nothing leaves the host.
- Gate 81 — not provable, and the local answer is the wrong one by construction: debug is *supposed*
  to be on where the developer is running it. The configuration this gate is about is the one in the
  image, and probing the deployed host is rail 2. Reason from the `Dockerfile`, compose service or
  settings module.
- Gate 83 — not provable read-only. Confirming the account exists means authenticating as it, which
  mints a session, and confirming it exists in the deployment means probing the deployment. Reason
  from the seed script and the deploy step that invokes it.
- Gate 85 — run `docker compose config` in the developer's own project to render the effective file,
  and `ss -ltn` on their own machine -> HELD if every datastore, cache, broker and admin UI is
  unpublished or bound to `127.0.0.1`; FAILED if a rendered `ports` entry has no interface prefix or
  `ss` shows `0.0.0.0:6379`. Both commands read; neither starts, stops or reconfigures anything. Do
  not connect to the port — the file settles it.
- Gate 87 — `stat -c '%a %n' .env` in the developer's own project, on a file their setup script has
  already written -> HELD if the mode is `600`, FAILED if any group or other bit is set. Read the
  mode, never the contents. If the file does not exist yet, the probe does not run — running their
  setup script to create it is a write, and rail 3 forbids it. Reason from the write call instead.
