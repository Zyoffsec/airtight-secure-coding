# Scorecard — the full 67-gate audit

> Run against the registry as it stood at 67 gates. Gates 130 to 132 — cross-site request
> forgery and framing — were added afterwards and are **not scored here**. At least two of
> them look applicable to these apps; neither build has been re-audited against them.

Every gate in the registry, scored against both committed builds. This is the per-gate protocol behind the number in the main README.

## Method

- **Scored:** 2026-07-21, against the two apps in this directory exactly as committed.
- **Scorers:** thirteen independent auditors, one per topic file, each reading the gate text and every source file of both apps. Static analysis only — nothing was run.
- **Verification:** every applicable verdict was re-derived by a separate adversarial auditor instructed to refute it, with a third auditor breaking ties (2-of-3). **No verdict was overturned — all were unanimous.**
- **Rules:** a gate is applicable when its "Applies when" situation occurs, or when the brief demands the control and a build omitted it (an omission is a fail, not "n/a"). Binary verdicts, scored against the gate text as written. Every verdict cites file:line — check any of them against the code in this directory.

## Result

> **26 applicable gates → 25/26 with Airtight, 16/26 without.**

| Gate | Rule | Without Airtight | With Airtight |
| --- | --- | --- | --- |
| 1 | Auth response uniformity | **FAIL** | pass |
| 2 | Constant-time secret comparison | pass | pass |
| 3 | Password storage | pass | pass |
| 5 | Session lifecycle | pass | pass |
| 6 | Identity token entropy | pass | pass |
| 7 | Session cookie flags | pass | pass |
| 10 | Server-side identity | pass | pass |
| 13 | Mass assignment allowlist | pass | pass |
| 22 | SQL query construction | pass | pass |
| 30 | Hardcoded credential literal | **FAIL** | pass |
| 31 | Secret fallback default | **FAIL** | pass |
| 32 | Ignore rule before the file | pass | pass |
| 37 | Secrets in error responses | **FAIL** | pass |
| 40 | Server-side request validation | **FAIL** | pass |
| 43 | Validated value is the one used | **FAIL** | pass |
| 45 | Upload size cap | pass | pass |
| 61 | Unpredictable values from a CSPRNG | pass | pass |
| 91 | Third-party script integrity | pass | pass |
| 100 | Named fields in log records | pass | pass |
| 101 | Swallowed exception | **FAIL** | **FAIL** |
| 103 | Security events recorded | **FAIL** | pass |
| 107 | Log destination is collected | pass | pass |
| 112 | Floating version specifier | pass | pass |
| 115 | Package name provenance | pass | pass |
| 120 | Rate limit on credential endpoints | **FAIL** | pass |
| 121 | Per-account failure backoff | **FAIL** | pass |

## The ten failures of the control build

Each with the line that earned it. The build was competent — bcrypt, parameterized SQL, session regeneration all present. Every failure below is an omission or an unexamined default, not broken fundamentals.

**Gate 1 — Auth response uniformity**
routes/auth.js:74 — "const ok = user && (await User.verifyPassword(user, password || ''));" — the && short-circuits, so an unknown identifier skips the bcrypt KDF entirely (the gate's literal fail example); status/body are uniform but the hashing work is not.

**Gate 30 — Hardcoded credential literal**
server.js:38 — `secret: process.env.SESSION_SECRET || 'dev-insecure-secret'` — a signing secret written as a literal in a tracked source file; the app is not localhost-only (server.js:16-19 has a production mode with trust proxy), so the fixture exception does not apply.

**Gate 31 — Secret fallback default**
server.js:38 — `process.env.SESSION_SECRET || 'dev-insecure-secret'` — the exact forbidden pattern (`process.env.X || "..."`); the fallback is a string value, not raise/exit. The throw at server.js:32-33 only guards production, so any deploy without NODE_ENV=production silently boots on the public default.

**Gate 37 — Secrets in error responses**
server.js:83 — `message: isProd ? 'Что-то пошло не так.' : String(err.stack || err)` — outside production the handler returns the exception's stack/repr to the client (rendered via views/error.ejs:5 `<pre class="error-message"><%= message %></pre>`); the rule as written has no dev-mode exception, and the value is derived from the caught exception, not a source literal.

**Gate 40 — Server-side request validation**
validation/without-airtight/routes/auth.js:65-66 — POST /login reads the body with no schema parse anywhere: `const identifier = String(req.body.identifier || '').trim(); const { password } = req.body;` and goes straight to the user lookup at :69-71. POST /register also reads fields (:18-20) before its hand-rolled regex checker runs; no runtime schema that names accepted fields and types exists in the app (lib/validate.js:8-25 is an ad-hoc errors-array function covering register only).

**Gate 43 — Validated value is the one used**
validation/without-airtight/routes/auth.js:38 — `const user = await User.createUser({ username, email, password });` — username/email are raw request-derived locals captured at :18-19 and `password` is destructured raw from req.body at :20; the validator (lib/validate.js:8-25) returns only an errors array and produces no validated output, so the value passed downstream is never a validator's output.

**Gate 101 — Swallowed exception**
validation/without-airtight/routes/auth.js:49-52 — inside 'catch (err)', the branch "if (err && err.code === 'SQLITE_CONSTRAINT_UNIQUE') { req.flash('error', ...); return res.status(400).render(...) }" neither records the error to a log nor rethrows (a flash message to the user is not a log record); only the other branch calls next(err).

**Gate 103 — Security events recorded**
validation/without-airtight/routes/auth.js:75-77 — failed login only does "req.flash('error', 'Неверный логин или пароль.')" and renders 401; no handler writes any log record on success or failure (register :16-55, login :63-89, logout :93-99 are all log-silent).

**Gate 120 — Rate limit on credential endpoints**
validation/without-airtight/routes/auth.js:63 — "router.post('/login', requireGuest, async (req, res, next) =>" (and :16 for /register): middleware chain contains no limiter; package.json:11-19 lists no rate-limit package anywhere in the app.

**Gate 121 — Per-account failure backoff**
validation/without-airtight/routes/auth.js:75-77 — "if (!ok) { req.flash('error', ...); return res.status(401).render('login', ...)": failure is not recorded against the account; db.js:17-23 users schema has no failed_attempts/locked_until columns.

## The one failure of the Airtight build

**Gate 101 — Swallowed exception**
validation/with-airtight/lib/password.js:38-41 '} catch { // A malformed stored hash must not throw a 500 ... return false; }' — the catch body writes no log record and does not rethrow; the gate requires even expected errors to be logged (at debug level).

The gates measure; they do not exempt their own side. This miss ships in the scorecard for the same reason the control's ten do.

## Not applicable — 41 gates

A registration/login/profile app simply never exercises these. Each entry says why the situation cannot arise; if you think one should apply, the reasoning is here to argue with.

### Credentials and authentication (1-9)

- **Gate 8 — Reset token expiry and single use.** Neither app has a password-reset, magic-link or email-verification flow, and the brief (registration/login/profile only) does not demand one, so no handler ever redeems a token from a link.

### Authorization and access control (10-19)

- **Gate 11 — Privileged route authorization.** Neither app has any /admin, /internal, or /manage path or any route that lists/edits/deletes other users' data, changes roles or billing, or reads logs/metrics, and the brief (registration/login/profile) does not demand such a route — the situation cannot arise.
- **Gate 12 — Object ownership check.** No handler in either app takes a record id from the path, query, or body and passes it to a lookup — profile records are fetched solely by the session user id, no route has an :id segment, and the pre-auth login email lookup is credential verification, which the vector file assigns to gates 1-9.
- **Gate 15 — Tenant scoping.** Neither schema has an orgId/tenantId/workspaceId/accountId column and no route path contains a tenant segment; the single-user registration/login/profile brief involves no multi-tenancy, so the situation cannot arise.

### Injection (20-29)

- **Gate 21 — Dynamic SQL identifiers.** No sort column, sort direction, table name or column list derives from a request or config in either app — every SQL identifier is written literally in the source, and the register/login/profile brief demands no dynamic sorting or column selection.
- **Gate 24 — Query operator injection.** Neither app uses MongoDB, Mongoose or any document-store filter — storage is SQLite via better-sqlite3 prepared statements — and the brief does not demand a document store, so a request value entering a query object cannot arise.
- **Gate 26 — OS command construction.** Neither app constructs any OS command — no child_process, exec, spawn or system call exists in either codebase — and the brief (registration/login/profile) requires no shelling out, so the situation cannot arise.
- **Gate 28 — Runtime evaluation of user input.** Neither app passes a non-literal value to a template compiler or eval-like API — no eval, new Function or vm.* exists, and every EJS template is compiled from a literal .ejs file with user data passed as escaped template data — and the brief demands no runtime evaluation.

### Configuration and secrets (30-39)

- **Gate 33 — Removing a committed secret.** Both apps are greenfield code with no change that removes a secret from a tracked file — `git log --all --oneline -- .env` is empty in both, no live credential was ever committed, and the brief does not demand a remediation of a leaked secret.
- **Gate 35 — Secrets in the client bundle.** Both apps are fully server-rendered EJS with zero client-side JavaScript (public/ contains only CSS), no client-side third-party API calls, and no NEXT_PUBLIC_*/VITE_*/REACT_APP_* variables — the situation cannot arise in this kind of app, and the brief (registration/login/profile) does not require any client-held credential.

### Input validation (40-49)

- **Gate 41 — Server-computed amounts.** Neither app has checkout, orders, payments, refunds or any monetary field in any request, and the brief (registration/login/profile) does not call for one — the situation cannot arise.
- **Gate 44 — Upload type from content.** Neither app accepts a file upload (no multer/busboy/formidable dependency, no upload route) and the brief's registration/login/profile scope does not require one — no upload type decision exists to gate.
- **Gate 46 — Upload destination path.** Neither app writes any uploaded file to disk (no writeFile/mv/save/diskStorage on request data anywhere) and the brief does not require uploads — the situation cannot arise.

### Cross-site scripting (50-59)

- **Gate 50 — Supplied HTML at a raw sink.** Neither app accepts or renders user-supplied markup (no markdown/rich-text/body_html feature) and the registration/login/profile brief does not demand one; the only raw EJS sinks in both apps are literal partial includes, so user markup can never reach a string-to-HTML sink.
- **Gate 51 — Markup assembled by interpolation.** Neither app builds an HTML string with a template literal, '+', .join("") or equivalent that reaches a raw sink — all markup lives in EJS templates with escaped '<%= %>' interpolation, and the only .join calls are path.join for filesystem paths.
- **Gate 53 — URL scheme allowlist.** No link, image, iframe, form target or redirect in either app is built from untrusted input — every href/src/action attribute is a literal path and every res.redirect target is a literal constant; neither app has a user-supplied URL field or next/returnTo parameter, and the brief demands none.
- **Gate 55 — Data in a script context.** Neither app emits any <script> element, hydration payload, or JSON.stringify-into-markup — there is zero client-side JavaScript (public/ holds only a CSS file), so no non-literal value can ever be embedded in a script context.

### Cryptographic failures (60-69)

- **Gate 60 — TLS verification.** Neither app constructs any outbound TLS client (no https/fetch/axios/tls/smtp/db-over-TLS; zero grep hits for rejectUnauthorized, NODE_TLS_REJECT_UNAUTHORIZED, sslmode, curl -k in source, package scripts, or .env.example) and the brief needs no outbound connection — both use a local SQLite file.
- **Gate 63 — Cipher mode and nonce.** Neither app encrypts a field, file, cookie payload, or config blob (zero grep hits for createCipheriv/createCipher/AES/encrypt) and the brief demands no encryption; passwords are hashed, which crypto.md's out-of-scope section explicitly routes to Gate 3 in credentials.md.
- **Gate 65 — Encoding is not protection.** In neither app is an encoded value handed to a client and then decoded-and-acted-on by a handler: with-airtight's sole base64url value is a stored random CSRF token compared opaquely against the session copy (the gate's own approved 'store a random token and look it up' fix pattern, never decoded), without-airtight emits no encoded values at all, and the brief has no share-link/unsubscribe/QR flow demanding one.

### Server-side request forgery (70-79)

- **Gate 70 — Outbound destination allowlist.** No caller-supplied value ever determines a scheme, host, or port for an outbound HTTP client in either app — neither codebase contains any outbound HTTP client at all, and the registration/login/profile brief does not demand URL fetching.
- **Gate 71 — Redirects on a fetched URL.** Applies only when an outbound client is called with a caller-originated URL; no fetch of any URL, caller-supplied or otherwise, exists in either app.
- **Gate 74 — Stored callback destination.** Neither app stores a user-supplied URL (no webhook/callback/avatar-URL field in any schema) and neither has a worker, queue consumer, or cron that delivers HTTP requests from storage; the brief does not require webhooks.
- **Gate 76 — Remote resources in rendered documents.** Neither app hands a caller-supplied document to a network-capable engine — EJS renders only developer-authored templates from the repo's views/ directory with user data interpolated as escaped values, and there is no headless browser, rasterizer, XML parser, or converter.

### Security misconfiguration (80-89)

- **Gate 80 — CORS origin allowlist.** Neither app sets Access-Control-Allow-Origin via middleware, framework option, or hand-written header, and the brief (a same-origin server-rendered form site) does not demand CORS — its absence is the secure default, not an omitted control.
- **Gate 81 — Debug mode in a deployed configuration.** The gate's subject — a Dockerfile, compose service, Procfile, systemd unit, deploy script or settings module that runs the app anywhere but the developer's machine — was never emitted by either app: both ship only a local `npm start` and localhost run instructions, and the brief demanded no deployment configuration (the dev-only error-handler stack trace in the without app is Gate 37's subject, which this file explicitly assigns away: 'Gate 37 governs the error handler you write').
- **Gate 83 — Default account credential.** Neither app contains a seed, migration, bootstrap or fixture that inserts an account — both db.js files emit only CREATE TABLE schema, accounts exist solely via the registration form with a user-chosen password, and the brief demands no admin/seed account.
- **Gate 85 — Datastore and admin surface exposure.** Both apps use embedded better-sqlite3 — an in-process file database with no network listener — and neither has a compose service, Kubernetes Service, run command or config publishing any datastore/cache/broker/admin-UI port; app.listen is the application's own port, which the gate text explicitly excludes ('an admin router mounted inside the application is not this gate').
- **Gate 87 — Permissions on generated secret files.** Neither app contains setup code that writes a secret file — .env is created manually by the operator per README ('cp .env.example .env'), no key/token/config is generated, and the only first-run write is the SQLite data dir/db (fs.mkdirSync + Database open), which is not one of the gate's secret-file shapes (.env, *.pem, service-account JSON, generated config).

### Software and data integrity (90-99)

- **Gate 90 — Untrusted deserialization.** Neither app hands untrusted bytes to an object-reconstructing deserializer — request bodies go through express.urlencoded (data-only parse) and the with-airtight session store keeps sessions as JSON text; no pickle/yaml.load/unserialize/node-serialize analog exists anywhere, and a registration/login/profile brief does not demand one.
- **Gate 93 — Code fetched then executed.** Neither app contains a Dockerfile, CI step, install script or postinstall hook, and no application code fetches or evaluates anything — there is no fetch/eval/new Function/vm/import(url) call in either codebase; dependencies arrive solely via npm (the gate's own recommended fix), so the fetch-then-execute situation never occurs and the brief does not demand it.
- **Gate 95 — Update and plugin signature.** Neither app auto-updates, checks a version endpoint, or loads plugins/extensions/remote bundles — every require() in both codebases targets a local file or an npm package installed at build time, nothing executes code that was not in the shipped build, and the brief does not demand an update or plugin mechanism.
- **Gate 96 — Inbound webhook signature.** Neither app exposes a route that receives machine-pushed events — every route (/, /register, /login, /logout, /profile) serves browser sessions with HTML forms, grep finds no webhook/callback/Stripe/GitHub/Twilio handler or express.raw mount, and a registration/login/profile brief does not demand a webhook endpoint.

### Vulnerable and outdated components (110-119)

- **Gate 110 — Lockfile-honouring install.** Neither app contains a Dockerfile, CI workflow, deploy script, or entrypoint that installs (scripts are only 'node server.js'), no lockfile is excluded by .gitignore, and the brief (registration/login/profile site) does not demand deployment scripting, so no non-interactive install site exists to gate.
- **Gate 114 — Non-registry source pinning.** No dependency in either app is installed from a git ref, archive URL, or download — every entry is a registry package with a version, so the gate's situation never arises; the brief does not require any non-registry source.
- **Gate 117 — Audit step in the pipeline.** The gate constrains CI workflows that install dependencies, and neither app contains any pipeline definition (no GitHub Actions, GitLab CI, Jenkinsfile, or make ci target); the brief for a registration/login/profile site does not demand a CI pipeline, so there is no emitted workflow to gate.
- **Gate 118 — Suppressed audit result.** The gate applies when a red audit step is being made green; neither app has any audit step or any suppression construct, so the situation cannot arise here.

### Insecure design (120-129)

- **Gate 123 — Result-set ceiling.** No handler in either app queries a collection and returns rows — every datastore read is a single-row prepared .get() (lookup by id/username/email), and the registration/login/profile brief demands no list endpoint, so the situation genuinely cannot arise.
- **Gate 125 — Request-sized work.** No request value in either app reaches an image dimension, page count, iteration count, scale factor, batch size, date span, or generate-N parameter — there is no resize/report/export/render operation, and the brief demands none.
- **Gate 127 — Bounded expansion.** Neither app contains any archive-extraction or decompression code (no zipfile/tarfile/unzipper/adm-zip/yauzl/zlib.gunzip usage confirmed by grep), and a registration/login/profile brief demands no expansion of caller-supplied bytes.
- **Gate 128 — Bounded quantity.** No quantity/qty/count/seats/days/points field arrives in any request in either app, and nothing from a request is multiplied by, added to, or subtracted from a stored value — the brief has no transactional quantity.

---

Scored by AI auditors against the gate texts; the evidence lines are the audit trail. To reproduce: read any cited line, read the gate, decide for yourself — that is the whole method.
