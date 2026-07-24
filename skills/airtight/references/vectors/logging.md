# Security logging and monitoring failures

Four emission decisions: what must never enter a log, what must never be thrown away, what must
always be recorded, and where records have to land. Each gate leads with its rule and its fix.

## Load this file when

- A log call is written or edited — `console.log`, `console.error`, `logger.*`, `print`, `logging.*`
  — with a request, response, user record, session, header map or config object in scope.
- A logger is constructed or configured: winston, pino or bunyan transports, `logging.basicConfig`,
  a `dictConfig`, a Django `LOGGING` block, a log file path.
- Any `try`/`catch`, `except`, `.catch()`, rejection handler, error boundary or global error hook is
  written — including one added to make a crash go away.
- A handler authenticates, signs out, registers, resets or changes a password, changes an email or
  phone, enrols or removes MFA, issues or revokes an API key, or assigns a role or permission.
- An admin or support route acts on another user's account, impersonation included.
- Request-logging or error-reporting middleware is added — `morgan`, `pino-http`, Sentry or
  OpenTelemetry init.
- The request is "add some logging so I can see what's going on".

## Gates

### Gate 100 — Named fields in log records

> Code that writes a request body, a header collection, a user record, or a token, key or password
> value to a log MUST NOT be emitted unless the logged value is an object built from an explicit list
> of field names written in the source.

**Applies when:** any log call, request-logging middleware or error handler takes a request, response,
header map, session, user row, config object or auth artifact as its argument, rather than fields
picked out of one.

**Fails:** `logger.info({ body: req.body, headers: req.headers }, "login attempt")` — the whole
container drags in the plaintext password and the `Cookie` / `Authorization` headers.

**Fix:** Build an object literal from the fields the record needs — `{ event: "auth.login", email,
outcome }` — and never pass the container the values arrived in. Where a logger already ingests whole
objects across the codebase, configure a redaction list at construction (pino `redact`, a structlog
processor) as a backstop, but the call site still names its own fields — redaction only covers the
key names someone thought of.

### Gate 101 — Swallowed exception

> A `catch` or `except` block MUST NOT be emitted unless its body records the error to a log or
> rethrows it.

**Applies when:** any `try`/`catch`, `except`, `.catch()`, rejection handler or error boundary is
written — most of all the one added to stop a crash whose cause was never established.

**Fails:** `catch {}`, `except: pass`, `.catch(() => {})` — the one instant the code knows something
is wrong is the instant it discards the evidence.

**Fix:** Give every catch a body that logs the caught error with enough context to identify the path
— an event name, the caller, the id — and rethrow when the error cannot be handled here. If an error
genuinely is expected and uninteresting, log it at debug level: the record is what makes that claim
checkable when it turns out to be wrong.

### Gate 103 — Security events recorded

> A handler that authenticates a caller, changes a password or contact address, changes a role or
> permission, or acts on another account with administrative privilege MUST NOT be emitted unless it
> writes a log record naming the event, the acting principal, the target and the outcome, on the
> failure path as well as the success path.

**Applies when:** writing or editing login, logout, signup, password reset or change, email or phone
change, MFA enrolment or removal, API key issuance or revocation, role or permission assignment, or
any admin, support or impersonation route that acts on another user's account.

**Fails:** a role-change or login handler that authorizes, validates and works but writes no record —
the only surviving evidence anyone was made an admin is the current value of the `role` column.

**Fix:** Emit one structured record per security-relevant outcome, carrying a stable `event` name,
the acting principal's id, the target's id and the outcome — on the rejected branch too, because a
record of refused attempts is what turns a single line into a visible pattern. Log the identifiers,
not the objects they came from: Gate 100 still applies to the record this gate requires.

### Gate 107 — Log destination is collected

> Code that configures a logging destination MUST NOT be emitted unless at least one destination
> writes to stdout or stderr unconditionally.

**Applies when:** a logger is constructed or configured — a winston or bunyan transport list, a pino
destination, `logging.basicConfig`, a `dictConfig` handler set, a Django `LOGGING` block — or a log
file path appears in application code.

**Fails:** transports that write only to files in the container (`error.log`, `combined.log`) with
the console added behind `if (NODE_ENV !== "production")` — in production the records go to a
filesystem discarded on the next restart and nothing ships them first.

**Fix:** Log to stdout unconditionally and let the platform's collector own everything downstream —
container runtimes, PaaS platforms and process supervisors already capture stdout, so the record is
collected on the day it is written. In Python the same trap is `logging.basicConfig(filename=...)`;
pass `stream=sys.stdout` instead.

## Out of scope

- **Which fields count as PII.** Whether an email, an IP or a user id may be logged at all is
  jurisdiction and product specific — nothing binary to read off the code. Gate 100 covers the
  mechanism that drags PII in unintentionally (dumping the container instead of naming fields); a
  deliberate decision to log an email is the product's to make. Gate 105 is held in case a binary
  slice of this emerges.
- **Log injection and forged records.** Real, but a JSON formatter escapes it by construction, and
  gating every log call that touches user data would fire everywhere and catch almost nothing.
- **Alerting, dashboards, retention windows and SIEM.** No line of code passes or fails "alert on
  repeated login failure" — rule 4. Gate 103 stops at whether the record is written, Gate 107 at
  whether it lands somewhere readable. Note its absence in an audit; do not cite a gate for it.
- **Access control on the log store itself.** Gate 100 assumes the log is an internal sink. Who may
  read the aggregator is configured outside the repository.
- **Tracing, metrics and uptime monitoring.** Observability work, not a safety defect in the code
  that was asked for.
- **The exception message reaching the client.** Gate 37 owns the response body; this file owns the
  log sink. A handler that returns `err.stack` to the caller and records nothing fails both — cite
  both.
- **Rate limiting and lockout on repeated failures.** Credentials range, already out of scope there.
  Gate 103 makes the attempts visible, a precondition and not a substitute.

## Prove probes

- Gate 100 — POST the developer's own local login endpoint with a registered address and a
  distinctive junk password (`airtight-canary-<random>`), then read their local log sink for that
  literal string -> HELD if it does not appear, FAILED if any record contains it. A wrong password is
  a read: no account is created and nothing is changed. If the sink cannot be read locally, that is
  Gate 107's finding, not this one's, and this gate is UNKNOWN.
- Gate 101 — not provable read-only. A probe that finds no record cannot distinguish a swallowed
  exception from an exception that never happened — the failure mode itself, restated. Reason from
  code.
- Gate 103 — POST the local login endpoint twice with a wrong password, once for an address the
  developer confirms is registered and once for one that is not, then read the log sink -> HELD if a
  failure record appears for both, naming the account and the outcome, FAILED if the sink is silent.
  Do not probe the password-change, email-change or role-change handlers: exercising those is a write.
  Reason those from code.
- Gate 107 — not settled by traffic; reason from the configuration site in the source. Read the
  logger construction -> HELD if a Console or stdout destination is registered unconditionally,
  FAILED if every destination is a file path or the console destination sits behind an environment
  condition. Do not start the service: `prove` exercises what is already running, and this destination
  is decidable from the source without it.
