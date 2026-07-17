# Cross-site scripting

Frameworks (JSX, Vue, Angular, Jinja, Django) escape interpolated output by default and get it right
unasked. This file does not gate that. It gates the four sinks where code **deliberately steps out** of
that protection: raw-HTML sinks, HTML built by interpolation, URL attributes, and data inside
`<script>`. Interpreter boundaries (SQL, shell, template compiler) are Gates 20-29 in `injection.md`.

## Load this file when

- The request mentions markdown, rich text, a WYSIWYG editor, "let users format", a bio, a comment
  body, a description, or rendering HTML stored in a database.
- A non-literal value reaches: `dangerouslySetInnerHTML`, `v-html`, `.innerHTML`, `.outerHTML`,
  `insertAdjacentHTML`, `document.write`, `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`, `|safe`,
  `mark_safe`, `{{{ }}}` (Handlebars), `<%- %>` (EJS), `.html_safe` (ERB).
- A value reaches `href`, `src`, `action`, `formaction`, `xlink:href`, `window.location` or
  `location.assign` from a request, database row or config value.
- A server-rendered `<script>` element contains an interpolation, or state is embedded for hydration.
- An HTML string is built with a template literal, `+`, `.join("")` or an f-string.
- A sanitizer is being written, chosen or configured.

## Gates


### Gate 50 — Supplied HTML at a raw sink

> Code that passes a non-literal value to a raw-HTML sink MUST NOT ship unless the value is passed
> through a maintained HTML sanitizer library — DOMPurify, `sanitize-html`, `bleach`, `nh3` — at the
> sink itself.

Applies when user-supplied markup (markdown, rich-text, `body_html`) reaches any string-to-HTML sink.

Fix: sanitize at the sink, as the last expression before the value enters it.
`(example omitted)`

Sanitize at the sink, not on write: sanitized-on-write columns are trusted forever and never see sanitizer upgrades. A hand-rolled regex strip is not a sanitizer — the HTML parser decides what runs and accepts `<script/src=x>`, `<img onerror>`, `<svg onload>`.

### Gate 51 — Markup assembled by interpolation

> Code that interpolates a non-literal value into an HTML string MUST NOT ship unless that value is
> itself the markup the feature exists to render, in which case Gate 50 applies instead.

Applies when markup is literal in source and a datum is placed inside it via template literal, `+`, `.join("")` or f-string reaching a raw sink.

Fix: do not build the HTML. Set `textContent`, return a JSX child (`<li>{item.title}</li>`), or use a template placeholder; in Python, `format_html("<b>{}</b>", user.name)` escapes the argument.
`(example omitted)`
Fails: `innerHTML = items.map((i) => `<li>${i.title}</li>`).join("")`; or `mark_safe(f"<b>{user.name}</b>")`. A sanitizer is the wrong answer — nothing in `item.title` was ever meant to be HTML.

### Gate 53 — URL scheme allowlist

> Code that places a non-literal value into `href`, `src`, `action`, `formaction`, `xlink:href` or a
> `location` assignment MUST NOT ship unless the value is parsed as a URL and its scheme tested against
> a literal allowlist before reaching the attribute.

Applies to any link, image, iframe, form target or redirect destination built from untrusted input.

Fix: parse with `new URL(raw)` and test `url.protocol` against a literal `Set`, then use `url.href`.
`(example omitted)`
Fails: `<a href={user.website}>` directly — auto-escaping does not cover URLs, and a prefix check fails to `JaVaScRiPt:` or ` javascript:` because `new URL()` normalizes case, whitespace and control chars the way the browser does.

### Gate 55 — Data in a script context

> Code that embeds a non-literal value inside a `<script>` element MUST NOT ship unless the value is
> serialized by a helper that escapes `<` to `\u003c`.

Applies when server-rendered HTML carries client state (hydration payload, config blob) placed inside `<script>` by interpolation or `JSON.stringify`.

Fix: serialize with a helper that escapes `<` — `serialize-javascript` (Node),
`{{ value|json_script:"user-data" }}` (Django), or `JSON.stringify(v).replace(/</g, "\\u003c")`.

A value containing `</script>` otherwise closes the data block; `<` reads as the same character to the JS parser but never closes the element for the HTML tokenizer.

## Out of scope

- **Output escaping in general.** Frameworks escape interpolated values by default; a gate firing on
  `<p>{bio}</p>` catches nothing. Only the four deliberate escape points are gated.
- **Hand-rolled sanitizers.** Folded into Gate 50 — a regex strip is not a named library, so it already
  fails Gate 50.
- **Inline event-handler attributes** (`onclick="rename('{{ item.name }}')"`). Real breakout, but not a
  default mistake in framework or server-template code. Report as an ungated finding; do not stretch
  Gate 55 over it.
- **CSP, `X-Content-Type-Options`, Trusted Types.** Defence in depth, ungated (see `misconfig.md`). A
  CSP does not make a Gate 50 failure pass. Report absence without a gate number.
- **`httpOnly` on the session cookie.** Already Gate 7.
- **SVG/HTML/markdown files served from own origin after upload.** Upload handling is Gates 40-49
  (Gate 46 fires); the response header is ungated.
- **What the serialized object contains.** Over-serialization (a token in `window.__USER__`) is Gates
  30-39. Gate 55 governs how the value is written, not which fields are in it.
- **Sanitizer bypasses, mutation XSS, DOM clobbering.** Unknown flaws in third-party code; Airtight
  checks the code in front of you.
- **`target="_blank"` without `rel="noopener"`.** Browsers default to `noopener` since 2021; never
  script execution.

## Prove probes

- Gate 50 — not provable read-only in the general case (getting a payload in is a write). Where the
  local dataset already holds a record with markup, GET the render route and read the raw body -> HELD
  if the markup arrives escaped or stripped, FAILED if a `<script` tag or `on...=` attribute survives.
  Otherwise reason from code.
- Gate 51 — where the value reflects from a query parameter into server-rendered HTML,
  `GET /<route>?q=<b>airtight</b>` -> HELD if the body contains `&lt;b&gt;airtight&lt;/b&gt;`, FAILED if
  `<b>airtight</b>`. For client-side `innerHTML`, reason from code.
- Gate 53 — not an HTTP probe (`javascript:` is inert until clicked). HELD if the value reaches the
  attribute through a function that parses it and tests the scheme against a literal set, FAILED if it
  reaches the attribute directly or through a prefix/substring check.
- Gate 55 — where the embedded object carries a query-string value, GET the page with that parameter set
  to `</script>` and read the **raw response** -> HELD if the script block contains `\u003c/script>`,
  FAILED if a literal `</script>` appears. For stored-only data, `JSON.stringify` with no escaping step
  FAILS.
