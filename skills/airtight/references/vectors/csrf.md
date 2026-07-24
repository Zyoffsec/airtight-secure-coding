# Cross-site request forgery and framing

These are the attacks that never touch your server's trust in a token — they borrow the victim's
browser. The session cookie is valid, the user is real, the request is genuine in every way the
handler can see. What is forged is the *intent*.

A model asked for "a transfer endpoint" writes one that checks the session and moves the money. It
has no reason to add a CSRF token: nothing in the request said the form would be submitted from
`evil.example`, and the endpoint works perfectly when tested from the app's own page. The same
blindness produces `@app.get("/subscribe/cancel")` — a mutation behind a method the browser will
issue for an `<img>` tag — and a page that renders fine inside someone else's `<iframe>`.

The defence is never in the handler's logic. It is in a token the other origin cannot read, a method
that does not mutate, and a header that refuses to be framed. All three are omissions by default.

## Load this file when

- A route mutates state — creates, updates, deletes, transfers, cancels, invites, changes a password
  or an email — and the caller is identified by a cookie rather than an `Authorization` header.
- A session or auth cookie is set, or `SameSite` is being chosen or loosened.
- An HTML form is rendered, or a template includes a form that posts back to the app.
- CORS is configured on an endpoint that also accepts cookies (`credentials: true`,
  `supports_credentials=True`, `withCredentials`).
- A page that shows authenticated content is served, or response headers are configured.
- A framework's built-in CSRF middleware is disabled, exempted, or scaffolded out
  (`@csrf_exempt`, `csrf: false`, `skip_before_action :verify_authenticity_token`).

## Gates


### Gate 130 — Cookie-authenticated state change

> Code that mutates state on behalf of a cookie-identified user MUST NOT be emitted unless the
> request carries a CSRF token the handler verifies, or the route authenticates from an
> `Authorization` header rather than a cookie.

**Applies when:** a handler for a mutating method reads identity from a session or auth cookie —
`request.session`, `req.session`, `current_user` backed by a cookie, `@login_required` — and writes,
deletes, transfers, or dispatches anything.

**Passes:**
```python
@app.post("/transfer")
def transfer(request: Request, amount: int, to: str, token: str = Form(...)):
    expected = request.session.get("csrf_token")
    if not expected or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="Invalid request")
    move_money(request.session["user_id"], to, amount)
```

**Fails:**
```python
@app.post("/transfer")
def transfer(request: Request, amount: int, to: str):
    move_money(request.session["user_id"], to, amount)
```

**Why:** The browser attaches the session cookie to any request to your origin, including one issued
by a form on a page the attacker controls. A victim who is logged in and visits that page submits the
transfer without seeing it. The handler cannot tell the difference — the cookie is real, the user is
real, only the intent is forged. `SameSite=Lax` blocks the plain cross-site POST but not a same-site
subdomain, a `GET`-shaped mutation, or a browser that never got the attribute.

**Fix:** Store a random token in the session at render time, put it in a hidden form field or a
request header, and compare it with `hmac.compare_digest` as the handler's first statement — or drop
the cookie and authenticate the route from an `Authorization` header, which no cross-site form can
set.


### Gate 131 — Mutation behind a safe method

> Code that changes state MUST NOT be reachable through `GET` or `HEAD`.

**Applies when:** a route registered for `GET` (or a framework default that includes `GET`) writes,
deletes, cancels, confirms, toggles, or dispatches — including "confirmation" and "unsubscribe" links
sent by email.

**Passes:**
```python
@app.post("/subscription/cancel")
def cancel(request: Request):
    cancel_subscription(request.session["user_id"])
```

**Fails:**
```python
@app.get("/subscription/cancel")
def cancel(request: Request):
    cancel_subscription(request.session["user_id"])
```

**Why:** A `GET` is issued by anything that can put a URL on a page — `<img src>`, a prefetch, a link
preview in a chat client, a crawler with the victim's cookies in a shared browser profile. No form,
no JavaScript and no CORS negotiation is required, so every CSRF defence that assumes a POST is
bypassed by the method itself. Safe methods are also the ones intermediaries feel free to retry.

**Fix:** Register the mutating route for `POST`, `PUT`, `PATCH` or `DELETE`, and leave `GET` returning
a page that submits it. For an emailed one-click action, have the link land on a page whose form
posts the change.


### Gate 132 — Framing denial

> Code that serves a page rendering authenticated content MUST NOT be emitted unless the response
> denies framing by a foreign origin.

**Applies when:** a response returns HTML for a signed-in view, or response headers are configured
for an app that has a login.

**Passes:**
```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response.headers["X-Frame-Options"] = "DENY"
    return response
```

**Fails:**
```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
```

**Why:** Without it the page loads inside an attacker's `<iframe>`, positioned under a transparent
overlay. The victim believes they are clicking a game or a cookie banner; the click lands on
"Confirm transfer" in your app, in their own authenticated session. Nothing in the request looks
wrong, because nothing about it is — the user really did click.

**Fix:** Send `Content-Security-Policy: frame-ancestors 'none'` on HTML responses, with
`X-Frame-Options: DENY` alongside it for browsers that predate `frame-ancestors`. Where the app is
legitimately embedded, name the permitted origins as literals instead of removing the header.
