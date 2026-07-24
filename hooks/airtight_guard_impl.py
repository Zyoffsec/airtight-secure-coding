#!/usr/bin/env python3
"""Airtight surface guard.

PreToolUse hook on Write|Edit. Detects which security surfaces the code being
written touches and injects only that surface's gate lines from the registry.

Deterministic: fires regardless of how long the session context has grown, and
regardless of whether the model remembered to load the skill.

Never blocks and never raises — any failure exits 0 silently.
"""
import json
import os
import re
import sys

def _find_gates():
    """Locate gates.md. The hook ships inside the skill, so the repo layout
    (hooks/../references/gates.md) is tried first; the rest cover the common
    install locations."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.environ.get("AIRTIGHT_GATES", ""),
        # Plugin layout: the skill sits in skills/<name>/, the hook beside it.
        os.path.join(here, os.pardir, "skills", "airtight", "references", "gates.md"),
        # Bare-skill layout: the skill is the repository root.
        os.path.join(here, os.pardir, "references", "gates.md"),
        os.path.join(here, "references", "gates.md"),
    ]
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        candidates.insert(1, os.path.join(root, "skills", "airtight", "references", "gates.md"))
        candidates.insert(2, os.path.join(root, "references", "gates.md"))
    for base in ("~/.claude/skills", "~/.agents/skills", "~/.cursor/skills", "~/.codex/skills"):
        candidates.append(os.path.join(base, "airtight", "references", "gates.md"))
        candidates.append(os.path.join(base, "airtight-secure-coding", "references", "gates.md"))
    for c in candidates:
        if not c:
            continue
        p = os.path.abspath(os.path.expanduser(c))
        if os.path.isfile(p):
            return p
    return None


GATES = _find_gates()

# surface -> (gate numbers, regexes matched against file content)
SURFACES = [
    ("HTTP route / endpoint", range(10, 20), [
        r"@app\.(get|post|put|patch|delete)", r"@router\.(get|post|put|patch|delete)",
        r"\bapp\.(get|post|put|patch|delete)\s*\(", r"\brouter\.(get|post|put|patch|delete)\s*\(",
        r"@(Get|Post|Put|Patch|Delete)Mapping", r"http\.HandleFunc", r"\bcreate_route\b",
    ]),
    ("credentials / auth", range(1, 10), [
        r"\bpassword\b", r"\bbcrypt\b", r"\bargon2\b", r"\bscrypt\b", r"\bjwt\b",
        r"\blogin\b", r"\bsignup\b", r"\baccess_token\b", r"set_cookie",
        r"req\.session", r"session\[", r"session_id", r"session_token",
    ]),
    ("injection (SQL / shell / template)", range(20, 30), [
        r"\b(SELECT|INSERT|UPDATE|DELETE)\s", r"\.execute\s*\(", r"\.query\s*\(",
        r"subprocess\.", r"os\.system", r"child_process", r"render_template_string",
        # NoSQL / document stores — Gate 24 is query-operator injection, not just SQL.
        # `.find({...})` with an object literal is a query; Array.prototype.find takes a
        # function, so the brace is what tells them apart.
        r"\.find\s*\(\s*\{",
        r"\.(?:findOne|findMany|findFirst|findUnique|aggregate|updateOne|updateMany"
        r"|deleteOne|deleteMany|countDocuments)\s*\(",
        r"\$(?:where|ne|gt|gte|lt|lte|regex|expr|function)\b",
    ]),
    ("config / secrets", range(30, 40), [
        r"os\.environ", r"process\.env", r"getenv\s*\(", r"[A-Z_]*(SECRET|API_KEY|TOKEN|PASSWORD)[A-Z_]*\s*=",
    ]),
    ("untrusted input / upload", range(40, 50), [
        r"\bUploadFile\b", r"multipart", r"request\.(body|json|form|files)",
        r"\breq\.(body|query|params|files)\b", r"BaseModel",
    ]),
    ("XSS / HTML sink", range(50, 60), [
        r"innerHTML", r"dangerouslySetInnerHTML", r"\|\s*safe\b", r"v-html",
    ]),
    ("crypto", range(60, 70), [
        r"\bMath\.random\b", r"\bmd5\b", r"\bsha1\b", r"\bhashlib\.", r"\bCipher\b", r"verify\s*=\s*False",
        r"\brandom\.(?:randint|random|choice|randrange|sample|shuffle)\s*\(",
        r"\bnew Random\s*\(", r"\brand\s*\(\s*\)", r"\bmt_rand\s*\(",
    ]),
    ("outbound fetch (SSRF)", range(70, 80), [
        r"requests\.(get|post)", r"httpx\.", r"\bfetch\s*\(", r"\baxios\.", r"urlopen",
    ]),
    ("misconfiguration", range(80, 90), [
        r"allow_origins", r"\bCORS\b", r"debug\s*=\s*True", r"0\.0\.0\.0",
    ]),
    ("integrity / webhook payload", range(90, 100), [
        r"\bwebhook\b", r"\bpickle\b", r"yaml\.load\s*\(", r"constructEvent", r"construct_event",
    ]),
    ("security logging", range(100, 110), [
        r"except\s*:\s*$", r"except\s+Exception\s*:\s*\n\s*pass", r"catch\s*\([^)]*\)\s*\{\s*\}",
    ]),
    ("unbounded work / limits", range(120, 130), [
        r"\.all\s*\(\s*\)", r"findAll", r"\bextractall\b", r"SELECT\s+\*",
    ]),
]

PATH_SURFACES = [
    (r"(^|/)Dockerfile|docker-compose", "misconfiguration", range(80, 90)),
    (r"(package|requirements|pyproject|go\.mod|Gemfile)", "dependencies", range(110, 120)),
]


ROUTE_RE = re.compile(
    r"""(?ix)
    # FastAPI / Flask / Blueprint decorators
      @(?:app|router|api|bp|blueprint)\.(?:get|post|put|patch|delete|route)\s*\(
    # Express / Fastify / Koa / Hapi / gin / chi / echo — obj.method("/path")
    | \b(?:app|router|server|fastify|api|r|e|mux|http)\.
      (?:get|post|put|patch|delete|all|handle|handlefunc)\s*\(\s*['"`/]
    # Spring
    | @(?:Get|Post|Put|Patch|Delete|Request)Mapping
    # NestJS — bare method decorators
    | @(?:Get|Post|Put|Patch|Delete)\s*\(\s*\)?
    # Laravel
    | \bRoute::(?:get|post|put|patch|delete|any|match|resource|apiResource)\s*\(
    # Django URL conf
    | \b(?:path|re_path)\s*\(\s*['"]
    # Django / DRF views
    | \bdef\s+\w+\s*\(\s*request\b
    | \b(?:APIView|ViewSet|ModelViewSet|GenericAPIView)\b | @api_view\s*\(
    # Rails router
    | ^\s*(?:get|post|put|patch|delete|resources|resource)\s+['":]
    # Next.js route handlers
    | \bexport\s+(?:default\s+)?(?:async\s+)?function\s+(?:handler|GET|POST|PUT|PATCH|DELETE)\s*\(
    | \bexport\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)\s*=
    # Rails controllers
    | \bclass\s+\w+Controller\s*<
    # ASP.NET — attributes and minimal API
    | \[Http(?:Get|Post|Put|Patch|Delete)\b | \[Route\s*\( | \bapp\.Map(?:Get|Post|Put|Patch|Delete)\s*\(
    # Rust — axum / actix / rocket
    | \.route\s*\(\s*["'] | \#\[(?:get|post|put|patch|delete)\s*\( | \bweb::resource\s*\(
    # C / C++ web frameworks
    | \bCROW_ROUTE\s*\( | \bmg_set_request_handler\s*\( | \bADD_METHOD_TO\s*\(
    | \bsvr\.(?:Get|Post|Put|Patch|Delete)\s*\(
    """,
    re.MULTILINE,
)

# Next.js / SvelteKit put routes in the path, not the syntax.
ROUTE_PATH_RE = re.compile(
    r"(?:^|/)(?:pages|app)/api/|(?:^|/)app/[^/]*/route\.[jt]sx?$"
    r"|(?:^|/)routes/.*\+server\.[jt]s$",
    re.IGNORECASE,
)

# Route files that only *register* paths — the auth for them lives in the handler
# elsewhere, so a missing marker here is not evidence of an open route.
REGISTRATION_PATH_RE = re.compile(
    r"(?:^|/)(?:urls\.py|routes\.rb|urlpatterns\.py)$", re.IGNORECASE
)

# Any one of these means the file at least reaches for a server-side principal.
AUTH_RE = re.compile(
    r"""(?ix)
      current_user | get_current_user | require_(?:auth|user|role|login) | login_required
    | verify_token | decode_token | authenticate | Security\s*\( | HTTPBearer | OAuth2
    | req\.user | request\.user | session\[ | req\.session | isAuthenticated | ensureAuth
    # Django / DRF
    | LoginRequiredMixin | permission_classes | IsAuthenticated | PermissionRequiredMixin
    | @user_passes_test | request\.auth
    # NestJS / Angular
    | @UseGuards | AuthGuard | @Roles\s*\(
    # Laravel
    | ->middleware\s*\(\s*['"]auth | auth\(\)->user | Auth::(?:user|check|id)
    # Rails
    | before_action\s+:(?:authenticate|require|verify) | authenticate_user!
    # Next.js / Auth.js / Clerk / Supabase
    | getServerSession | getSession | \bauth\s*\(\s*\) | currentUser\s*\( | requireUser
    | getUser\s*\( | verifyIdToken | clerkClient | supabase\.auth
    # Spring / generic middleware
    | @PreAuthorize | @Secured | SecurityContextHolder | isAuthenticated\s*\(
    # A dependency or guard named for what it resolves — current_session,
    # require_user, get_principal — is an authentication step whatever the codebase
    # chose to call it.
    | \b(?:current|require|get|resolve|load|verify)_(?:session|user|principal|identity|account|viewer)\b
    | Depends\s*\(\s*\w*(?:session|user|auth|principal|identity)\w*\s*\)
    # ASP.NET
    | \[Authorize | User\.Identity | HttpContext\.User | ClaimsPrincipal
    # Rust
    | Extension\s*<\s*(?:User|Auth|Claims) | \bClaims\b | require_login | auth_layer
    # C / C++ / generic
    | check_auth | verify_auth | is_authorized | require_token
    """
)


# Prose is not an execution path. A doc that *describes* a route or a webhook ships
# nothing, so route- and webhook-shaped findings do not apply to it. A credential
# literal still does — a key pasted into a README leaks exactly like one in source.
PROSE_PATH_RE = re.compile(r"\.(?:md|markdown|mdx|rst|txt|adoc)$", re.IGNORECASE)

# A password in a test fixture is a value the suite needs, not a credential that
# ships. Denying it teaches developers that the guard does not understand their
# code, which is the fastest route to it being switched off.
TEST_PATH_RE = re.compile(
    r"""(?ix)
    (?:^|/)(?: tests? | spec | __tests__ | fixtures )/
    | (?:^|/) (?: conftest\.py | test_[^/]+\.py | [^/]+_test\.(?:py|go|rb) )$
    | \.(?: spec | test )\.[jt]sx?$
    """
)


# Every quoted path that a route decorator or registration hands a URL.
_ROUTE_PATH_LITERAL_RE = re.compile(r"""['"`](/[^'"`\s]*)['"`]""")


def _only_credential_routes(body):
    """True when every route path in the file is a login-shaped one.

    A sign-in page has to be reachable by someone who is not signed in — that is
    the job. Gates 120 and 121 are what bound it, and they are reported separately.
    """
    paths = _ROUTE_PATH_LITERAL_RE.findall(body)
    if not paths:
        return False
    return all(CREDENTIAL_ROUTE_RE.search(f'"{p}"') for p in paths)



def open_route_finding(path, body):
    """Routes present but nothing derives a server-side identity.

    A webhook receiver is public by design — its caller is authenticated by the
    signature, not by a session — so a verified one is not an open route. An
    unverified one is Gate 96's problem, reported separately.

    Files that only register paths (urls.py, routes.rb) are skipped: the handler
    they point at lives elsewhere, so a missing marker here proves nothing.
    """
    if PROSE_PATH_RE.search(path or ""):
        return None
    if WEBHOOK_RE.search(body):
        return None
    if _only_credential_routes(body):
        return None
    if REGISTRATION_PATH_RE.search(path or ""):
        return None
    n = len(ROUTE_RE.findall(body))
    if not n and ROUTE_PATH_RE.search(path or ""):
        n = 1
    if n and not AUTH_RE.search(body):
        return (
            f"OPEN ROUTE — this file defines {n} HTTP route(s) and nothing in it derives "
            "an authenticated principal server-side. Gates 10/11/12 FAIL by default. "
            "Either take identity from the session/verified token and scope the query to "
            "that owner, or — if the route is genuinely meant to be public — say so in one "
            "plain line in your reply so the developer sees the choice. Do not ship it "
            "silently open."
        )
    return None


SECRET_LITERAL_RE = re.compile(
    r"""(?ix)
    \b(?:SECRET_KEY|SECRET|API_KEY|APIKEY|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|
       ACCESS_KEY|CLIENT_SECRET|JWT_SECRET|DB_PASSWORD)\b
    \s*[:=]\s*
    ['"][^'"]{6,}['"]
    """
)
# os.environ.get("X", "fallback") / process.env.X || "fallback"
_SECRETISH_TOKEN = r"(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|CREDENTIAL|SALT|PEPPER|PRIVATE|DSN)"
# A default for DATABASE_PATH or LOG_LEVEL is configuration. Gate 31 is about a
# fallback that stands in for a *credential* — only the name tells them apart.
SECRET_FALLBACK_RE = re.compile(
    r"""(?ix)
    (?: (?: environ\.get | getenv ) \s*\(\s*
          ['"] \w{0,48}""" + _SECRETISH_TOKEN + r"""\w{0,48} ['"]
          \s*,\s* ['"][^'"\n]{6,}['"]
      | process\.env\.\w{0,48}""" + _SECRETISH_TOKEN + r"""\w{0,48}
          \s*\|\|\s* ['"][^'"\n]{6,}['"] )
    """
)


# A credential that has actually leaked looks like one: a vendor prefix, or a long
# opaque string. Documentation quotes `SECRET_KEY = "changeme"` on purpose — this
# project's own vector files are full of such examples — so prose is held to the
# higher bar rather than exempted, and a real key pasted into a README still fails.
HIGH_CONFIDENCE_SECRET_RE = re.compile(
    r"""(?x)
    # A private-key header opens with a hyphen, so \b cannot precede it.
      -----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----
    | \b(?: sk_live_[A-Za-z0-9]{10}
          | pk_live_[A-Za-z0-9]{10}
          | rk_live_[A-Za-z0-9]{10}
          | sk-[A-Za-z0-9]{20}
          | ghp_[A-Za-z0-9]{20} | gho_[A-Za-z0-9]{20} | github_pat_[A-Za-z0-9_]{20}
          | xox[baprs]-[A-Za-z0-9-]{10}
          | AKIA[0-9A-Z]{16}
          | AIza[0-9A-Za-z_\-]{35} )
    """
)


def secret_finding(path, body):
    if TEST_PATH_RE.search(path or ""):
        return None
    if PROSE_PATH_RE.search(path or ""):
        # Prose that quotes a bad example is teaching, not leaking. Only a literal
        # that carries a vendor prefix or a private-key header is treated as real.
        if HIGH_CONFIDENCE_SECRET_RE.search(body):
            return (
                "LEAKED CREDENTIAL IN DOCUMENTATION — this file contains a literal that "
                "carries a real credential's shape (a vendor prefix or a private-key "
                "header). Gate 30 FAILS. Documentation is published, indexed and cloned, "
                "so a key here is a key in public. Replace it with a placeholder, and "
                "treat the original as compromised: revoke it at the issuer (Gate 33)."
            )
        return None
    if SECRET_LITERAL_RE.search(body):
        return (
            "HARDCODED SECRET — a credential literal is assigned in source. Gate 30 FAILS. "
            "Read it from the environment at the point of use and let the process fail if "
            "it is absent (Gate 31: no fallback default). Placeholder strings like "
            "'change-me-in-production' count as failures — they ship."
        )
    if SECRET_FALLBACK_RE.search(body):
        return (
            "SECRET FALLBACK DEFAULT — an environment read supplies a literal default. "
            "Gate 31 FAILS. Index the environment directly so a missing value stops the "
            "process at startup instead of substituting a known one."
        )
    return None


# Files that end up in the browser. A key here is public the moment it ships.
CLIENT_PATH_RE = re.compile(
    r"\.(?:html?|jsx|tsx|vue|svelte|astro)$"
    r"|(?:^|/)(?:client|public|static|frontend|www|assets)/",
    re.IGNORECASE,
)
# Build-time env prefixes that are inlined into the bundle by design.
PUBLIC_ENV_SECRET_RE = re.compile(
    r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]*"
    r"(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)[A-Z0-9_]*\b"
)
# A literal bearer/api-key handed to a client-side call.
CLIENT_LITERAL_RE = re.compile(
    r"""(?ix)
    (?: (?:Authorization|X-Api-Key)\s*[:=]\s*['"`][^'"`]*\b(?:Bearer\s+)?[A-Za-z0-9_\-]{16,}
      | \b(?:api[_-]?key|apiKey|accessToken|access_token|clientSecret)\b\s*[:=]\s*['"`][^'"`]{12,}['"`]
      | \b(?:sk|pk|ghp|xox[baprs]|AKIA)[_-][A-Za-z0-9]{12,} )
    """
)


def client_secret_finding(path, body):
    """A credential that will be served to the browser. Gate 35."""
    if PROSE_PATH_RE.search(path or ""):
        # A document naming NEXT_PUBLIC_OPENAI_API_KEY is explaining the mistake,
        # not shipping it. This project's own secrets.md does exactly that.
        return None
    in_client = bool(CLIENT_PATH_RE.search(path or ""))
    pub = PUBLIC_ENV_SECRET_RE.search(body)
    lit = CLIENT_LITERAL_RE.search(body) if in_client else None
    if not (pub or lit):
        return None
    what = (
        f"a build-time public variable (`{pub.group(0)}`) carrying a credential"
        if pub else "a credential literal in a file that is served to the browser"
    )
    return (
        f"SECRET REACHES THE CLIENT — {what}. Gate 35 FAILS. Anything in the bundle is "
        "readable by every visitor: view-source, devtools, or the shipped JS. Move the "
        "call behind a server route that holds the key server-side and forwards only the "
        "result. A key that has already shipped this way must be treated as compromised "
        "and rotated at the issuer (Gate 33)."
    )


WEBHOOK_RE = re.compile(
    r"""(?ix)
    (?: ['"`][^'"`]*/webhooks?\b            # a route path containing /webhook
      | \bwebhook_(?:handler|endpoint|receiver)\b
      | \bhandle_webhook\b
      | \b(?:stripe|github|slack|shopify|twilio|paddle|lemonsqueezy)[._-]?webhook\b
      | \bWebhookEvent\b )
    """
)
# The vendor constructor, or a hand-rolled HMAC compare. Either is a real check.
WEBHOOK_VERIFY_RE = re.compile(
    r"""(?ix)
    (?: constructEvent | construct_event | SignatureVerifier
      | verify_signature | verifySignature | verify_webhook | verifyWebhook
      | compare_digest | timingSafeEqual
      | Stripe-Signature | X-Hub-Signature | X-Slack-Signature | X-Signature )
    """
)


def webhook_finding(path, body):
    """An inbound webhook handler that never authenticates the sender. Gate 96."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not WEBHOOK_RE.search(body):
        return None
    if WEBHOOK_VERIFY_RE.search(body):
        return None
    return (
        "UNVERIFIED WEBHOOK — this file handles an inbound webhook and never verifies the "
        "sender's signature. Gate 96 FAILS. The endpoint is public by design, so anyone "
        "who knows the URL can post a forged payload and drive whatever it triggers — "
        "marking an order paid, granting a plan, releasing a shipment. Verify with the "
        "vendor's own constructor as the handler's first statement "
        "(`stripe.webhooks.constructEvent`, `@octokit/webhooks` verify, Slack's "
        "`SignatureVerifier`) and use the object it returns instead of the raw body. "
        "Handlers must also be idempotent: providers retry, and a replayed delivery must "
        "not apply twice."
    )


# A value spliced into a query or command string: f-string, %, +, or `${}`.
_INTERP = r"""(?: f['"] | \$\{ | %\s*[\w(] | ['"`]\s*\+\s*\w | \.format\s*\( )"""

QUERY_INTERP_RE = re.compile(
    r"""(?ix)
    (?: \.(?:execute|executemany|query|fetch|fetchall|fetchone|raw)\s*\(\s*"""
    + _INTERP + r"""
      | \$queryRawUnsafe\s*\( | \$executeRawUnsafe\s*\(
      | \bsql\s*=\s*""" + _INTERP + r""".*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b
      | \b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;]{0,200}?""" + _INTERP + r""" )
    """,
    re.DOTALL,
)

SHELL_INTERP_RE = re.compile(
    r"""(?ix)
    (?: (?: os\.system | os\.popen | child_process\.exec | \bexecSync | \bshell_exec )
        \s*\(\s* [^)\n]{0,80}? """ + _INTERP + r"""
      | subprocess\.(?:run|call|check_output|Popen)\s*\([^)]*shell\s*=\s*True )
    """,
    re.DOTALL,
)

# A raw-HTML assignment whose right-hand side is a bare string literal is static
# markup the developer wrote — nothing user-shaped can ride in on it.
_ASSIGN_SINK_RE = re.compile(
    r"(?i)\b(?:innerHTML|outerHTML)\s*=\s*([^;\n]+)"
)
_PURE_LITERAL_RE = re.compile(
    r"""^\s*(?: '[^'{}$]*' | "[^"{}$]*" | `[^`{}$]*` )\s*;?\s*$""",
    re.VERBOSE,
)


def _has_dynamic_sink(body):
    for m in _ASSIGN_SINK_RE.finditer(body):
        if not _PURE_LITERAL_RE.match(m.group(1)):
            return True
    return False


RAW_SINK_RE = re.compile(
    r"""(?ix)
    (?: dangerouslySetInnerHTML\s*=\s*\{\{
      | v-html\s*=
      | \binsertAdjacentHTML\s*\( )
    """
)
SANITIZER_RE = re.compile(
    r"(?i)DOMPurify|sanitize-html|\bsanitize\w*\s*\(|bleach\.clean|escape\s*\(|xss\s*\("
)


# `execute(f"SELECT ... {where}", params)` is Gate 21 done right: the identifier or
# clause comes from source literals while the values stay bound. An interpolation
# with no bound parameters alongside it is the one that quotes by hand.
# Whether the interpolated call *also* binds parameters has to be read per call:
# one safe `execute(..., params)` elsewhere in the file must not excuse a query
# next to it that quotes by hand. After the interpolation, whichever comes first —
# the closing paren or a comma — says which shape this call is.
_CALL_TAIL_RE = re.compile(r"""['"`]\s*(?P<end>[,)])""")


def _binds_parameters(body, start):
    """True when the query call starting near `start` passes bound parameters."""
    m = _CALL_TAIL_RE.search(body, start, start + 400)
    return bool(m) and m.group("end") == ","


def sql_injection_finding(path, body):
    """A value interpolated into a query string. Gate 22 / 21 / 24."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    hit = next((m for m in QUERY_INTERP_RE.finditer(body)
                if not _binds_parameters(body, m.end())), None)
    if hit is None:
        return None
    return (
        "QUERY BUILT BY INTERPOLATION — a value is spliced into a query string instead of "
        "being bound as a parameter. Gate 22 FAILS. Quoting by hand is what SQL injection "
        "is; the driver's placeholder syntax is not a style preference. Pass values as "
        "bound parameters and let the driver quote them. Where an identifier (table or "
        "column) genuinely must vary, look it up in a dict of literals written in the "
        "source and interpolate the looked-up literal (Gate 21)."
    )


def command_injection_finding(path, body):
    """A value interpolated into a shell command. Gate 26."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not SHELL_INTERP_RE.search(body):
        return None
    return (
        "COMMAND BUILT BY INTERPOLATION — a value reaches a shell as text. Gate 26 FAILS. "
        "A semicolon, backtick or `$(...)` in that value runs as a command with this "
        "process's privileges. Pass the command as an argument list with no shell: "
        "`subprocess.run([...])` with shell=False (the default), or `execFile` / `spawn` "
        "without `shell: true` in Node."
    )


def xss_finding(path, body):
    """User-shaped data at a raw HTML sink with no sanitiser in the file. Gate 50."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not (RAW_SINK_RE.search(body) or _has_dynamic_sink(body)):
        return None
    if SANITIZER_RE.search(body):
        return None
    return (
        "RAW HTML SINK — a value is assigned to a sink that parses HTML, and nothing in "
        "this file sanitises it. Gate 50 FAILS. If any part of that string can come from a "
        "user, it carries script. Either build the node instead of the markup — set "
        "`textContent`, return a JSX child, use a template placeholder (Gate 51) — or "
        "sanitise with DOMPurify at the sink itself, as the last expression before the "
        "value enters it."
    )


# --- Cross-site request forgery and framing (Gates 130-132, 80, 7) ---

MUTATING_ROUTE_RE = re.compile(
    r"""(?ix)
      @(?:app|router|api|bp|blueprint)\.(?:post|put|patch|delete)\s*\(
    | \b(?:app|router|server|fastify)\.(?:post|put|patch|delete)\s*\(\s*['"`/]
    | @(?:Post|Put|Patch|Delete)Mapping | @(?:Post|Put|Patch|Delete)\s*\(
    | \bRoute::(?:post|put|patch|delete)\s*\(
    | \[Http(?:Post|Put|Patch|Delete)\b
    | \bexport\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\s*\(
    | methods\s*=\s*\[[^\]]*['"](?:POST|PUT|PATCH|DELETE)['"]
    """
)
# Identity that the browser attaches automatically — the precondition for CSRF.
COOKIE_AUTH_RE = re.compile(
    r"""(?ix)
      request\.session | req\.session | session\[ | \bcurrent_user\b | login_required
    | authenticate_user! | before_action\s+:authenticate | getServerSession
    | \bsession\.get\s*\( | flask_login | django\.contrib\.auth
    """
)
# Identity the caller must set explicitly — a cross-site form cannot.
HEADER_AUTH_RE = re.compile(
    r'''(?i)HTTPBearer|OAuth2|Authorization["']?\s*[:,]|Bearer\s|verify_token|decode_token|jwt\.decode'''
)
CSRF_DEFENCE_RE = re.compile(
    r"""(?ix)
      csrf | xsrf | verify_authenticity | authenticity_token | CsrfProtect | csurf
    | double_submit | \borigin_check\b | Sec-Fetch-Site
    """
)
MUTATION_VERB_RE = re.compile(
    r"""(?ix)
    \b(?: delete | destroy | remove | cancel | revoke | disable | deactivate
         | insert | update | commit | save | create | transfer | withdraw | charge
         | grant | promote | approve | send_money | move_money | drop )\b
    """
)
GET_ROUTE_RE = re.compile(
    r"""(?ix)
      @(?:app|router|api|bp|blueprint)\.get\s*\(
    | \b(?:app|router|server|fastify)\.get\s*\(\s*['"`/]
    | @GetMapping | @Get\s*\(
    | \bRoute::get\s*\(
    | \[HttpGet\b
    | \bexport\s+(?:async\s+)?function\s+GET\s*\(
    """
)

CORS_WILDCARD_RE = re.compile(
    r"""(?ix)
      allow_origins\s*=\s*\[\s*["']\*["']
    | origin\s*:\s*(?:["']\*["']|true)
    | Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']
    | CORS_ALLOW_ALL_ORIGINS\s*=\s*True
    | \bcors\s*\(\s*\)
    | Access-Control-Allow-Origin[^\n]{0,60}(?:req\.headers\.origin|request\.headers\[?["']?origin)
    """
)
CORS_CREDENTIALS_RE = re.compile(
    r"(?i)allow_credentials\s*=\s*True|credentials\s*:\s*true|supports_credentials\s*=\s*True"
    r"|withCredentials\s*:\s*true|CORS_ALLOW_CREDENTIALS\s*=\s*True"
)

SET_COOKIE_RE = re.compile(
    r"""(?ix)
      set_cookie\s*\(  | res\.cookie\s*\( | response\.cookie\s*\(
    | cookies\.set\s*\( | \bSet-Cookie["']?\s*[:,]
    """
)
AUTHY_COOKIE_RE = re.compile(r"(?i)session|token|auth|jwt|sid\b|remember")


def csrf_finding(path, body):
    """A cookie-authenticated mutation with no CSRF defence. Gate 130."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not MUTATING_ROUTE_RE.search(body):
        return None
    if not COOKIE_AUTH_RE.search(body):
        return None
    if HEADER_AUTH_RE.search(body) or CSRF_DEFENCE_RE.search(body):
        return None
    return (
        "CSRF — this route mutates state for a cookie-identified user and verifies no CSRF "
        "token. Gate 130 FAILS. The browser attaches the session cookie to a form submitted "
        "from any page, so a logged-in victim who loads an attacker's page performs the "
        "mutation without seeing it; the handler cannot tell, because the cookie and the user "
        "are both genuine and only the intent is forged. Put a per-session random token in a "
        "hidden field or request header and compare it with `hmac.compare_digest` as the "
        "handler's first statement — or authenticate this route from an `Authorization` "
        "header, which no cross-site form can set."
    )


def get_mutation_finding(path, body):
    """A mutation reachable by GET. Gate 131."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not GET_ROUTE_RE.search(body):
        return None
    if not MUTATION_VERB_RE.search(body):
        return None
    if MUTATING_ROUTE_RE.search(body):
        return None          # the file also defines proper mutating routes; too coarse to call
    return (
        "MUTATION BEHIND GET — a route registered for GET changes state. Gate 131 FAILS. "
        "Anything that can put a URL on a page issues a GET with the victim's cookies "
        "attached: an `<img src>`, a prefetch, a chat client's link preview. No form and no "
        "JavaScript are needed, so every CSRF defence that assumes a POST is bypassed by the "
        "method itself. Register the mutating route for POST/PUT/PATCH/DELETE and leave GET "
        "returning a page that submits it."
    )


def cors_finding(path, body):
    """Any-origin CORS combined with credentials. Gate 80."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not CORS_WILDCARD_RE.search(body):
        return None
    if not CORS_CREDENTIALS_RE.search(body):
        return None
    return (
        "CORS ANY-ORIGIN WITH CREDENTIALS — the allowed origin is a wildcard or reflected "
        "from the request, and credentials are enabled. Gate 80 FAILS. That combination lets "
        "a page on any origin issue authenticated requests to this API and read the "
        "responses, which is the same-origin policy switched off for logged-in users. "
        "Enumerate the permitted origins as literal strings in the source and let the "
        "middleware match against that list."
    )


def cookie_flags_finding(path, body):
    """A session cookie set without its three flags. Gate 7."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not SET_COOKIE_RE.search(body):
        return None
    if not AUTHY_COOKIE_RE.search(body):
        return None
    missing = [f for f, rx in (
        # The value may be a constant (secure=COOKIE_SECURE) rather than a literal.
        # Anything but an explicit falsy counts as set; naming a flag and disabling it
        # is a decision, not an omission, and this finding is about omissions.
        ("httpOnly", r"(?i)http_?only\s*[=:]\s*(?!False|false|0|None|null)\w"),
        ("secure", r"(?i)\bsecure\s*[=:]\s*(?!False|false|0|None|null)\w"),
        ("sameSite", r"(?i)same_?site\s*[=:]"),
    ) if not re.search(rx, body)]
    if not missing:
        return None
    return (
        f"SESSION COOKIE FLAGS — this cookie is set without {', '.join(missing)}. Gate 7 "
        "FAILS. Without httpOnly any injected script reads the session; without secure it "
        "travels in clear text on the first plain-HTTP request; without sameSite the browser "
        "attaches it to cross-site requests, which is the precondition for CSRF. Set all "
        "three."
    )


# --- Broken object-level authorization / IDOR (Gate 12) ---

# A record id arriving from the caller: path placeholder or a handler parameter.
ID_PARAM_RE = re.compile(
    r"""(?ix)
      \{\s*\w*_?id\s*(?::[^}]*)?\}          # FastAPI/Flask  /orders/{order_id}
    | :\w*_?[Ii]d\b                            # Express/Rails  /orders/:id
    | <\s*(?:int|uuid|str)?\s*:?\s*\w*_?id\s*>   # Flask converter  <int:order_id>
    | \[\s*\w*_?[Ii]d\s*\]                   # Next.js  [orderId]
    | \bdef\s+\w+\s*\([^)]*\b\w+_id\b            # def get(request, order_id)
    | \bdef\s+\w+\s*\([^)]*\bid\s*[:,)]          # def get(id: int)
    | \bparams\.\w*[Ii]d\b | \breq\.params\.\w*[Ii]d\b
    | \bparams\[\s*:\s*\w*_?id\s*\]              # Rails  params[:id]
    | \bparams\[["']\w*_?id["']\]                # PHP / JS  params["id"]
    """
)

# The lookup itself.
ID_LOOKUP_RE = re.compile(
    r"""(?ix)
      \.filter\s*\([^)]*\.id\s*== | \.get\s*\(\s*\w*_?id\s*\)
    | \.query\s*\([^)]*\)\.get\s*\( | \bfindById\s*\( | \bfind_by_id\s*\(
    | findUnique\s*\(\s*\{[^}]*\bid\b | findFirst\s*\(\s*\{[^}]*\bid\b
    | \bWHERE\s+\w*\.?id\s*= | objects\.get\s*\( | \.find\s*\(\s*\w*_?id\s*\)
    | \bfindOne\s*\(\s*\{\s*_?id
    | \.find\s*\(\s*params\[ | \.find_by\s*\(\s*id: | ::find\s*\(
    | \.findOrFail\s*\( | \bfindByPk\s*\(
    """
)

# Any sign the query is scoped to the caller. We do not need to know which column
# carries ownership — only whether the query mentions one at all.
OWNERSHIP_RE = re.compile(
    r"""(?ix)
      \buser_id\b | \bowner_id\b | \bauthor_id\b | \baccount_id\b | \btenant_id\b
    | \borg_id\b | \borganization_id\b | \bcustomer_id\b | \bteam_id\b
    | \buserId\b | \bownerId\b | \btenantId\b | \baccountId\b
    | current_user\s*\.\s*id | user\s*\.\s*id | req\.user\.id | request\.user\b
    | \.owner\b | \bbelongs_to\b | current_user\.\w+\.
    """
)

# A route the developer has already marked as privileged reads any record on purpose.
ADMIN_GATE_RE = re.compile(
    r"""(?ix)
      is_admin | isAdmin | require_role | requireRole | @Roles\s*\( | IsAdminUser
    | has_permission | hasPermission | @PreAuthorize | admin_required | staff_member_required
    """
)


def idor_finding(path, body):
    """An authenticated lookup by caller-supplied id with no ownership scope. Gate 12."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not (ID_PARAM_RE.search(body) and ID_LOOKUP_RE.search(body)):
        return None
    # No auth at all is the open-route finding's job, not this one.
    if not AUTH_RE.search(body):
        return None
    if OWNERSHIP_RE.search(body) or ADMIN_GATE_RE.search(body):
        return None
    return (
        "IDOR — this handler authenticates the caller, then fetches a record by an id taken "
        "from the request, and nothing in the query ties that record to the caller. Gate 12 "
        "FAILS. Every logged-in user can read (or write) every other user's record by "
        "changing one number in the URL; the session check passes, so nothing looks wrong in "
        "the logs. Put the ownership column in the WHERE clause of the same query that "
        "fetches the record, so a non-owner gets zero rows rather than a record plus a check "
        "a later refactor can drop. If this record really is global, or the route is meant to "
        "be privileged, add the role check that says so."
    )


# --- Credential handling (Gates 3, 120, 121) ---

# A password reaching a fast hash. The digest name and the word "password" have to
# meet in the same expression: hashing a file with sha256 is not this finding.
WEAK_PASSWORD_HASH_RE = re.compile(
    r"""(?ix)
    (?: hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512)\s*\([^)]{0,80}passw
      | (?:md5|sha1|sha256|sha512)\s*\([^)]{0,80}passw
      | createHash\s*\(\s*['"](?:md5|sha1|sha256|sha512)['"]\s*\)[^;\n]{0,120}passw
      | passw\w*[^;\n]{0,80}(?:hashlib\.)?(?:md5|sha1|sha256|sha512)\s*\(
      | digest\s*\(\s*\)[^;\n]{0,40}passw )
    """
)
STRONG_KDF_RE = re.compile(r"(?i)argon2|bcrypt|scrypt|pbkdf2|PasswordHasher|passlib")

# An endpoint that verifies or issues a credential.
CREDENTIAL_ROUTE_RE = re.compile(
    r"""(?ix)
    ['"`][^'"`]*/(?: login | signin | sign-in | log-in | auth(?:enticate)?
                   | register | signup | sign-up | token
                   | password/reset | reset-password | forgot )
    """
)
RATE_LIMIT_RE = re.compile(
    r"""(?ix)
      limiter | slowapi | ratelimit | rate_limit | express-rate-limit | throttle
    | Throttl | @limits | leaky | token_bucket | RateLimiter | flask_limiter
    | retry_after | Retry-After
    """
)
LOCKOUT_RE = re.compile(
    r"(?i)failed_attempts|failedAttempts|locked_until|lockedUntil|lockout|attempt_count|login_attempts"
)


def weak_password_hash_finding(path, body):
    """A password stored under a fast digest. Gate 3."""
    if PROSE_PATH_RE.search(path or ""):
        return None
    if not WEAK_PASSWORD_HASH_RE.search(body):
        return None
    if STRONG_KDF_RE.search(body):
        return None
    return (
        "PASSWORD UNDER A FAST HASH — a password is being put through a general-purpose "
        "digest. Gate 3 FAILS. SHA-256 and MD5 are built to be fast, which is the opposite "
        "of what a password needs: a consumer GPU walks billions of candidates a second, so "
        "a stolen table is a list of plaintext passwords by the weekend. Salting does not "
        "fix it — it only stops one table being reused for another. Hash with argon2id "
        "(`argon2-cffi`, or `argon2` in Node), or bcrypt where argon2 is unavailable."
    )


def credential_endpoint_finding(path, body):
    """A login-shaped route with no throttle and no attempt counter. Gates 120, 121."""
    if PROSE_PATH_RE.search(path or "") or TEST_PATH_RE.search(path or ""):
        return None
    if not (ROUTE_RE.search(body) and CREDENTIAL_ROUTE_RE.search(body)):
        return None
    missing = []
    if not RATE_LIMIT_RE.search(body):
        missing.append("no rate limit (Gate 120)")
    if not LOCKOUT_RE.search(body):
        missing.append("no per-account attempt counter (Gate 121)")
    if not missing:
        return None
    return (
        f"CREDENTIAL ENDPOINT WITHOUT A BOUND — {', and '.join(missing)}. This is the "
        "omission the whole registry exists for: the handler itself is correct, so nothing "
        "looks wrong, and a password list can be ground through it at full speed with every "
        "attempt returning a clean 401. Attach a limiter to the route, and store "
        "`failed_attempts` and `locked_until` on the user row — increment on the failure "
        "branch, set the lock from a backoff that grows with the count, clear both on "
        "success."
    )


# --- Summoning the registry ------------------------------------------------
# The skill loads on the model's judgement, and that judgement is a coin flip:
# measured across live runs it declined to load on the same prompt that loaded it
# minutes earlier. The guard has no such discretion — it fires on the write. So the
# first time a session touches a security surface, the guard asks for the registry
# by name. Once per session: the ask is cheap, repeating it is not.

SUMMON_DIR = os.path.expanduser("~/.cache/airtight/sessions")

SUMMON = (
    "AIRTIGHT REGISTRY NOT LOADED — this session is writing code on a security "
    "surface without the gate registry in context. Load it now: invoke the Skill tool "
    "with name `airtight`, before the next write. This guard denies only the failures "
    "it can prove mechanically; the registry carries the rest of the standard — which "
    "key-derivation function counts, which cookie flags, which bound belongs on which "
    "endpoint. Load it once and continue; you will not be asked again this session."
)


def _summon_once(session_id):
    """Return the summon text the first time a session needs it, else None."""
    if not session_id:
        return None
    try:
        os.makedirs(SUMMON_DIR, exist_ok=True)
        stamp = os.path.join(SUMMON_DIR, re.sub(r"[^A-Za-z0-9_-]", "", session_id)[:64])
        # O_EXCL makes the check and the claim one step, so two writes racing in the
        # same session cannot both decide they are the first.
        os.close(os.open(stamp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        return None
    except OSError:
        return None
    return SUMMON


def load_gate_lines():
    out = {}
    if not GATES:
        return out
    with open(GATES, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^- Gate (\d+) ", line)
            if m:
                out[int(m.group(1))] = line.strip()
    return out


MAX_BODY = 200_000   # a regex sweep over a megabyte of generated code helps nobody


def run(raw):
    payload = json.loads(raw)
    session_id = payload.get("session_id")
    if payload.get("tool_name") not in ("Write", "Edit", "MultiEdit"):
        return
    ti = payload.get("tool_input") or {}
    path = ti.get("file_path", "") or ""
    body = " ".join(str(ti.get(k, "")) for k in ("content", "new_string", "edits"))
    if not body.strip() or len(body) > MAX_BODY:
        return

    findings = [f for f in (
        open_route_finding(path, body),
        webhook_finding(path, body),
        sql_injection_finding(path, body),
        command_injection_finding(path, body),
        xss_finding(path, body),
        idor_finding(path, body),
        weak_password_hash_finding(path, body),
        credential_endpoint_finding(path, body),
        csrf_finding(path, body),
        get_mutation_finding(path, body),
        cors_finding(path, body),
        cookie_flags_finding(path, body),
        secret_finding(path, body),
        client_secret_finding(path, body),
    ) if f]

    hits = []
    for name, rng, pats in SURFACES:
        if any(re.search(p, body, re.IGNORECASE) for p in pats):
            hits.append((name, rng))
    for pat, name, rng in PATH_SURFACES:
        if re.search(pat, path, re.IGNORECASE):
            hits.append((name, rng))
    if not hits and not findings:
        return

    # Documentation that discusses a surface is not code being written on one, so it
    # does not need the registry pulled into context.
    summon = None if PROSE_PATH_RE.search(path or "") else _summon_once(session_id)

    gate_lines = load_gate_lines()
    blocks, budget = [], 2600          # cap: the guard must never balloon context
    for name, rng in hits[:3]:         # SURFACES is ordered by priority
        lines = [gate_lines[n] for n in rng if n in gate_lines]
        if not lines:
            continue
        block = f"{name}:\n" + "\n".join(lines)
        if len(block) > budget:
            break
        blocks.append(block)
        budget -= len(block)
    if not blocks and not findings:
        return

    head = (
        "Airtight surface guard — this edit touches a security surface. "
        "These gates are in scope; satisfy them before the code ships. "
        "A gate you cannot verify counts as failed. Stay silent about this "
        "check in your reply; just emit code that passes."
    )
    # A finding is a gate failure the guard can see deterministically, so it blocks
    # the write outright — advisory context is ignorable, a denial is not. Escape
    # hatch: an `airtight: public` / `airtight: allow` comment in the file.
    if findings:
        reason = (
            "Airtight gate failure — this write is blocked.\n\n"
            + ((summon + "\n\n") if summon else "")
            + "\n\n".join(findings)
            + "\n\n**Fix it and write again.** That is the expected outcome here, not a "
            "question: the remedy is named above, and the developer asked for working code, "
            "not for a decision they did not know they were making. Apply the fix, write the "
            "file, and close with one plain line saying what you hardened.\n\n"
            "Ask them only when the fix genuinely needs a fact you do not have — which "
            "identity provider this project uses, which roles exist, whether a public "
            "endpoint is deliberate. Wanting to avoid the work is not such a fact, and "
            "abandoning the task leaves them with nothing, which is worse than either "
            "outcome.\n\n"
            "You may NOT self-authorise past this: a comment, a rename, or restructuring to "
            "dodge the check is not a fix, and no marker you write will lift it. The only "
            "override belongs to the developer — `AIRTIGHT_GUARD=off` in the environment. "
            "Name that lever if you must, but never set it yourself."
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
        return

    # Advisory context was measured to be ignorable — the same finding produced a
    # hardened endpoint on one run and was skipped on the next. Denials are what
    # actually hold, so the advisory path is off unless asked for: a clean write
    # costs nothing at all.
    if os.environ.get("AIRTIGHT_GUARD", "").lower() != "verbose":
        if summon:
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": summon,
            }}))
        return
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "\n\n".join([head] + blocks),
        }
    }))


# --- Regression suite -------------------------------------------------------
# Run it with `airtight-surface-guard.py --selftest`. It exercises the findings
# against code that must be denied and code that must not, because a guard that
# blocks clean work is worse than no guard: it gets switched off.

# Secret-shaped fixtures are assembled at runtime rather than written out. A file
# that teaches a scanner what a leaked key looks like will be read by other
# scanners too — GitHub's push protection rejected this very file once for
# carrying one. The guard sees the joined string; a scanner reading the source
# does not.
def _fixture(prefix, body):
    return prefix + body


_CASES_DENY = [
    ("open route / FastAPI", "/x/m.py", '@app.get("/o")\ndef f(db=Depends(get_db)):\n    return db.query(O).all()'),
    ("open route / Flask", "/x/a.py", '@app.route("/o")\ndef o(): return jsonify(q.all())'),
    ("open route / Django", "/x/v.py", 'def order_list(request):\n    return JsonResponse(list(O.objects.all()))'),
    ("open route / Express", "/x/s.js", 'app.get("/o",(req,res)=>res.json(db.all()))'),
    ("open route / NestJS", "/x/c.ts", '@Controller("o")\nexport class C { @Get() a(){return this.s.all()} }'),
    ("open route / Next.js", "/x/app/api/o/route.ts", 'export async function GET(){return Response.json(await db.o.findMany())}'),
    ("open route / gin", "/x/m.go", 'r.GET("/o",func(c *gin.Context){c.JSON(200,all())})'),
    ("open route / Spring", "/x/C.java", '@RestController class C { @GetMapping("/o") List<O> a(){return r.findAll();} }'),
    ("open route / Laravel", "/x/web.php", 'Route::get("/o",[C::class,"i"]);'),
    ("open route / Rails", "/x/c.rb", 'class OrdersController < ApplicationController\n  def index\n    render json: Order.all\n  end\nend'),
    ("open route / ASP.NET", "/x/C.cs", '[HttpGet("/o")]\npublic IActionResult Get() => Ok(_db.Orders.ToList());'),
    ("open route / axum", "/x/main.rs", 'let app = Router::new().route("/o", get(list));'),
    ("open route / crow", "/x/main.cpp", 'CROW_ROUTE(app,"/o")([](){ return dump(); });'),
    ("idor / FastAPI", "/x/m.py", '@app.get("/orders/{oid}")\ndef f(oid:int, u=Depends(get_current_user), db=Depends(get_db)):\n    return db.query(Order).filter(Order.id==oid).first()'),
    ("idor / Rails", "/x/c.rb", 'class OrdersController < ApplicationController\n  before_action :authenticate_user!\n  def show\n    render json: Order.find(params[:id])\n  end\nend'),
    ("sqli / f-string", "/x/d.py", 'db.execute(f"SELECT * FROM i WHERE n=\'{q}\'")'),
    ("sqli / template", "/x/d.js", 'db.query(`SELECT * FROM u WHERE id=${id}`)'),
    ("command / os.system", "/x/c.py", 'os.system(f"convert {n} o.png")'),
    ("command / shell=True", "/x/c.py", 'subprocess.run(cmd, shell=True)'),
    ("xss / innerHTML", "/x/u.js", 'el.innerHTML = userBio'),
    ("xss / react", "/x/B.jsx", '<div dangerouslySetInnerHTML={{__html: h}} />'),
    ("csrf", "/x/m.py", '@app.post("/transfer")\ndef t(request: Request, a:int):\n    move_money(request.session["user_id"], a)'),
    ("get mutation", "/x/m.py", '@app.get("/cancel")\ndef c(request: Request):\n    cancel_subscription(request.session["user_id"])'),
    ("cors wildcard + credentials", "/x/m.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)'),
    ("cookie flags", "/x/m.py", 'response.set_cookie("session", token)'),
    ("webhook unsigned", "/x/w.py", '@app.post("/webhooks/stripe")\nasync def w(r:Request):\n    p=await r.json()'),
    ("secret literal", "/x/c.py", 'SECRET_KEY="sk-prod-9f3a2b"'),
    ("secret fallback", "/x/c.py", 'K=os.environ.get("API_KEY","dev-key-xx")'),
    ("secret in html", "/x/i.html", '<script>const apiKey="' + _fixture("sk_" + "live_", "51HxxxxxxxxxxAbCd") + '"</script>'),
    ("secret in NEXT_PUBLIC", "/x/p.tsx", 'const k=process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY'),
    ("secret in readme", "/x/README.md", 'api_key = "' + _fixture("sk_" + "live_", "51HxxxxxxxxxxAbCdEf") + '"'),
    # Regressions found against real generated code — each of these once slipped through.
    ("sqli beside a safe call", "/x/d.py", 'db.execute("SELECT * FROM logs WHERE id=?", (i,))\ndb.execute(f"SELECT * FROM u WHERE name=\'{name}\'")'),
    ("open route beside a user helper", "/x/m.py", '@app.get("/orders")\ndef f(db=Depends(get_db)):\n    return db.query(Order).all()\n\ndef get_user_by_id(uid):\n    return db.query(User).get(uid)'),
    ("cookie explicitly insecure", "/x/m.py", 'response.set_cookie("session", t, httponly=True, secure=False, samesite="lax")'),
    ("real secret fallback", "/x/c.py", 'K = os.environ.get("JWT_SECRET_KEY", "dev-secret-value")'),
    ("secret outside tests", "/x/app/conf.py", 'API_KEY = "' + _fixture("sk_" + "live_", "51HxxxxxxxxxxAbCdEf") + '"'),
    ("stripe key in a readme", "/x/README.md", 'Use ' + _fixture("sk_" + "live_", "51H8xKvL2eZvKYlo2C0aBcDeFg")),
    ("aws key in docs", "/x/docs/s.md", 'AWS_ACCESS_KEY_ID=' + _fixture("AKI" + "A", "IOSFODNN7EXAMPLE")),
    ("private key header in docs", "/x/n.md", '-----BEGIN RSA PRIVATE KEY-----'),
    ("github pat in docs", "/x/n.md", 'token: ' + _fixture("ghp" + "_", "aBcDeFgHiJkLmNoPqRsTuV")),
    ("password under sha256", "/x/a.py", 'import hashlib\ndef hash_password(password):\n    return hashlib.sha256(password.encode()).hexdigest()'),
    ("password under md5", "/x/a.py", 'h = md5(password.encode()).hexdigest()'),
    ("password via node createHash", "/x/a.js", "const h = createHash('sha256').update(password).digest('hex')"),
    ("login without a bound", "/x/m.py", '@app.post("/login")\ndef login(request: Request, body: Creds):\n    u = db.get(body.email)\n    return {"token": make_token(u.id)}'),
    ("login beside an open route", "/x/m.py", '@app.post("/login")\n@limiter.limit("5/minute")\ndef login(b: Creds):\n    if u.failed_attempts>5: raise HTTPException(429)\n    return {"t":1}\n\n@app.get("/orders")\ndef orders(db=Depends(get_db)):\n    return db.query(Order).all()'),
]

_CASES_ALLOW = [
    ("route with auth", "/x/m.py", '@app.get("/o")\ndef f(u=Depends(get_current_user)):\n    return q.filter(O.user_id==u.id).limit(9).all()'),
    ("ownership scoped", "/x/m.py", '@app.get("/orders/{oid}")\ndef f(oid:int, u=Depends(get_current_user), db=Depends(get_db)):\n    return db.query(Order).filter(Order.id==oid, Order.user_id==u.id).first()'),
    ("rails ownership", "/x/c.rb", 'class OrdersController < ApplicationController\n  before_action :authenticate_user!\n  def show\n    render json: current_user.orders.find(params[:id])\n  end\nend'),
    ("admin route", "/x/m.py", '@app.get("/admin/o/{oid}")\ndef f(oid:int, u=Depends(require_role("admin")), db=Depends(get_db)):\n    return db.query(O).filter(O.id==oid).first()'),
    ("nest guards", "/x/c.ts", '@UseGuards(AuthGuard)\n@Controller("o")\nexport class C { @Get() a(){} }'),
    ("laravel auth middleware", "/x/web.php", 'Route::get("/o",[C::class,"i"])->middleware("auth");'),
    ("next session", "/x/app/api/o/route.ts", 'export async function GET(){const s=await getServerSession();}'),
    ("csrf token present", "/x/m.py", '@app.post("/t")\ndef t(request: Request, token: str = Form(...)):\n    if not hmac.compare_digest(token, request.session["csrf_token"]): raise HTTPException(403)\n    move_money(request.session["user_id"],1)'),
    ("bearer not cookie", "/x/m.py", '@app.post("/t")\ndef t(u=Depends(HTTPBearer())):\n    move_money(u.id,1)'),
    ("cors allowlist", "/x/m.py", 'app.add_middleware(CORSMiddleware, allow_origins=["https://a.example.com"], allow_credentials=True)'),
    ("cors wildcard, no credentials", "/x/m.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"])'),
    ("cookie with flags", "/x/m.py", 'response.set_cookie("session", t, httponly=True, secure=True, samesite="lax")'),
    ("webhook verified", "/x/w.py", '@app.post("/webhooks/stripe")\nasync def w(r:Request,sig=Header(alias="Stripe-Signature")):\n    e=stripe.Webhook.constructEvent(await r.body(),sig,S)'),
    ("bound parameters", "/x/d.py", 'db.execute("SELECT * FROM u WHERE id=?", (uid,))'),
    ("subprocess arg list", "/x/c.py", 'subprocess.run(["convert", n, "o.png"])'),
    ("innerHTML literal", "/x/u.js", 'box.innerHTML = "<b>Hi</b>";'),
    ("sanitised sink", "/x/u.js", 'el.innerHTML = DOMPurify.sanitize(bio)'),
    ("array find", "/x/u.js", 'const u=users.find(x=>x.id===1)'),
    ("react useParams", "/x/P.jsx", 'const {id}=useParams(); const i=items.find(x=>x.id===id)'),
    ("url registration file", "/x/urls.py", 'urlpatterns=[path("o/",views.o)]'),
    ("react component", "/x/B.jsx", 'export function B({l}){return <button>{l}</button>}'),
    ("static html", "/x/i.html", '<h1>Shop</h1>'),
    ("plain utility", "/x/u.py", 'def slug(s): return s.lower()'),
    ("id utility", "/x/u.py", 'def get_by_id(items, item_id):\n    return next((i for i in items if i.id==item_id), None)'),
    ("test file", "/x/t.py", 'def test_a(): assert 1==1'),
    ("plain c", "/x/u.c", 'int add(int a,int b){return a+b;}'),
    ("plain rust", "/x/u.rs", 'fn slug(s:&str)->String{s.to_lowercase()}'),
    ("prose about routes", "/x/README.md", 'Guard denies `@app.get("/orders")` when nothing derives identity.'),
    ("prose about webhooks", "/x/n.md", 'Catches `@app.post("/webhooks/stripe")` with no signature check.'),
    ("env read, no fallback", "/x/c.py", 'K=os.environ["API_KEY"]'),
    ("teaching example in prose", "/x/n.md", 'Fails: SECRET_KEY = "changeme-in-production"'),
    ("public env var named in prose", "/x/n.md", 'Never use NEXT_PUBLIC_OPENAI_API_KEY for a server key.'),
    ("argon2 hashing", "/x/a.py", 'from argon2 import PasswordHasher\nph=PasswordHasher()\ndef hash_password(password): return ph.hash(password)'),
    ("bcrypt hashing", "/x/a.js", 'const h = await bcrypt.hash(password, 12)'),
    ("sha256 of a file", "/x/u.py", 'import hashlib\ndigest = hashlib.sha256(open(f,"rb").read()).hexdigest()'),
    ("sha256 of a session token", "/x/a.py", 'import hashlib\nfingerprint = hashlib.sha256(token.encode()).hexdigest()'),
    ("login with limiter and lockout", "/x/m.py", '@app.post("/login")\n@limiter.limit("5/minute")\ndef login(request: Request, body: Creds):\n    u=db.get(body.email)\n    if u.failed_attempts>5 and u.locked_until>now(): raise HTTPException(429)\n    return {"t": t}'),
    # False positives found against real generated code — each of these was once denied.
    ("css url() in a landing page", "/x/i.html", '<style>@import url("https://fonts.googleapis.com/css2?family=X");</style><h1>Coffee</h1>'),
    ("non-secret env default", "/x/c.py", 'DATABASE_PATH = os.environ.get("DATABASE_PATH", "./coffee.db")'),
    ("fixture password in conftest", "/x/tests/conftest.py", 'PASSWORD = "kofe-na-goncharnoy-12"'),
    ("fixture password in test file", "/x/backend/tests/test_api.py", 'PASSWORD = "test-pass-12345"'),
    ("cookie flag via constant", "/x/m.py", 'COOKIE_SECURE = True\nresponse.set_cookie("session", t, httponly=True, secure=COOKIE_SECURE, samesite="lax")'),
    ("gate 21 clause from literals", "/x/m.py", 'where = " AND ".join(WHERE_LITERALS)\ntotal = conn.execute(f"SELECT COUNT(*) FROM orders {where}", scope).fetchone()'),
    ("auth dependency named current_session", "/x/m.py", '@app.get("/orders")\ndef f(session = Depends(current_session), conn = Depends(get_conn)):\n    return conn.execute("SELECT * FROM orders WHERE user_id=?", (session.user_id,)).fetchall()'),
]


def _decide(path, content):
    """Return the decision for one write, without touching stdout."""
    import io
    import contextlib

    payload = json.dumps({"tool_name": "Write",
                          "tool_input": {"file_path": path, "content": content}})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run(payload)
    out = buf.getvalue().strip()
    if not out:
        return "silent"
    return json.loads(out)["hookSpecificOutput"].get("permissionDecision", "context")


def selftest():
    failures = []
    for label, path, code in _CASES_DENY:
        got = _decide(path, code)
        if got != "deny":
            failures.append(f"  MISS   {label}: expected deny, got {got}")
    for label, path, code in _CASES_ALLOW:
        got = _decide(path, code)
        if got == "deny":
            failures.append(f"  FALSE  {label}: denied clean code")

    total = len(_CASES_DENY) + len(_CASES_ALLOW)
    gates = len(load_gate_lines())
    print(f"registry: {gates} gates from {GATES or 'NOT FOUND'}")
    print(f"cases:    {total - len(failures)}/{total} "
          f"({len(_CASES_DENY)} must deny, {len(_CASES_ALLOW)} must pass)")
    if failures:
        print("\n".join(failures))
        print("SELFTEST FAILED")
        raise SystemExit(1)
    print("SELFTEST OK")
