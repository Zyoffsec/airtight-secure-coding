# Server-side request forgery

Ask a model to "let users import an image from a URL" and it returns exactly that:
`fetch(req.body.url)`, the bytes streamed to storage, the content type read off the response. The
feature works on the first try, handles `https://example.com/cat.png` perfectly, and is finished
code by every measure the request set. It is also a request the caller composes and your server
sends — from inside your network, with your instance's identity, to any address your server can
reach. The caller supplies the destination; you supply the network position. This file gates the
emission decisions in that flow: which destinations an outbound client may be handed, what happens
on a redirect, how a stored callback URL is constrained at delivery, and what a document renderer is
allowed to fetch on the caller's behalf.

## Load this file when

- A request value — body field, query param, path segment, header — reaches an outbound HTTP client:
  `fetch`, `axios`, `got`, `undici.request`, `http.get`, `requests`, `httpx`,
  `urllib.request.urlopen`, `curl`.
- The request mentions importing, fetching, previewing, mirroring, proxying, scraping or unfurling a
  URL, or a "paste a link" field of any kind.
- Code stores a user-supplied URL for later use: webhook, callback, subscription target,
  notification endpoint, avatar source, RSS or import feed.
- A worker, cron job or queue consumer sends an HTTP request to a URL it loaded from the database.
- Code renders or parses a user-supplied document with an engine that can reach the network:
  headless-browser HTML-to-PDF, an SVG rasterizer, an XML parser, an office-document or template
  converter, an image processor handed a remote reference.
- An HTTP client is constructed with redirect behaviour, a proxy, a custom agent or a `lookup` hook
  — or with none of those, on a call whose URL came from a request.
- A URL string is assembled by interpolation and the host, scheme or authority portion is not
  written literally in the source.

## Gates


### Gate 70 — Outbound destination allowlist

> Code that passes a request-supplied URL to an outbound HTTP client MUST NOT be emitted unless the
> destination is constrained before the request is made, either by checking the parsed scheme and
> host against an allowlist of literal values written in the source or by routing the call through a
> dedicated egress proxy that enforces one.

**Applies when:** any value that arrived from a caller — directly, or read back out of storage after
a caller put it there — determines the scheme, host or port an HTTP client connects to.


**Fix:** Parse the URL, check `protocol` and `hostname` against a `Set` of literal values written in
the source, and reject otherwise — the allowlist is also what makes `file:///etc/passwd` and
`gopher://` fail closed, since neither carries a host that can be on it. Where the destination set
is not enumerable, do not fall back to a denylist of internal ranges: it is bypassed by a redirect
(Gate 71), by DNS that answers publicly on the first lookup and privately on the second, by
`[::ffff:127.0.0.1]`, by `2130706433` and `0177.0.0.1`, by `0.0.0.0`, and by any of the wildcard DNS
services that resolve a name you have never seen to an address you tried to block. Route those calls
through an egress proxy instead — see Gate 74. A URL interpolated into a shell `curl` is Gate 26
before it is this gate.


### Gate 71 — Redirects on a fetched URL

> Code that fetches a request-supplied URL MUST NOT be emitted unless redirects are disabled at the
> call site (`redirect: "manual"`, `maxRedirections: 0`, `allow_redirects=False`) or each hop's
> destination is re-checked against the same constraint before it is followed.

**Applies when:** an outbound client is called with a URL that originated from a caller, and the
client's redirect behaviour is left at its default.


**Fix:** Set `redirect: "manual"` (undici `maxRedirections: 0`, Python `allow_redirects=False`) and
follow hops yourself, running the same scheme-and-host check on each `Location` before the next
request, with a hop cap. Where the client is a shared instance, set it on the client rather than per
call, so a later caller cannot omit it.


### Gate 74 — Stored callback destination

> Code that sends an HTTP request to a user-supplied URL loaded from storage — a webhook, callback
> or subscription target — MUST NOT be emitted unless the destination is constrained at the moment
> of delivery, by routing the call through an egress proxy that denies private destinations or by
> validating the address the connection actually resolves to, and never only by a check performed
> when the URL was saved.

**Applies when:** a delivery path, worker, queue consumer or cron job reads a URL out of a table or
config that a user put there, and calls it.


**Fix:** Send webhook traffic through a dedicated egress proxy that allows only public destinations,
and give the delivery client that proxy as its dispatcher with redirects off. Where a proxy is not
available, validate in-process with a `lookup` hook on the client's agent that rejects every
resolved address outside public ranges — the check has to run on the address the socket connects to,
not on a hostname resolved separately beforehand, or the second resolution is the one that lands.


### Gate 76 — Remote resources in rendered documents

> Code that renders or parses a user-supplied document with an engine capable of fetching remote
> resources MUST NOT be emitted unless outbound requests are denied by default at the engine's
> configuration site, with any permitted destinations named literally in the source.

**Applies when:** caller-supplied HTML, SVG, XML, Markdown-with-embeds or an office document is
handed to a headless browser, a rasterizer, a converter or a parser that resolves references while
it works.


**Fix:** Turn on request interception and abort by default, continuing only for a scheme and host on
a literal allowlist — inline the document's own assets as data URIs so the render needs no network
at all. For XML in Python, construct the parser with `lxml.etree.XMLParser(resolve_entities=False,
no_network=True)` or use `defusedxml`; do not rely on the parser's default.


## Out of scope

- **A denylist of private ranges.** Not a separate gate: it is already a Gate 70 failure, since the
  escape clause is an allowlist or a proxy and a denylist is neither. Why it fails is in Gate 70's
  fix.
- **Pinning the resolved address against DNS rebinding.** Real, and the reason Gate 70's escape is
  an allowlist rather than a check: when the host must be one of a few literal names, the attacker
  does not control the name being resolved, so there is nothing to rebind. It bites only in the
  denylist design Gate 70 already fails and in the Gate 74 delivery path, where it is part of that
  gate's escape. No gate of its own.
- **The cloud metadata endpoint.** The classic target, not an emission condition — no line of code
  passes or fails "169.254.169.254 exists". Enforcing IMDSv2 and a hop limit is the right answer and
  it is infrastructure configuration, not application code. Say it is unaddressed; do not cite a
  gate.
- **A standalone scheme allowlist.** Subsumed. `file:///etc/passwd`, `gopher://` and `dict://` carry
  no host that can appear on Gate 70's allowlist, so they fail it closed; `urllib.request.urlopen`
  handing back a local file is that gate, not another one.
- **Timeouts, response size caps and retry budgets on outbound calls.** Availability rather than
  forgery, and the right values are deployment decisions no line in the handler passes or fails.
- **Interpolating a request value into the path of a fixed, allowlisted URL.** A genuine bug —
  `..%2f` in a path segment reaches endpoints on that host the caller was not offered — but the host
  is still one you chose, so there is no pivot into your network. Ungated in this range today; 72,
  73, 75 and 77-79 are held.
- **Whether the fetched body may be returned to the caller.** Blind against non-blind changes the
  attacker's payoff, not what may be emitted, and returning the body is usually the feature — a link
  preview that shows nothing is not a link preview.
- **Network segmentation, egress firewall rules, VPC design.** The durable fix, at a layer the code
  cannot see. Note its absence in an audit; there is no gate for it.
- **Signature verification on inbound webhooks.** The opposite direction — traffic arriving, not
  leaving. It triggers this file only because webhooks do, and it is Gate 96 in `integrity.md`.
- **What the fetch error tells the caller.** A 502 carrying `ECONNREFUSED 10.0.0.5:9200` is a port
  scanner with a UI, and it is Gate 37, not a gate here.
- **Whether a caller may register a webhook at all, or read another org's deliveries.** Gates 10-19.
  That the URL field parses is Gate 40; that the parsed value is the one fetched is Gate 43.

## Prove probes

- Gate 70 — POST the developer's own import or preview endpoint twice with `url` pointing at
  loopback: once at the app's own port (`http://127.0.0.1:3000/`) and once at a closed one
  (`http://127.0.0.1:1/`) -> HELD if both are rejected identically before any request is made — a
  400 naming the host constraint, same body for both. FAILED if the app's own page comes back
  rendered as a preview, or if the closed port produces anything the caller can distinguish from the
  rejection: a 502 "could not fetch", an `ECONNREFUSED` in the body, a timeout that reads
  differently. The fetch being *attempted* is the failure; whether it succeeded is the target's
  business, not the gate's. Keep the probe on loopback — a metadata address or any host off the
  machine is rail 2, and the loopback answer settles the gate anyway.
- Gate 71 — not provable read-only in the general case: demonstrating a redirect needs a redirector,
  and standing one up is a service `prove` does not start. Reason from code — `redirect`,
  `maxRedirections` and `allow_redirects` are readable at the call site or at the client instance's
  configuration site, and their absence is the finding.
- Gate 74 — not provable read-only. Delivery fires on an event, and producing the event is a write
  through the application; registering a subscription to observe it is another. Reason from code —
  the dispatcher, proxy and redirect settings are readable where the delivery client is constructed.
- Gate 76 — not provable read-only. A render endpoint that would demonstrate it generally persists
  the document it produced, and whether the engine made the request is not visible in the output it
  hands back. Reason from code — `setRequestInterception` / `page.route`, and the XML parser's
  `resolve_entities` and `no_network`, are readable where the page or parser is created.
