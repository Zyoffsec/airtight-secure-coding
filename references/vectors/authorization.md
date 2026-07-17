# Authorization and access control

Asked for "an endpoint to fetch an invoice", a model writes one that fetches the invoice. It will
often add `requireAuth`, because logging in is part of the feature — and then look up the record by
the id in the URL, because that is what the URL is for. The result authenticates every caller and
authorizes none of them: change the id, read someone else's record. The same default produces admin
routes guarded only by being logged in, update handlers that spread the whole request body into the
record, and org-scoped queries that trust the org id in the path.

## Load this file when

- A handler reads an identifier from the URL, path params, query string or request body and uses it
  to look up a record.
- The code mentions roles, permissions, `isAdmin`, `requireAuth`, `requireRole`, or a middleware that
  gates a route.
- Any route path contains `/admin`, `/internal`, `/manage`, or a resource id segment (`/:id`,
  `{id}`).
- A record is created or updated from a request body, an ORM `update`/`create` call, or a spread of
  user-supplied fields.
- The data model has an owner column (`userId`, `ownerId`, `createdBy`) or a tenant column (`orgId`,
  `tenantId`, `workspaceId`, `accountId`).
- The request carries identity outside the session: `req.body.userId`, `?userId=`, an `X-User-Id`
  header, a user id in a JWT claim the server did not sign.
- The developer describes users, teams, organizations, workspaces, or "only the owner should see
  this".

## Gates


### Gate 10 — Server-side identity

> Code that decides whose data to read or write MUST NOT be emitted unless the acting user's identity
> comes from the server-side session, a server-verified token claim, or a server-issued request
> context — never from a path param, query param, request body field or client-set header.

**Applies when:** a handler needs to know who is calling.

**Passes:**
`(example omitted)`

**Fails:**
`(example omitted)`

**Why:** The client-supplied id lets an attacker send someone else's: `GET /api/orders?userId=42` returns another user's data, and `requireAuth` proves nothing beyond having an account.

**Fix:** Take identity only from `req.session` (or verified token claims), never from the request. When the client must name a different user (e.g. an admin), that is privileged and Gate 11 applies.

### Gate 11 — Privileged route authorization

> A route handler that performs a privileged action MUST NOT be emitted unless the handler chain
> checks the caller's role or permission server-side, from server-side state.

**Applies when:** the route lists, edits or deletes other users' data, changes roles or billing,
reads logs or metrics, or sits under an `/admin`, `/internal` or `/manage` path.

**Passes:** `app.get("/api/admin/users", requireAuth, requireRole("admin"), handler)`

**Fails:** `app.get("/api/admin/users", requireAuth, handler)`

**Why:** Any logged-in user who types the path reaches the route; hiding the UI link is not a check.

**Fix:** Add a role check to the handler chain that reads the role from the session or a server-side
lookup by session user id, and reject with 403 before the handler body runs. Never read the role from
the request body, a client-set header, or an unverified token.

### Gate 12 — Object ownership check

> Code that fetches or mutates a record identified by a client-supplied id MUST NOT be emitted unless
> the ownership or membership predicate is part of the lookup itself, or is verified against the
> session user before the record is used or returned.

**Applies when:** any handler takes an id from the path, query or body and passes it to a
`findUnique`, `findByPk`, `get`, `SELECT ... WHERE id = ?`, `update` or `delete`.


**Fix:** Put the ownership column in the `WHERE` clause of the same query that fetches the record, so
a non-owner gets zero rows rather than a record plus a check that a later refactor can drop. Return
404, not 403 — 403 confirms the id exists.


### Gate 13 — Mass assignment allowlist

> Code that creates or updates a persisted record from a request body MUST NOT be emitted unless the
> fields written are an explicit allowlist named literally in the source — a typed schema, a
> field-by-field assignment, or an ORM `select`/`pick` of named columns.

**Applies when:** a request body reaches an ORM `create`/`update`/`save`, a `$set`, a `**payload`
spread, or `Object.assign(record, req.body)`.

**Passes:**
`(example omitted)`

**Fails:**
`(example omitted)`

**Why:** Even correctly scoped to the caller's own record (Gate 12), a raw-body write grants admin to anyone who sends `{"role": "admin"}` to their own profile endpoint.

**Fix:** Declare a schema listing only the editable fields (a Pydantic model, a zod schema, a
serializer) and write the validated object, never the raw body. Fields that authorize — `role`,
`isAdmin`, `plan`, `ownerId`, `orgId`, `verified` — are changed by their own privileged endpoints
under Gate 11, not by a profile update.

### Gate 15 — Tenant scoping

> Code that queries a tenant-owned collection MUST NOT be emitted unless the tenant identifier used
> in the query is derived from the session or verified against the session user's membership before
> the query runs.

**Applies when:** the schema has an `orgId`, `tenantId`, `workspaceId` or `accountId` column, or a
route path contains a tenant segment such as `/orgs/:orgId/...`.

**Fails:**
`(example omitted)`

**Why:** The query is scoped by `orgId`, but the caller picks it — any authenticated user swaps the path id and reads another customer's projects.

**Fix:** Resolve the tenant to the session user's membership before querying, and pass the resolved
tenant id to the query rather than the path value. Records with a direct per-user owner are Gate 12;
this gate is for collections whose only boundary is the tenant column.

## Out of scope

- **Which role should hold which permission.** Whether a "manager" may issue refunds is domain
  knowledge, not a default mistake — Airtight checks that a check exists, not that the policy is
  right.
- **Sequential or guessable identifiers.** An incrementing id is not the defect and a UUID is not the
  fix; the fix is Gate 12. Unguessable ids are obscurity, and they are not gated here.
- **Session integrity, token signing and fixation.** If the session says the wrong user, every gate
  in this range enforces the wrong answer correctly — that belongs to the credentials range, gates
  1-9.
- **CSRF.** Defence in depth around the authorization decision rather than the decision itself, and
  the frameworks a model reaches for ship the token plumbing; no gate.
- **Audit logging of a privileged action.** A record of who granted a role is Gate 103 in
  `logging.md`, which covers the admin and impersonation routes this range gates. The check and the
  record are separate failures — a handler missing both fails Gate 11 and Gate 103, and an audit
  cites both.
- **Rate limits on enumeration.** How many ids a caller may walk is Gate 120's territory only where
  the route verifies a credential; on an ordinary object route it is ungated. Gate 12 is what makes
  walking ids return nothing worth having.
- **Database row-level security, policy engines and ABAC frameworks.** Sound architecture, not a
  default AI mistake — their absence is not a gate failure.
- **Whether a record should exist at all, or who created it.** Business logic outside the registry.

## Prove probes

- Gate 10 — as fixture user A, `GET` a collection endpoint with the identity param set to fixture
  user B (`?userId=<B>`) -> HELD if the response is A's own rows or 403, FAILED if it returns B's
  rows.
- Gate 11 — as a non-admin fixture user, `GET` the admin route -> HELD if 403 or 404 with no body,
  FAILED if 200 with data. A 401 means the session was not accepted; that is UNKNOWN, not HELD.
- Gate 12 — as fixture user A, `GET` a record id owned by fixture user B -> HELD if 404 or 403 with
  no body, FAILED if 200 with B's record. Do not then write to anything reached.
- Gate 13 — not provable read-only; demonstrating it requires a write. Reason from code.
- Gate 15 — as a member of org A only, `GET` a tenant-scoped collection under org B's id -> HELD if
  404 or 403, FAILED if 200 with org B's rows.
