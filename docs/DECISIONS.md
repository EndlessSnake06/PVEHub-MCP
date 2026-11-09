# Decisions

Each decision is binding until superseded. Format: context → decision → consequences.

## D001 — Clean rebuild, no fork

**Context:** The target repository `admin/PVEHub-MCP` starts empty (initial commit only).
Candidate projects were audited; the two closest functional matches (`ahmetem/homelab-proxmox-mcp`,
`ahmetem/homelab-pbs-mcp`) are GPL-3.0. A fork would force GPL-3.0 on the whole project and
carry a large amount of code we do not need.

**Decision:** Build a new, MIT-licensed codebase from scratch, using the audited projects as
conceptual references only. The API schema is taken from the live Proxmox servers, not from
third-party code. No source code is copied, so `THIRD_PARTY.md` records inspiration only.

**Consequences:** More work in Phase 1–5, but a clean license position, a small dependency
surface and full control over the module layout. GPL projects are read-only references.

## D002 — License: MIT

**Context:** The repository already contains an MIT license text (copyright `admin`, 2026).

**Decision:** Keep MIT. All dependencies are permissive (MIT/BSD/Apache-2.0). No GPL code is
included.

## D003 — MCP SDK 2.x (`MCPServer`, not legacy `FastMCP`)

**Context:** The official Python SDK is at 2.3.0. In 2.x the `mcp.server.fastmcp.FastMCP`
class was renamed to `mcp.server.mcpserver.MCPServer`; the old import raises an explicit
migration error.

**Decision:** Use the current `MCPServer` API. It provides the same decorator model,
Streamable HTTP (`streamable_http_app`) and stdio (`run_stdio_async`), plus lifespan hooks
needed for capability discovery.

**Consequences:** Documentation and examples use `MCPServer`. Pinning `<3` protects against
another major rename.

## D004 — HTTP encoding: form data for writes, query for reads

**Context:** The official PVE API documentation states that parameters are passed via URL and
`x-www-form-urlencoded` for PUT/POST. JSON bodies are not documented.

**Decision:** `GET`/`DELETE` use query parameters; `POST`/`PUT` use
`application/x-www-form-urlencoded`. Lists are encoded as repeated keys; booleans as `1`/`0`;
nested objects as compact JSON strings. PBS uses the same encoding and `/api2/extjs` as the
default API prefix (PVE: `/api2/json`).

**Consequences:** Compatible with `pvesh`/`proxmoxer` behaviour. Generic API callers must
pass scalars or lists; dict values are JSON-encoded and documented as such.

## D005 — asyncssh instead of paramiko

**Context:** The stack is fully async (`httpx`, MCP server). paramiko is synchronous and would
need thread offloading; asyncssh provides native async connections, host-key verification,
known_hosts handling and SFTP.

**Decision:** Use `asyncssh`.

## D006 — Tool results are compact JSON strings

**Context:** MCP clients pay for every token; verbose prose and emoji are noise. Structured
output is useful for machines but hard to bound.

**Decision:** Every tool returns a JSON string, either `{"ok":true,"data":...}` or
`{"ok":false,"error":{...}}`. Lists are summarized (selected fields) and hard-truncated at
`PVEHUB_MAX_OUTPUT_BYTES`. No emoji, no decorative text.

## D007 — Static registration + per-call enforcement

**Context:** MCP tool lists are read at session start. Rebuilding the registry at runtime
would confuse connected clients.

**Decision:** Policy and capabilities are evaluated once at startup to decide which tools are
registered. Every call re-checks policy and the concrete token privilege. Periodic capability
refresh updates the `pvehub_capabilities` report and per-call decisions; it does not
add/remove tools. Restart to change the visible tool set.

## D008 — Capability discovery failure: fail open by default

**Context:** If `/access/permissions` fails (network glitch, older PBS), hiding every tool
makes the server useless; ignoring permissions violates the rights-aware goal.

**Decision:** `capabilities.fail_open: true` by default. Tools are registered, each call still
hits the API and maps 403 to a clear error; `pvehub_capabilities` and `/health` show the
discovery error. Operators who want strict behaviour set `PVEHUB_CAPABILITIES_FAIL_OPEN=false`.

## D009 — Host shell and PBS shell are opt-in

**Context:** Host-level shell is the highest-risk capability.

**Decision:** `exec.host` and `exec.pbs_host` default to `false`. LXC and VM exec default to
`true` but still require `confirm=true`, allowed VMIDs and (for LXC) SSH configuration.
`exec.allowed_vmids` defaults to `100-199`; operators must widen it explicitly.

## D010 — Docker build not executed in the development sandbox

**Context:** The development sandbox has no Docker/Podman daemon. Building or running the
image here is impossible.

**Decision:** Ship a multi-stage Dockerfile, compose file and a Gitea Actions workflow that
builds the image. Locally verify Python packaging, server startup, stdio and HTTP transport.
Document the unverified Docker build in `docs/STATUS.md`; do not claim it was tested.

## D011 — Documentation language: English

**Context:** The project is an MCP server intended for reuse; MCP terminology and the
upstream ecosystem are English. The operator communicates in German.

**Decision:** Code, README and docs are English. Decisions and safety warnings in chat remain
German.

## D012 — Named instances, `instance` parameter

**Context:** Multiple PVE clusters or PBS servers must be usable from one server.

**Decision:** Config supports lists of named PVE and PBS instances. Every tool accepts an
optional `instance` argument; when omitted, the first configured instance of that type is
used. Unknown names produce an error listing valid names.

## D013 — TLS: verify by default; fingerprint pinning per connection

**Context:** Self-signed Proxmox certificates are common in homelabs; silently disabling
verification is unacceptable.

**Decision:** `verify=true` by default. Operators can supply a CA bundle or a SHA-256
certificate fingerprint. Fingerprint pinning uses a custom `ssl.SSLContext` that checks the
peer certificate on every TLS handshake. `verify=false` requires an explicit opt-in and logs
a warning at startup.

## D014 — Audit: metadata by default, results opt-in

**Context:** Audit logs are useful, but command output and API bodies may contain secrets.

**Decision:** Log timestamp, tool, instance, target, redacted parameters, status, duration and
output size. Do not log result bodies unless `PVEHUB_AUDIT_INCLUDE_RESULTS=true`. Arguments
whose key looks secret (`token`, `secret`, `password`, `key`, `authorization`, `cookie`) are
replaced with `***`; token-like string patterns and private-key blocks are redacted anywhere.

## D015 — Conservative generic API defaults

**Context:** The generic API bridge can reach every endpoint, including access control and
console tickets.

**Decision:** Default `generic_api.deny_paths` covers ticket/shell/console endpoints
(`/access/ticket`, `/access/users/*/token*`, `/nodes/*/vncshell`, `/nodes/*/spiceshell`,
`/nodes/*/termproxy`) and default `deny_methods` includes `DELETE`. The `admin.yaml` example
opens DELETE explicitly; sensitive paths stay denied unless the operator removes them.

## D016 — Test strategy: mocks, schemas verified live

**Context:** No PVE/PBS API tokens or SSH keys were provided for this build. The API
documentation endpoints are publicly readable and were fetched from the live test servers;
the API itself requires authentication.

**Decision:** Unit and contract tests run against `respx`/in-memory fakes. The exact paths,
parameters and auth header formats are verified against the live `apidoc.js` files and the
official PVE API wiki. Integration tests are marked `integration` and skipped unless
credentials are present. `docs/STATUS.md` states exactly what was mocked.

## D017 — No automatic tool reload on policy change

**Context:** Hot-reloading policy could expose or hide tools mid-session and is hard to audit.

**Decision:** Policy is read at startup. Changes require a restart. `pvehub_capabilities`
reports the policy file path and a hash so operators can verify what is active.

## D018 — MCP endpoint: authentication is default-deny (issue #16)

**Context:** The server carries full PVE/PBS control rights plus SSH access to the PVE
hosts. In 0.1.0 the bearer token was optional: a loopback bind started without any
caller authentication, so every local process or container in the LXC (e.g. a
compromised service with `network_mode: host`) could drive the full control plane,
including destructive tools. Fail-open at the endpoint that holds the highest rights in
the homelab.

**Decision:** The http transport requires `PVEHUB_MCP_AUTH_TOKEN` and refuses to start
without it, for any bind address. `PVEHUB_MCP_AUTH_REQUIRED=false` is an explicit,
logged opt-out for loopback development setups only; a non-loopback bind without a token
is rejected even with the opt-out (the pre-existing hard rule stays). `stdio` is
unaffected (no listener). `/health` remains unauthenticated (liveness for orchestrators;
it exposes no control data). Per-client attribution (named tokens, `client` field in the
audit log) and OAuth2 client-credentials against Pocket ID are out of scope for this
fix and tracked as follow-up work in issue #16.

## D019 — Per-client audit attribution: named MCP tokens (issue #21)

**Context:** 0.1.0 had a single `PVEHUB_MCP_AUTH_TOKEN` for the whole http transport.
Two operational problems: (a) rotating that token (leak, staff change, routine) logged
out *every* client at once — there is no per-client revocation; (b) the audit log
(its whole purpose per D014 is "who ran what") could not attribute a tool call to a
client: every entry said "someone". For a box whose token can run `exec_host`,
post-incident "which client" is the first question, and it was unanswerable.

**Decision:** `PVEHUB_MCP_AUTH_TOKENS` (env) / `mcp_auth_tokens` (YAML) maps
*client name* -> *bearer token* (`name:token,name2:token2` in env). The legacy token
remains and is exposed to the middleware under the reserved name `default`, so existing
deployments keep working. Rules: names are 1-32 chars of `[a-z0-9_-]` (letter or digit
first), `default` is reserved, every token is >= 16 chars, and a named token must not
equal the legacy token (one secret, two identities = ambiguous attribution). Config
validation enforces all of this at startup; the http transport requires *at least one*
of legacy/named tokens unless `PVEHUB_MCP_AUTH_REQUIRED=false` on loopback.

The middleware compares the presented bearer against **all** known tokens
(`secrets.compare_digest` per candidate) and, on success, stores the resolved name in a
`ContextVar` for the duration of the request. The tool wrapper (the single choke point
through which every tool call passes, D014) reads it and writes `client` into every
audit entry — including denials and errors, which is where attribution matters most.
The MCP SDK runs tool calls in a child task; contextvars propagate to it, so the
attribution survives that hop (covered by `tests/test_attribution.py`). stdio and
unauthenticated loopback setups attribute to `unknown` — the field is always present,
so log consumers can rely on the schema.

**Consequences:** Per-client revocation is a config reload, not a global outage; audit
entries are attributable; a leaked token compromises exactly one client. The reserved
`default` name and the "one token = one identity" rule keep attribution unambiguous.
OAuth2 client-credentials against Pocket ID remains the longer-term path (issue #16
follow-up) and would slot into the same `client` field.

## D020 — Audit log tail: `pvehub_audit_tail` + `read_audit_tail` (issue #20)

**Context:** The audit log is the server's only "what happened" record, but reading it
required shell access to the container (`docker exec ... tail /data/audit.jsonl`).
That (a) bypasses MCP as the single control plane, (b) hands the reader unredacted
bytes — the redaction is applied on the *write* path (D014), and a direct read of the
file re-exposes anything a redaction rule misses, and (c) gives no way to filter by
tool/status/client without grep pipelines on the host.

**Decision:** `read_audit_tail(path, max_lines, ...)` in `pvehub_mcp/audit.py` reads the
last N entries *in file order* by scanning backward from the end of the file in
64 KiB chunks, bounded by an 8 MiB `window_bytes` cap — a 10 MiB log never enters
memory. Malformed lines are skipped, never raised (the reader must not take the audit
down). Every returned entry passes through `redact_value` **again** on the way out:
redaction is write-time *and* read-time, so no code path can emit an unredacted entry.
The `pvehub_audit_tail` tool (category `read`, D014) wraps it with `limit` (1..500),
`tool`, `category`, `status`, `client` (D019) and `since` (ISO-8601) filters applied
in memory after the capped read. `limit` is clamped, not truncated; an invalid value
is a structured `invalid_argument`, not a traceback.

The audit *state* itself is also observable in-band: `pvehub_capabilities` (an
authenticated, audited tool — the right place) reports `enabled`, `path`,
`size_bytes`, `max_bytes`, `keep` and the **last write error** (D023). A silently
stopped audit (full volume, lost permissions) is now visible from the control plane
instead of only in the container log. `pvehub_health` reports `enabled`/`path` only —
the health endpoints (D021) deliberately stay minimal.

**Consequences:** Audit inspection is an MCP call with the same authentication as
everything else, is redacted, and is bounded in memory. The 8 MiB window is a
*read* cap: with `limit=500` and large entries it can still return fewer than 500
entries if the window is exhausted — the response is honest about what it returned, it
just does not pretend to have the whole tail. `since`/`client` filters operate on the
window, not the whole file (documented in the tool docstring).

## D021 — Health: liveness (`/health`, minimal) vs readiness (`/ready`, authenticated) (issues #23, #24)

**Context:** In 0.1.0, `GET /health` answered 200 with the full health body (`status`,
`version`, `transport`, tool count) — unauthenticated. Two problems: (a) the status code
was always 200, so Docker/compose healthchecks and external monitors never saw a
`degraded` backend (bad or revoked PVE/PBS token); (b) the unauthenticated endpoint
leaked the exact version (CVE matching against a server whose token can run `exec_host`
and `guest_delete`), the tool count (policy shape) and the degraded signal to any LAN
client. The security review (F-13) had accepted the leak as low value; with
`PVEHUB_CAPABILITIES_FAIL_OPEN=true` (the default) the degraded state is exactly when
that information is most useful to an attacker.

**Decision:** Split the concerns. `GET /health` is liveness: `{"status": "ok"}`, always
200 while the process runs, no version or tool count, unauthenticated (Docker healthchecks
and external liveness monitors need it without credentials; the port stays LAN-only per
the README). `GET /ready` is readiness: the full `hub.health()` body (the same method
that feeds the authenticated `pvehub_health` MCP tool — unchanged), HTTP 200 while
`status == "ok"`, 503 otherwise. The bearer middleware protects `/ready` via an
exact-path list next to the `/mcp` prefix; the single-token comparison is unchanged.
In loopback development mode without a token the middleware is not installed, so `/ready`
is open there; non-loopback binds without a token are already refused by config
validation. The Dockerfile and docker-compose healthchecks probe `/ready` with the bearer
from the container environment, so a dead or degraded backend turns the container
`unhealthy`. The CI compose smoke asserts `/health` 200, `/ready` with bearer in
(200, 503) — 503 is the expected steady state in CI, where the PVE/PBS URLs are
unreachable placeholders — and `/ready` without bearer 401.

**Consequences:** Operators who parsed `/health` for version or tool count must use
`/ready` (authenticated) or the `pvehub_health` tool. External readiness monitors must
use `/ready` with the token; pure process-liveness monitors may use `/health`. stdio
deployments remain `unhealthy` (no HTTP listener) — expected and documented. This
supersedes the `/health` remark in D018 and resolves F-13 of the security review (see
the 0.1.1 addendum in `docs/SECURITY_REVIEW.md`).

## D022 — Tool labeling: readable titles (derived, overridable), confirm requirement in description, category in _meta

**Context:** `PVEHub._register` set `ToolAnnotations(title=name)`, so `tools/list`
exposed the snake_case technical name as the display title, and no client-visible
annotation existed for the `confirm=true` requirement of categories in
`safety.require_confirm_for`. Agents that only consumed `tools/list` (schema plus
annotations) produced avoidable `confirm required` denials, and the category was
only indirectly recoverable from three boolean hints (issue #22).

**Decision:** Every registered tool now carries a readable `title` in `title` and
`annotations.title`, plus `_meta` = `{"category": <category>, "confirm_required":
<bool>}`. The title is derived from the name by `pvehub_mcp.toolnaming.derive_title`
(a pure, stdlib-only module: acronym map PVE/PBS/LXC/VM/..., the `pvehub_` brand
prefix mapped to the single word `PVEHub`, title-casing of all other words); the
derived title is the default and `hub.tool(..., title="...")` is the documented
override point. No per-tool hand-written titles ship in this release. The confirm
requirement is appended to the tool description as a stable, greppable note
(`This tool is protected: the call is rejected unless confirm=true is passed.`,
plus a `dry_run` mention where the tool's signature supports it), computed from the
effective policy at registration. The category/confirm flag travel in `_meta`
rather than new annotation fields because `ToolAnnotations` is a fixed MCP schema
and `meta`/`_meta` is the spec's extension channel for exactly this.
`scripts/generate_tool_docs.py` mirrors the derivation and the note (static AST scan,
it cannot import the server; the mirrored constants are kept in sync deliberately)
and `docs/TOOLS.md` gained a `Title` column plus the note for the default confirm
categories. The `RegisteredTool` record gained `title` and `confirm_required`;
existing consumers (capabilities report, tests) read only `name`/`category`/
`pve_privileges` and are unaffected.

## D023 — Audit completeness: rotation, write-error surfacing, full target/error records (issues #18, #19)

**Context:** 0.1.0 audit entries were incomplete and the log was unmanaged. (a) The
`target` field captured a *single* key (the first of `vmid`/`node`/... present) as a
`key=value` string: a call that addressed both a node and a VM (the common case —
`/nodes/<node>/qemu/<vmid>`) lost half its targeting. (b) A forced denial or a tool
error left only the status string; *why* it was denied (policy rule, confirm gate,
permission) was not in the log, so the log could not answer "was this a misconfiguration
or an attack". (c) `output_bytes` was missing, so the size of what a call *would* have
returned (or did, with `PVEHUB_AUDIT_INCLUDE_RESULTS`) was unknown. (d) The JSONL file
grew without bound: a busy box fills the LXC volume, and an audit that stops because
the disk is full is exactly when you want it. (e) A write failure (permission lost,
volume full) was dropped on the floor — the audit could die silently (D014's premise is
that the log is trustworthy, which it is not if it can stop quietly).

**Decision:**

* **`target` collects *all* present target keys** (D012 named instances make
  `node`/`vmid`/`store`/`path`/... all meaningful). A single key keeps the legacy
  `key=value` *string* so existing log consumers (jq pipelines, alerting) keep working
  unchanged; **two or more keys are a `{key: "key=value"}` dict** — the first breaking
  change in the schema, flagged in the changelog. Every value passes the same
  `redact_value` as everything else (a `command=` value is masked wholesale).
* **Denials and errors carry `error: {code, message}`** — the typed error's own code
  (`policy_denied`, `confirm_required`, `invalid_argument`, `permission_denied`, ...)
  and message, so the log distinguishes "blocked by policy X" from "caller forgot
  confirm" from "no permission for Y" without leaving the log.
* **`output_bytes`** records the size of the (redacted, shrunk) response that was
  actually returned, on every status including `error` (where it is `0`/`null` as
  appropriate).
* **Size-based rotation** (`PVEHUB_AUDIT_MAX_BYTES`, default 10 MiB;
  `PVEHUB_AUDIT_KEEP`, default 5): before each write the *active* file is checked;
  over the cap, `audit.jsonl` -> `.1`, `.1` -> `.2`, ... and the oldest archive is
  dropped to hold `keep` files. Rotation is the writer's job, single-writer by
  construction (one process, one file), so there is no rename race. Archives keep
  `0600`.
* **Write failures are recorded, not dropped.** `AuditLogger.error` holds the last
  failure (type + message) and is surfaced in the `pvehub_capabilities` report (D020),
  so "the audit stopped and here is why" is one MCP call away. The logger keeps
  trying (a transient full-volume error clears itself); a *missing* file (never
  created) is `enabled=false`, reported the same way.

**Consequences:** The log answers "what, where, to what, by whom (D019), with what
result size, and why not" for every call, including the ones that did nothing.
`target` schema: consumers that pattern-matched the string form still work for
single-key calls; multi-key calls need the dict (changelog, `docs/TOOLS.md`). Rotation
is size-based and local (no external tooling); `keep` bounds total audit storage to
`keep * max_bytes`. The `pvehub_audit_tail` reader (D020) reads the *active* file only;
archived entries are out of its scope by design (they are for the operator, not the
control plane).

## D024 — Trusted proxy and client-IP audit attribution (issue #25)

**Context:** The audit log records *who* ran a call (D019's `client`) but not
*where it came from*. Behind a reverse proxy (Caddy/Traefik/nginx — the normal
deployment for a server whose token can run `exec_host`) `request.client` is
the proxy, and `X-Forwarded-For` is the only source of the real client
address. But that header is untrusted input: a direct client — or any attacker
who can reach the port — can forge arbitrary entries. Consulting `X-Forwarded-For`
without a trust model is not attribution, it is a forgery target. Separately,
a deployment behind a proxy should be able to say "direct access from any
other network is rejected" — not merely misattribute it.

**Decision:** A new, dependency-free module `pvehub_mcp/proxy.py` (no SDK or
network imports, unit-testable) implements the trust decision explicitly:

* `trusted_proxies` (`PVEHUB_TRUSTED_PROXIES`, comma-separated CIDRs; a bare
  IP is a /32 or /128) names the trusted reverse proxies. Malformed entries
  fail **at startup** (`TrustedProxyError` surfaced through config validation):
  a misconfigured trust set is a security bug, not a default to fall back on.
* The direct TCP peer must be inside the set before any forwarded header is
  consulted. An untrusted peer (or no trust set at all) is attributed to the
  peer itself — a forged header cannot change that, and the default
  configuration (empty set) behaves exactly as before: `X-Forwarded-For` is
  never read.
* For a trusted peer the chain is read **right to left**: the rightmost entry
  that is *not* in the trusted set is the client. Rationale: a hop can only
  append to the *right* of its own position, so the entry a trusted hop saw on
  the wire (the first untrusted entry from the right) is that hop's real
  address, not a forged one. If every entry is trusted (an internal client
  behind an internal proxy), the leftmost entry is the client; malformed
  entries are dropped (they can be neither a trusted hop nor a client); no
  usable chain falls back to the peer (e.g. a proxy that strips the header).
* `require_trusted_proxy` (`PVEHUB_REQUIRE_TRUSTED_PROXY`, default `false`,
  validated to require a non-empty trust set) adds a 403 gate: a
  `TrustedProxyMiddleware` is installed as the **outermost** layer — after
  the bearer middleware, so an untrusted peer gets `403 proxy_required`
  *before* any `401` — protecting `/mcp` and `/ready`. `GET /health` stays
  exempt: the container healthcheck probes it from the bridge network and a
  failed healthcheck is a liveness incident, not a security one (D021). A
  scope without a socket peer is 403 as well — an unverifiable peer is not
  passable.
* `uvicorn` runs with `proxy_headers=False`: forwarded-header handling is
  explicit in the server (gate + resolver above), not delegated to the
  framework's proxy-header layer, so the behaviour is testable and documented
  in one place.

The resolved address is written as `client_ip` into **every** audit entry
(`audit.py`), including denials and errors: always present, `unknown` when
unresolvable — the same contract as `client` (D019). The `pvehub_capabilities`
report and `pvehub_audit_tail` carry the field unchanged by the existing
redaction (plain addresses are not masked by the redaction rules, which target
secrets, not locations).

**Verification:** `tests/test_trusted_proxy.py` covers the forgery table
(10 cases: no trust set, forged chain from an untrusted peer, single- and
multi-hop chains, all-trusted chain, malformed entries, IPv6, missing peer),
config validation (malformed entry, `require` without a set, env mapping), the
403 middleware at ASGI level (untrusted peer, missing peer, `/ready`
protected, `/health` exempt, no-op default) — and **end to end through a real
uvicorn server** (`proxy_headers=False`, full MCP session via the streamable
HTTP client behind a "local reverse proxy", `127.0.0.1/32` trusted): the audit
entries assert the resolved client address, and a default-configuration run
asserts that a forged `X-Forwarded-For` is ignored (socket peer logged).

**Consequences:** The audit answers "what, by whom (D019), **from where**" for
every call, including the ones that were denied — post-incident "which network
did this come from" is answerable without leaving the log. Forgery resistance
comes from the trust decision, not from the header: the socket peer is always
verifiable, the forwarded header only ever is. The trust set is a
security-critical config: a too-broad set (e.g. `0.0.0.0/0`) re-opens the
forgery window, which is documented and why strict startup validation exists.
`require_trusted_proxy` is an operational choice, off by default, so
proxy-less deployments and every existing configuration are unaffected; a
403-only deployment behind the homelab proxy sets both variables in one
`config.yaml` edit.

## D025 — Memory layer: SQLite notes + metadata events, split policy categories (issues #31-#39)

**Context:** The server is stateless between sessions, so every client rediscovered the
same facts (maintenance windows, conventions, "this guest has no agent installed") and
the action history existed only in the audit log, which is a *security* record: it is
append-only by rotation, not queryable per subject, and holds redacted arguments rather
than a usable index. A memory layer had to answer "what do I know about guest 100, and
what happened to it last" without becoming a second, weaker audit log and without
turning untrusted text into instructions.

**Decision:**

* **One SQLite file** (`memory_db`, default `<state_dir>/memory.db`), standard-library
  `sqlite3`, WAL, `busy_timeout`, FTS5 with an automatic `LIKE` fallback. No new
  service, no new dependency; `PRAGMA user_version` carries the schema version and
  migrations run idempotently at startup. All access goes through one connection behind
  an `asyncio.Lock` and `asyncio.to_thread`, so the event loop never blocks on disk.
* **Two tables with different trust levels.** `notes` holds client-written free text
  (redacted before write and again on read). `events` holds **metadata only** per
  mutating call: tool, category, status, instance, client, duration, error code, a
  static summary built from arguments, and one row per subject. Guest output never
  enters the table; for `exec` the command is reduced to `command_sha256` (16 hex) and
  `command_length`. Live state has no schema slot at all.
* **Two policy categories instead of one**: `memory` (recall, resource, prompt) and
  `memory_write` (remember, forget). `read_only: true` allows exactly `read`, `generic`,
  `memory`; a profile can therefore keep recall and enrichment while refusing writes,
  and `categories.deny: [memory]` remains a valid way to hide the feature entirely.
  Blocked memory tools are unregistered and listed under `tools.blocked` with the
  reason — same contract as every other tool.
* **Enrichment is opt-in per call, not a second tool.** A successful result whose
  arguments name a subject (vmid, node, datastore, path) gets a `_memory` block with
  `trust: "untrusted-data"`, capped by `memory_enrich_max_bytes` and by a quarter of
  `max_output_bytes`. It never runs on errors, never on `memory_*` tools, and any
  failure returns the original response unchanged (fail-open). The cap exists so a
  memory block can never push `data` out of the output budget.
* **Retention is a cleanup job, not a TTL daemon**: TTL per note (`expires_in_days`),
  soft delete with a tombstone window, then purge; global retention in days, an event
  retention window and a hard `memory_max_notes` cap. Runs at startup and then
  periodically (`memory_cleanup_interval_seconds`, `0` disables); every run is reported
  in `pvehub_capabilities` including failures.
* **A disabled store is a reported state, not a crash.** An unwritable path (read-only
  rootfs, unmounted volume, wrong owner) leaves `memory.enabled=false` + `memory.error`
  in the capabilities report and blocks the memory tools with that reason.
* **MCP resource `memory://notes` and prompt `memory_briefing`** are read-only views:
  the resource returns data with the trust marker, the prompt contains instructions for
  the client but never note content. Both vanish when the category or the store is
  disabled (issue #37, no SDK hack required).

**Consequences:** Clients keep a durable, queryable context per subject; operators get a
per-subject action history that is *not* the audit log and cannot be mistaken for one,
because it contains no payloads. The database is a second state file next to
`audit.jsonl`, so backups must include both (and `memory.db` must be copied with the
SQLite backup API, not a bare `cp` while WAL is active). Free-text notes remain the one
place where untrusted input is stored; every consumer is told, in-band, that `_memory`
is data. Migrations are additive (`user_version`), so an upgrade keeps existing notes
and an old `policy.yaml` without the new categories keeps loading unchanged.

## D026 — Bearer pass-through: the MCP bearer *is* the PVE API token (issue #30)

**Context:** In the default ("static") mode the server authenticates MCP clients with
named tokens (D019) and then calls PVE with a single *configured* service token. Three
problems follow: (1) every action in PVE and in the audit is attributed to the service
account, not to the human who issued the request, so the per-client audit attribution of
D019 stops at the MCP boundary; (2) the operator must provision a powerful service
token for the server to do anything, which is exactly the standing privilege a
compromised server would inherit; (3) issue #7 left PBS in passthrough undecidable,
because a PVE API token and a PBS credential are different things and the single
configured token conflated them.

**Decision:** Add an opt-in `mcp_auth_mode: "passthrough"`. In this mode the MCP bearer
is not a server token at all — it is the *requesting client's own PVE API token*, and
the server uses it as the credential for every PVE call of that request.

* **The bearer is a PVE API token, structurally.** `parse_pve_bearer` accepts only
  `Bearer <user@realm!tokenid>=<secret>` (a realm `@`, the PVE token separator `!`, no
  whitespace, a secret of at least 16 characters). Anything else — a missing header, a
  plain MCP service token, a typo — is rejected **at the edge** with a `401` by the
  `PassthroughBearerMiddleware`, which *replaces* the named-token `BearerAuthMiddleware`
  for `/mcp` and `/ready`. There is no named client to resolve, so the audit's
  `client` stays `"unknown"`; the request's identity is carried in a new `pve_token`
  audit field that records the token *identity only* (`user@realm!tokenid`), never the
  secret.
* **Config is fail-loud.** `mcp_auth_mode="passthrough"` requires at least one PVE
  instance (there is nothing to validate the token against otherwise), the `http`
  transport (the token rides an HTTP header that does not exist on stdio),
  `mcp_auth_required=true` (the token is the credential, so an unauthenticated `/mcp`
  would defeat the contract), and `mcp_token_validation_ttl >= 1`. It *exempts* the
  "an MCP bearer is required for http" rule, because the PVE token is that credential.
* **Validation is one round-trip, cached per (instance, full token identity).** On the
  first use of a token the server calls `GET /access/permissions` *with that token*. A
  `401` means PVE rejected it: the call fails with a clear `AuthenticationError` and
  **no** fallback to the configured token. A `403` means the token authenticated (PVE
  authenticates before it ACLs) but lacks `Sys.Audit`: the identity is trusted, the
  per-token snapshot records the discovery failure, and PVE keeps enforcing every call
  per call. A `200` yields the per-token permission snapshot. Results are cached in a
  bounded, TTL-based `TokenValidationCache` keyed by the *full* token identity
  (user, realm, token-id, **and** secret), so a rotated secret is a new key
  (re-validated immediately) and two clients with different tokens never share a
  validated state or a permission snapshot. The cache owns the clock and the eviction
  returns evicted entries so their HTTP clients are closed.
* **The per-request client is scoped, never the configured one.** The wrapper
  resolves the bearer (from the request context when the SDK runs the call in the
  middleware's task, otherwise by re-parsing the raw `Authorization` header — the only
  channel that always reaches the tool), validates it, and stores the resulting
  `TokenState` in a request-local `pve_scoped_context`. `PVEHub.pve()` hands out
  *that* client, whose `Authorization` header carries the request's token, and is
  **fail-closed**: with no validated token for the requested instance it raises
  `AuthenticationError` rather than falling back to the configured service token.
  `PVEHub.pbs()` raises `AuthenticationError` in passthrough mode, because a PVE API
  token is not a PBS credential.
* **PBS is out of scope for passthrough (closes issue #7).** A PVE API token is not
  valid on the PBS API, and the only credential a passthrough request carries is a PVE
  token. So *no* PBS tool is registered in passthrough mode: each is blocked at
  registration with the reason `passthrough: PVE API tokens are not valid on the PBS
  API (run in static mode for PBS access)`, reported like any other block under
  `tools.blocked`. Static mode is unchanged and remains the only way to reach PBS.
* **The call-time per-token gate is the security boundary.** In passthrough mode the
  request's token is unknown at registration time, so tool *visibility* is no longer
  permission-filtered (it cannot be, against a credential that is not the configured
  one). Visibility is therefore not gated at registration; the per-call
  `check_pve_token_snapshot` gate runs against the token's own snapshot (fail-open /
  fail-closed per the `capabilities_fail_open` policy), and PVE enforces every call
  with the request's own ACL regardless.
* **The mode is visible.** `pvehub_capabilities` reports an `auth` block
  (`mode`, `required`, and `token_validation_ttl` in passthrough) so an operator can
  see how the endpoint authenticates.

**Consequences:** PVE- and audit-side attribution now reach the requesting client's own
identity end to end; the server holds no standing PVE privilege of its own in
passthrough mode — a compromised server can do exactly what the *current request's*
token allows, and nothing more. The cost is that every distinct PVE token is validated
once (cached, bounded, TTL) and that PBS is unavailable in this mode (a deliberate
trade, documented here as the resolution of issue #7). Static mode is byte-for-byte
unchanged and remains the default; passthrough is strictly opt-in and config-validated,
so an existing deployment is unaffected by upgrading. The `pve_token` audit field adds
one more identity to the redacted entry; the secret is never written, and the existing
`pvehub_audit_tail` redaction applies to it.
