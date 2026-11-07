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
