# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog;
versioning: Semantic Versioning.

## [0.1.3] — 2026-11-09

### Added

- **Bearer pass-through: the MCP bearer *is* the PVE API token (D026, issue #30).**
  A new opt-in `mcp_auth_mode: "passthrough"` (`PVEHUB_MCP_AUTH_MODE`) makes the
  `Authorization: Bearer` value the requesting client's **own PVE API token**, used as
  the credential for every PVE call of that request. The configured PVE service token is
  **not** used in this mode (fail-closed).
  - Structural validation at the edge: `PassthroughBearerMiddleware` replaces the
    named-token middleware for `/mcp` and `/ready` and rejects any bearer that is not a
    well-formed PVE API token (`user@realm!tokenid=<secret>`, secret ≥ 16 chars) with a
    `401`.
  - Per-request, per-instance validation against `GET /access/permissions`, cached in a
    bounded TTL `TokenValidationCache` keyed by the **full** token identity (user,
    realm, token-id **and** secret), so a rotated secret re-validates immediately and
    two clients never share a validated state or a permission snapshot. A `401` fails
    the call with a clear `AuthenticationError` (no fallback to the configured token);
    a `403` (valid but lacking `Sys.Audit`) is trusted and recorded as a discovery
    failure — PVE enforces every call per call.
  - The per-request client is scoped via a request-local context channel;
    `PVEHub.pve()` hands out the per-request client and is fail-closed (raises
    `AuthenticationError` with no validated token instead of falling back to the
    configured service token). `PVEHub.pbs()` raises `AuthenticationError` in
    passthrough mode.
  - Per-token capability gate at call time (`check_pve_token_snapshot`) — the request's
    token is unknown at registration, so visibility is no longer permission-filtered;
    the call-time gate and PVE's own ACL are the security boundary.
  - A new `pve_token` field in the audit log records the token **identity**
    (`user@realm!tokenid`) — never the secret; `client` stays `unknown` in this mode.
    The existing secret-redaction applies.
  - `pvehub_capabilities` reports an `auth` block (`mode`, `required`, and
    `token_validation_ttl` in passthrough) so the mode is visible.
  - New settings (all optional, defaults in `docs/CONFIGURATION.md`):
    `mcp_auth_mode` (`PVEHUB_MCP_AUTH_MODE`) and `mcp_token_validation_ttl`
    (`PVEHUB_MCP_TOKEN_VALIDATION_TTL`, default `60`, minimum `1`).

### Changed

- **PBS is not available in passthrough mode (closes issue #7).** A PVE API token is
  not a valid PBS credential, so no PBS tool is registered in passthrough mode: each is
  blocked at registration with the reason
  `passthrough: PVE API tokens are not valid on the PBS API (run in static mode for PBS
  access)`, reported under `tools.blocked`. Static mode is unchanged and remains the
  only way to reach PBS.
- Tool registration in passthrough mode no longer permission-filters PVE tool visibility
  (the per-token gate moved to call time). Static mode is unaffected.

### Notes

- Static mode (the default) is byte-for-byte unchanged; passthrough is strictly opt-in
  and config-validated (requires a PVE instance, `transport: http`,
  `mcp_auth_required: true`, `mcp_token_validation_ttl >= 1`), so an existing
  deployment is unaffected by upgrading. See `docs/DECISIONS.md` D026.

## [0.1.2] — 2026-11-09

### Added

- **Memory layer (D025, issues #31-#39).** A SQLite store next to the audit log
  (`memory_db`, default `<state_dir>/memory.db`, WAL, FTS5 with a `LIKE` fallback)
  with three tools:
  - `memory_recall` — full-text search over notes, filters `entity_type`,
    `entity_key`, `since`, optional last events for the subject;
  - `memory_remember` — store a note for `guest`, `node`, `datastore`, `cluster`,
    `convention` or `runbook`, with `title`, `tags`, `expires_in_days`; the body is
    redacted before it is written, `source` is the client name (D019);
  - `memory_forget` — tombstone a note, **requires `confirm=true`**.
  Tool count: 75 -> 78.
- `_memory` enrichment on successful tool results (issue #35): notes and the last
  recorded action for the call's subject, marked `trust: "untrusted-data"`, capped by
  `memory_enrich_max_bytes` and a quarter of `max_output_bytes`, fail-open on any
  database error.
- Action history of mutating calls as **metadata events** (issue #33): one row per
  subject with tool, category, status, instance, client, duration, error code and a
  static summary. Guest output is never stored; `exec` calls store `command_sha256`
  plus `command_length` instead of the command, and no `path` subject.
- TTL, retention and cleanup (issue #36): per-note `expires`, tombstones, global
  retention in days, event retention, `memory_max_notes`, periodic job
  (`memory_cleanup_interval_seconds`, `0` disables) and a report per run.
- MCP resource `memory://notes` and prompt `memory_briefing` (issue #37), both gated by
  the `memory` category and hidden when the store is disabled.
- `pvehub_capabilities` reports `memory.{enabled,path,size_bytes,schema_version,fts,enrich,events_dropped,error,last_event_error,cleanup}`.
- New settings (all optional, defaults shown in `docs/CONFIGURATION.md`):
  `memory_enabled`, `memory_db`, `memory_enrich`, `memory_enrich_max_bytes`,
  `memory_enrich_max_notes`, `memory_note_max_bytes`, `memory_retention_days`,
  `memory_event_retention_days`, `memory_tombstone_days`,
  `memory_cleanup_interval_seconds`, `memory_max_notes` — YAML keys and
  `PVEHUB_MEMORY_*` environment variables.


- Trusted-proxy support and client-IP audit attribution (D024, issue #25):
  `PVEHUB_TRUSTED_PROXIES` / `trusted_proxies` (comma-separated CIDRs, or bare IPs
  treated as `/32`/`/128`) names the trusted reverse proxies; `PVEHUB_REQUIRE_TRUSTED_PROXY`
  / `require_trusted_proxy` (default `false`, validated to require a non-empty trust
  set) adds a `403` gate on `/mcp` and `/ready` for peers outside the trust set,
  **before** any authentication (`/health` stays exempt so container healthchecks keep
  working). New `client_ip` field in **every** audit entry (always present, `unknown`
  when unresolvable): for a trusted proxy peer, the client resolved from
  `X-Forwarded-For` (the rightmost entry *outside* the trust set — a forged chain
  cannot change the outcome for an untrusted peer, who is attributed to the socket
  peer); otherwise the socket peer. New dependency-free module `pvehub_mcp/proxy.py`
  (strict startup validation of the trust set); `uvicorn` runs with
  `proxy_headers=False` so the forwarded-header policy is explicit and testable.
  Malformed trust-set entries fail at startup instead of degrading silently.
- `tests/test_trusted_proxy.py`: the forgery table (10 cases), config validation,
  the 403 middleware at ASGI level, plus end-to-end tests through a real uvicorn
  server (full MCP session behind a "local reverse proxy", `127.0.0.1/32` trusted)
  asserting the resolved client IP in the audit log, and a default-configuration run
  asserting that a forged `X-Forwarded-For` is ignored.

### Changed

- Policy categories gained `memory` (recall, resource, prompt) and `memory_write`
  (remember, forget). They are valid in `categories.deny` and in
  `safety.require_confirm_for`; `read_only: true` allows `read`, `generic` and
  `memory`, so recall and enrichment keep working while writes disappear.
  `config/examples/readonly.yaml` now denies `memory_write` explicitly.
- Blocked memory tools follow the existing contract: absent from `tools/list`, listed in
  `pvehub_capabilities` under `tools.blocked` with the reason (`policy: ...` or
  `memory: ...`).

### Security

- Prompt-injection containment: auto-events contain only metadata (no guest output, no
  command text, no free-text arguments), and `_memory` is labelled as untrusted data in
  every response, in the resource payload and in the prompt wording. Notes are never
  rendered as instructions.
- The existing audit redaction runs before every memory write and again on every read;
  secrets in note bodies, tags, titles and argument-derived subjects are not persisted.
- The store is fail-closed for tools and fail-open for enrichment: an unwritable path
  disables the memory tools with a reported reason, while a failed enrichment never
  changes a tool result.

### Notes


- Default configuration is **unchanged**: without `trusted_proxies`, `X-Forwarded-For`
  is never consulted and the socket peer is logged — existing proxy-less and
  proxy-fronted deployments behave exactly as before. The audit schema gains one
  always-present field (`client_ip`); existing consumers are unaffected.

### Upgrade notes

- No action required: every key has a default and the database is created on first
  start. Existing `policy.yaml` files (including the shipped examples) load unchanged;
  without the new categories the defaults apply (`memory` and `memory_write` allowed,
  `read_only` keeps recall only).
- Back up `/data/memory.db` together with `audit.jsonl`. Copy it with the SQLite backup
  API (`sqlite3 memory.db ".backup ..."`) — a bare `cp` while WAL is active can miss
  recent writes.
- Do not share one `memory.db` between two server processes (stdio + HTTP). Give each
  transport its own file or volume.
- The database lives under `/data`; a read-only `/data` disables the memory layer
  (`memory.enabled=false`, `memory.error`) and the server starts normally.

## [0.1.1] — 2026-11-08

### Added

- `hub.tool(..., title="...")`: optional human-readable display title for a tool
  (issue #22). When omitted, the title is derived from the technical name by
  `pvehub_mcp.toolnaming` with consistent, acronym-aware labels
  (`pve_guest_delete` -> `PVE Guest Delete`, `pvehub_health` -> `PVEHub Health`).
  The derived title is the default; the `title` decorator argument is the
  documented override point.
- Per-client MCP tokens: `PVEHUB_MCP_AUTH_TOKENS` / `mcp_auth_tokens` (D019, issue #21).
  The legacy `PVEHUB_MCP_AUTH_TOKEN` keeps working (exposed to the middleware under the
  reserved client name `default`); named tokens add per-client revocation — rotating one
  client's token no longer logs out the others. The resolved client name is written as
  `client` into **every** audit entry (ok, denied, error; `unknown` for stdio /
  unauthenticated loopback). Config validation: 1-32 chars of `[a-z0-9_-]`, `default`
  reserved, >= 16 chars, and a named token must not equal the legacy token (one secret
  = one identity).
- `pvehub_audit_tail` MCP tool (D020, issue #20): tail the audit log in-band —
  `limit` (1..500), `tool`, `category`, `status`, `client`, `since` (ISO-8601) filters.
  The underlying `read_audit_tail` reads the last N entries in 64 KiB chunks bounded by
  an 8 MiB window (a large log never enters memory), skips corrupt lines, and
  **re-redacts on the way out** — nothing leaves the server unredacted.
- Audit rotation (D023, issue #19): `PVEHUB_AUDIT_MAX_BYTES` (default 10 MiB) and
  `PVEHUB_AUDIT_KEEP` (default 5). The active file rotates to `.1`, `.2`, … and the
  oldest archive is dropped; archives keep `0600`.
- Audit completeness (D023, issue #18): entries now carry `output_bytes` (size of the
  redacted response actually returned, every status) and — on `denied`/`error` —
  `error: {code, message}` with the typed error's own code, so the log distinguishes
  policy blocks, missing `confirm`, and permission misses.
- The `pvehub_capabilities` report now includes the audit state: `enabled`, `path`,
  `size_bytes`, `max_bytes`, `keep` and the **last write error** — a silently stopped
  audit is one MCP call away from diagnosis. `pvehub_health` reports `enabled`/`path`.

### Changed

- **Audit schema (breaking for multi-key calls):** `target` now collects **all** present
  target keys (D023, issue #18). A single key keeps the legacy `key=value` string
  unchanged; two or more keys are a `{key: "key=value"}` dict. jq pipelines that assume
  the string form keep working for single-key calls; multi-key calls need `.target
  | to_entries`.
- The http transport now starts with `PVEHUB_MCP_AUTH_TOKEN` **or**
  `PVEHUB_MCP_AUTH_TOKENS` (at least one); the "exactly one token" model is gone (D019,
  issue #21).
- The http transport now refuses to start without `PVEHUB_MCP_AUTH_TOKEN` for **any**
  bind address. 0.1.0 only refused non-loopback binds; loopback binds started with an
  unauthenticated `/mcp` (issue #16). `PVEHUB_MCP_AUTH_REQUIRED=false` (new, default
  `true`) is the explicit opt-out for loopback development setups; a warning is logged
  at startup and non-loopback binds without a token stay refused.
- `GET /health` is now a minimal liveness probe: the body is exactly `{"status": "ok"}`
  (always `200` while the process runs) and no longer exposes the version, transport or
  tool count (issue #24).
- `tools/list` now exposes, for every tool, a readable `title` (previously the
  snake_case technical name, which MCP clients rendering `title` showed verbatim)
  in both `title` and `annotations.title`, plus a `_meta` object carrying
  `category` and `confirm_required`, so clients can group tools and detect
  confirm-gated tools from the tool list alone (issue #22).
- Tools whose category is covered by `safety.require_confirm_for` (default:
  `destructive` and `exec`) now carry a stable note in the tool description:
  `This tool is protected: the call is rejected unless confirm=true is passed.`
  (plus a `dry_run` mention where the tool supports it). Agents that read only
  `tools/list` no longer hit avoidable `confirm required` denials.
- `docs/TOOLS.md` (and `make docs-tools`) now renders the derived titles in a
  `Title` column and the confirm note for the default confirm categories, and
  the doc generator honors a literal `title=` override (issue #22).
- The runtime version is single-sourced in `pvehub_mcp/_version.py`; `server.py` and the
  outgoing `User-Agent` header (`pvehub-mcp/<version>`) read it from there, and a packaging
  test pins it to `pyproject.toml` so a release cannot drift.

### Security

- New authenticated `GET /ready` readiness endpoint (same bearer as `/mcp`): full health
  body, HTTP `503` while any capability discovery is degraded. The Dockerfile and
  docker-compose healthchecks now probe `/ready` with the token from the container
  environment, so a dead or degraded backend marks the container `unhealthy` instead of
  staying `healthy` (issues #23, #24).

## [0.1.0] — 2026-11-07

### Added

- Initial release: one MCP server for Proxmox VE and Proxmox Backup Server.
- Streamable HTTP transport at `/mcp` with bearer authentication, stdio transport and
  unauthenticated `/health` liveness endpoint.
- PVE and PBS REST clients with API-token auth, retries, timeouts, TLS verification,
  optional CA bundle and SHA-256 certificate fingerprint pinning.
- Token permission discovery (`/access/permissions`) with periodic refresh, tool
  registration filtering and per-call privilege pre-checks.
- Policy engine with tool/category allow-deny lists, read-only mode, generic API path and
  method rules, VMID ranges, confirmation requirements and dry-run support.
- JSONL audit log with recursive secret redaction and bounded output.
- Generic API bridges for PVE and PBS with cached, live-fetched `apidoc.js` schemas.
- Curated PVE and PBS tools for cluster, guests, storage, backup, network, access, tasks,
  datastores, snapshots, prune/GC/verify and jobs.
- Shell access: QEMU guest agent exec, LXC via SSH + `pct exec`, opt-in PVE/PBS host shell,
  guest-agent file transfer and host SFTP with size limits.
- Dockerfile (multi-stage, non-root, healthcheck), docker-compose example, example policies,
  Gitea Actions CI workflow, documentation and generated tool catalog.

### Security

- Bearer token required for non-loopback HTTP binds; the server refuses to start otherwise.
- Destructive and exec tools require `confirm=true`; destructive tools support dry-run.
- SSH host-key verification, dedicated key, output/time limits and `shlex.quote`-based LXC
  command construction.
- No secrets in the repository; `.env.example` only. Audit redaction for token/password/
  private-key patterns, command/file bodies hashed instead of logged in clear.
- Independent security review (`docs/SECURITY_REVIEW.md`): fixed API-path traversal in curated
  tools, VMID bypass in generic API parameters, audit leaks, DNS-rebinding on loopback,
  resource-policy bypass and SFTP symlink escape; 5 low/info findings accepted and documented.
