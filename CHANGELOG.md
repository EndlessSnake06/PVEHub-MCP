# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog;
versioning: Semantic Versioning.

## [Unreleased]

### Added

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
