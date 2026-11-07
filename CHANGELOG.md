# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog;
versioning: Semantic Versioning.

## [Unreleased]

### Changed

- The http transport now refuses to start without `PVEHUB_MCP_AUTH_TOKEN` for **any**
  bind address. 0.1.0 only refused non-loopback binds; loopback binds started with an
  unauthenticated `/mcp` (issue #16). `PVEHUB_MCP_AUTH_REQUIRED=false` (new, default
  `true`) is the explicit opt-out for loopback development setups; a warning is logged
  at startup and non-loopback binds without a token stay refused.

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
