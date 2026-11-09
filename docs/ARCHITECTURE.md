# Architecture

## Overview

```
MCP client (Claude, Hermes, Open WebUI, ...)
        │  Streamable HTTP + Bearer  (or stdio)
        ▼
┌──────────────────────────────────────────────────────────────┐
│ pvehub-mcp (single container / process)                      │
│                                                              │
│  server.py       MCPServer, transport, auth, /health, /ready │
│  policy.py       categories, allow/deny, generic API rules   │
│  capabilities.py token permissions → tool availability       │
│  audit.py        JSONL audit trail + redaction               │
│  memory.py       SQLite notes + call-metadata events         │
│                                                              │
│  tools/          curated tools + generic API bridges          │
│                                                              │
│  clients/pve.py  httpx async, /api2/json, UPID polling       │
│  clients/pbs.py  httpx async, /api2/extjs, UPID polling      │
│  clients/ssh.py  asyncssh pool, pct exec, SFTP               │
└───────┬───────────────────────────┬──────────────────────────┘
        │ HTTPS (API token)         │ SSH (dedicated key)
        ▼                           ▼
   PVE cluster / PBS            PVE nodes / PBS host
   (REST API)                   (host shell, pct exec)
```

## Why SSH is required for host and LXC commands

The PVE REST API has no endpoint that executes a command in an LXC container or on a PVE
host. QEMU VMs are different: the QEMU guest agent exposes `agent/exec` and
`agent/exec-status` through the PVE API. Therefore:

| Target | Transport | Requirement |
|---|---|---|
| QEMU VM | PVE REST (`agent/exec`) | guest agent installed and running in the VM |
| LXC | SSH to the node + `pct exec <vmid> -- sh -c <quoted>` | SSH access to the node, root or `pct` capability |
| PVE host | SSH to the node | opt-in (`exec.host: true`) |
| PBS host | SSH to the PBS host | opt-in (`exec.pbs_host: true`) |

This is a design property, not a missing feature.

## Tool layers

1. **Generic:** `pve_api_schema` / `pve_api_call`, `pbs_api_schema` / `pbs_api_call`.
   The schema is parsed from the server's own `apidoc.js` (PVE:
   `/pve-docs/api-viewer/apidoc.js`, PBS: `/docs/api-viewer/apidoc.js`), cached in memory
   and on disk. This makes every endpoint reachable without one tool per endpoint.
2. **Curated:** stable, frequently used workflows with compact JSON output. Every curated
   tool still passes through policy, capability and audit layers.

Tool output is a compact JSON document:

```json
{"ok": true, "data": ...}
{"ok": false, "error": {"code": "permission_denied", "message": "...", "required": "VM.PowerMgmt on /vms/100"}}
```

## Request pipeline

```
tool call
  → policy.check_tool_call()      category, deny list, read-only, allowed VMIDs
  → confirm check                 destructive/exec need confirm=true
  → capability.check()            token privilege on the concrete path
  → audit start                   parameters redacted
  → client call (retry/timeout)
  → optional task wait (UPID)
  → output truncation
  → audit finish (status, duration, output bytes)
```

Registration is filtered the same way: a tool blocked by policy, or for which the token has
no possible privilege, is never added to the MCP tool list. Per-call checks are defense in
depth (for example when a token loses a privilege after startup).

## Capability model

`GET /access/permissions` returns a map `path → {privilege: propagate}`. A privilege for a
target path is granted when an entry exists for that path or any parent path (`/` is the
root ACL). Tool requirements are declared as `(privilege, path template)`, for example:

- `VM.PowerMgmt` on `/vms/{vmid}`
- `VM.Audit` on `/vms/{vmid}`
- `Datastore.Audit` on `/storage/{store}`
- `Sys.Audit` on `/nodes/{node}`
- `Sys.Modify` on `/nodes/{node}` for node-level changes

At startup the server asks PVE and PBS for the token's effective permissions. Curated tools
without any matching privilege are hidden. At call time the concrete path is checked again
and a clear `permission_denied` error is returned instead of a raw HTTP 403. Discovery is
repeated every `PVEHUB_CAPABILITIES_REFRESH_SECONDS`; availability metadata is updated, but
the registered tool set is fixed for the process lifetime (restart to re-evaluate).

## Bearer pass-through (D026, issue #30)

The **default** mode (`mcp_auth_mode: "static"`) authenticates MCP clients with named
tokens (D019) and calls PVE with one configured service token. **Passthrough**
(`mcp_auth_mode: "passthrough"`, opt-in) changes the credential model: the
`Authorization: Bearer` value **is** the requesting client's own PVE API token, and it is
used as the credential for every PVE call of that request. The configured service token is
never used in this mode (fail-closed).

* **Edge.** `PassthroughBearerMiddleware` replaces the named-token
  `BearerAuthMiddleware` for `/mcp` and `/ready`. It performs *structural* validation only
  (`parse_pve_bearer`: `user@realm!tokenid=<secret>`, secret ≥ 16 chars, no whitespace)
  and returns `401` for anything else. It does **not** call PVE.
* **Validation (deferred, per request + per instance).** The tool wrapper resolves the
  bearer (from the request context, or by re-parsing the raw `Authorization` header when
  the SDK runs the call in a different task), then calls `GET /access/permissions` *with
  that token*. A `401` is a hard `AuthenticationError` (no fallback). A `403` (PVE
  authenticates before it ACLs, so the token is real but lacks `Sys.Audit`) is trusted and
  recorded as a discovery failure. A `200` yields the per-token permission snapshot.
* **Cache.** `TokenValidationCache` is a bounded, TTL cache keyed by the **full** token
  identity (user, realm, token-id **and** secret) per PVE instance, so a rotated secret is
  a new key (re-validated immediately) and two clients with different tokens never share a
  validated state or a permission snapshot. Evicted entries return their clients so they
  are closed.
* **Scoped client.** The validated `TokenState` is stored in a request-local context
  (`pve_scoped_context`). `PVEHub.pve()` returns the per-request client — whose
  `Authorization` header carries the request's token — and is fail-closed (raises
  `AuthenticationError` with no validated token instead of falling back to the configured
  service token). `PVEHub.pbs()` raises `AuthenticationError` in passthrough mode.
* **Call-time gate is the boundary.** The request's token is unknown at registration, so
  PVE tool visibility is **not** permission-filtered in this mode; the per-call
  `check_pve_token_snapshot` gate runs against the token's own snapshot (fail-open /
  fail-closed per `capabilities_fail_open`), and PVE enforces the caller's ACL on every
  call regardless.
* **PBS is out of scope (closes issue #7).** A PVE API token is not a PBS credential, and
  the only credential a passthrough request carries is a PVE token, so no PBS tool is
  registered in this mode (blocked at registration, reported under `tools.blocked`).
  Static mode remains the only way to reach PBS.
* **Audit & visibility.** The audit log writes the token **identity** (`user@realm!tokenid`,
  never the secret) into a `pve_token` field; `client` stays `unknown` (there is no named
  MCP token). `pvehub_capabilities` reports an `auth` block (`mode`, `required`,
  `token_validation_ttl` in passthrough). Static mode is byte-for-byte unchanged.

## Configuration and policy precedence

```
defaults  <  config.yaml (PVEHUB_CONFIG_FILE)  <  environment (PVEHUB_*)
```

Policy is a separate YAML file (`/config/policy.yaml`) with environment overrides. Both are
validated at startup; unknown keys fail loudly (`extra="forbid"`).

## Transports

- **Streamable HTTP** (default in the container): `0.0.0.0:8080/mcp`, bearer token required.
  Refuses to bind a non-loopback address without `PVEHUB_MCP_AUTH_TOKEN`.
- **stdio**: `PVEHUB_TRANSPORT=stdio`; no network listener, no bearer token needed.
- `/health`: unauthenticated **liveness** endpoint; always `200` while the process runs,
  body is exactly `{"status": "ok"}` — no version, no tool count, no backend state.
- `/ready`: **readiness** endpoint, authenticated with the same bearer as `/mcp` (the
  middleware protects the exact path in addition to the `/mcp` prefix). Full health body
  (`status`, `version`, `transport`, `tools`, per-instance capability state); `200` while
  healthy, `503` while any capability discovery is degraded. The container and CI
  healthchecks probe `/ready` with the token from the container environment (D021).

## Module layout

```
src/pvehub_mcp/
  __main__.py        CLI entrypoint (transport selection)
  server.py          MCP instance, HTTP app, auth middleware, tool registration
  config.py          settings (env + YAML), validation
  policy.py          allow/deny, categories, path rules, exec gates
  capabilities.py    permission discovery and privilege mapping
  audit.py           JSONL audit log, redaction, truncation
  memory.py          SQLite memory store (notes, events, retention, _memory)
  errors.py          typed errors and JSON error envelopes
  clients/
    base.py          shared httpx client, retries, TLS, form encoding
    pve.py           PVE API, UPID polling, apidoc schema cache
    pbs.py           PBS API, UPID polling, apidoc schema cache
    ssh.py           asyncssh pool, pct exec, SFTP
  tools/
    registry.py      registration + guard wrapper
    meta.py          pvehub_capabilities
    memory.py        memory_recall / memory_remember / memory_forget
    pve_generic.py   pve_api_schema, pve_api_call
    pve_cluster.py   cluster/nodes/HA
    pve_guests.py    list/status/config/power/snapshot/clone/migrate/create/delete/resize
    pve_storage.py   storage list/status/content
    pve_backup.py    backup/restore
    pve_network.py   network interfaces
    pve_access.py    users/roles/ACLs (read)
    pve_tasks.py     task list/status/log/stop
    pbs_generic.py   pbs_api_schema, pbs_api_call
    pbs_datastore.py datastores/status/namespaces
    pbs_snapshots.py snapshots/protect/forget/prune/gc/verify
    pbs_jobs.py      sync/verify/prune jobs, remotes
    pbs_tasks.py     task list/status/log
    exec_host.py     host shell (opt-in)
    exec_lxc.py      pct exec
    exec_vm.py       guest-agent exec
    exec_pbs.py      PBS host shell (opt-in)
    files.py         guest-agent file read/write, SFTP pull/push
  resources.py       proxmox://nodes, proxmox://guests, proxmox://storage
  prompts.py         health_check, provision_lxc, backup_audit
```

## Failure behavior

| Failure | Behavior |
|---|---|
| PVE/PBS unreachable at startup | server starts; capabilities marked `unknown`; tools registered if `capabilities.fail_open`; `GET /ready` reports `degraded` with HTTP `503` (liveness `/health` stays `200`) |
| Permission discovery 401/403 | treated as "no permissions"; no privileged tools registered |
| API 403 at call time | `permission_denied` with required privilege and path |
| Passthrough token rejected by PVE (401) | the call fails with `AuthenticationError`; **no** fallback to the configured service token; the identity is not cached as valid (revalidated next use) |
| Passthrough token valid but lacks `Sys.Audit` (403) | identity trusted; per-token snapshot records a discovery failure; PVE keeps enforcing the caller's ACL per call |
| Task timeout (`wait=true`) | returns UPID + `timed_out: true`; caller can poll `*_task_status` |
| SSH unavailable | shell tools hidden unless SSH config is complete; runtime errors include the missing prerequisite |
| Audit file not writable | warning, server continues, audit disabled (reported in `pvehub_capabilities`) |
