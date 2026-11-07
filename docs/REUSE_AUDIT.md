# Reuse audit

Reference checkouts: `/tmp/ref` (shallow clones, audited 2026-11-07). Licenses were read from
the repository `LICENSE` file or package metadata. The rule applied: MIT/Apache-2.0 code may
be reused with attribution; GPL/AGPL is reference-only; unlicensed code is not copied.

| Project | License | Useful for | Reused? |
|---|---|---|---|
| `RekklesNA/ProxmoxMCP-Plus` | MIT | Streamable-HTTP operation in Docker, exec tools, config structure, OpenAPI bridge | Concepts only: transport lifecycle, exec polling shape, Docker entrypoint idea. No code copied. |
| `ahmetem/homelab-proxmox-mcp` (`pve-mcp`) | **GPL-3.0** | Safety model (confirm, dry-run, audit), token-efficient output, `lxc_exec` via `pct exec` | Reference only. Reimplemented safety model independently. |
| `ahmetem/homelab-pbs-mcp` (`pbs-mcp`) | **GPL-3.0** | PBS tools: datastores, snapshots, GC, verify, prune | Reference only. Tool list informed the PBS catalog; API behaviour taken from live PBS `apidoc.js`. |
| `akmalovaa/proxmox-mcp` | MIT | Slim multi-arch image, risk-tier model (`PROXMOX_RISK_LEVEL`), tool structure | Concept only: risk tiers inspired the `read/lifecycle/write/destructive/exec/generic` categories. No code copied. |
| `netixc/ProxmoxMCP` | unknown (clone failed) | SSH host/container exec, SFTP transfer, host exec opt-in | Not audited, not reused. Repository unavailable at build time. |
| `husniadil/proxmox-mcp-server` | MIT | `execute_container_command` / `execute_host_command` via SSH, SFTP | Reviewed quoting approach; replaced with `shlex.quote`-based construction. No code copied. |
| `gilby125/mcp-proxmox` | MIT | Tiered permissions, MCP resources and prompts | Concept only: resources/prompts included. No code copied. |
| `bldg-7/proxmox-mcp` | MIT | Tool catalog checklist (55 tools) | Used as a checklist for coverage (cluster, access, backup, network, SDN, snapshots). No code copied. |
| `bakhshb/proxmox-mcp-openapi` | Apache-2.0 | "Few generic tools for hundreds of operations" | Concept only: `pve_api_schema` + `pve_api_call` bridge. No code copied. |

## What was deliberately not reused

- **GPL implementation code** (`pve-mcp`, `pbs-mcp`): no copy, no translation, no vendoring.
  Their safety features were specified independently from the task requirements.
- **Authentication via username/password tickets**: only API tokens are supported. Ticket
  handling adds CSRF complexity and encourages storing user passwords.
- **Host exec enabled by default**: rejected; opt-in only.
- **Free-form command strings passed to a shell without quoting**: rejected. LXC commands are
  wrapped as `pct exec <vmid> -- sh -c <shlex.quote(command)>`.
- **OpenAPI proxies with their own HTTP auth**: the MCP endpoint already has bearer auth; a
  second proxy surface would double the attack surface.

## Verified API facts (live servers, unauthenticated docs)

- PVE API base `/api2/json`, PBS API base `/api2/extjs` (both also answer on `/api2/json`;
  `/api2/extjs` is the documented PBS form).
- PVE `GET /access/permissions` returns `path → {privilege: propagate}` and accepts optional
  `path` and `userid`.
- PBS `GET /access/permissions` exists and accepts optional `auth-id` and `path`.
- PVE guest agent: `POST /nodes/{node}/qemu/{vmid}/agent/exec` (`command` array),
  `GET .../agent/exec-status?pid=`, `GET .../agent/file-read` (max 16 MiB, base64 decode
  option), `POST .../agent/file-write`.
- PVE tasks: `GET /nodes/{node}/tasks/{upid}/status`, `GET .../log` (`start`, `limit`).
- PBS: `/admin/datastore`, `/admin/datastore/{store}/snapshots` (GET/DELETE),
  `/admin/datastore/{store}/prune` (POST, `dry-run`), `.../gc` (GET status, POST start),
  `.../verify` (POST), `.../namespace` (GET/POST/DELETE), `/nodes/{node}/tasks`.
- Auth headers: PVE `Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET`,
  PBS `Authorization: PBSAPIToken=USER@REALM!TOKENID:SECRET` (colon before the secret).

## Attribution

No third-party source code is included, so no license headers are required. The projects above
are credited as design inspirations in `THIRD_PARTY.md`.
