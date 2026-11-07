# PVEHub-MCP

One MCP server for **Proxmox VE** and **Proxmox Backup Server**, plus shell access to PVE
hosts, LXC containers, QEMU VMs (guest agent) and the PBS host.

> Status: `0.1.0` — implementation in progress; see `docs/STATUS.md` for the exact
> tested/mocked matrix.

## Features

- **PVE REST API** — curated tools plus a generic `pve_api_schema` / `pve_api_call` bridge
  for every endpoint the token can reach.
- **PBS REST API** — datastores, namespaces, snapshots, prune, GC, verify, jobs, tasks, plus
  a generic bridge.
- **Shell** — QEMU guest agent, LXC via `pct exec`, host and PBS host via SSH (opt-in).
- **Rights-aware** — token permissions are discovered at startup; tools without the required
  privilege are not registered, and each call is pre-checked.
- **Blockable** — every tool and category can be denied via YAML/env policy; denied tools do
  not appear in `tools/list`.
- **One container, one endpoint** — Streamable HTTP at `/mcp`, `/health`, optional stdio.

## Quickstart

```bash
git clone https://git.mls4tech.net/admin/PVEHub-MCP.git
cd PVEHub-MCP
cp .env.example .env
# edit .env: PVE/PBS URLs, token IDs/secrets, PVEHUB_MCP_AUTH_TOKEN
mkdir -p config ssh
cp config/examples/operator.yaml config/policy.yaml
docker compose up -d --build
curl -s http://127.0.0.1:8080/health
```

The API token needs the privileges of the tools you want to use. Start read-only:

```
PVE:  Datastore.Audit, Sys.Audit, VM.Audit, VM.Monitor
PBS:  Datastore.Audit, Sys.Audit
```

Then widen the token ACL and restart the server. `pvehub_capabilities` shows what is
available, what policy blocks and what the token is missing.

## Documentation

| Document | Content |
|---|---|
| `docs/ARCHITECTURE.md` | components, request pipeline, why SSH is needed |
| `docs/CONFIGURATION.md` | every environment variable and YAML key |
| `docs/TOOLS.md` | generated tool catalog with categories and privileges |
| `docs/DECISIONS.md` | design decisions and trade-offs |
| `docs/REUSE_AUDIT.md` | reference projects, licenses, what was reused |
| `docs/SECURITY_REVIEW.md` | independent review findings and fixes |
| `docs/STATUS.md` | tested vs. mocked vs. untested |

## Security (short version)

- Bind the MCP port to LAN/VPN only; put TLS in front of it (reverse proxy).
- Always set `PVEHUB_MCP_AUTH_TOKEN` for non-loopback binds; the server refuses to start
  without it.
- Use a dedicated PVE/PBS API token with the minimum ACLs and no expiry surprises.
- Shell access: dedicated SSH key, `known_hosts` verification, `exec.host` and
  `exec.pbs_host` stay `false` unless you really need them.
- Destructive and exec tools require `confirm=true`; destructive tools support `dry_run`
  where the API does.
- Audit JSONL is written to `/data/audit.jsonl` with secret redaction.

See `README` sections below (filled in Phase 6) and `docs/SECURITY_REVIEW.md`.

## License

MIT — see `LICENSE`. Third-party inspiration: `THIRD_PARTY.md`.
