# PVEHub-MCP

One MCP server for **Proxmox VE** and **Proxmox Backup Server**, plus shell access to PVE
hosts, LXC containers, QEMU VMs (guest agent) and the PBS host.

> Status: `0.1.0` — core server, policy engine, curated PVE/PBS/exec tools and packaging are
> implemented. `docs/TOOLS.md` is generated from the code and shows exactly what exists today;
> `docs/STATUS.md` separates live-verified, mocked and untested behaviour.

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

## Architecture

```mermaid
flowchart LR
  client["MCP client<br/>Claude, Hermes, Open WebUI"]
  subgraph hub["pvehub-mcp container (UID 10001)"]
    server["server.py<br/>/mcp · /health<br/>bearer auth"]
    policy["policy.py<br/>categories · allow/deny<br/>generic API gates"]
    caps["capabilities.py<br/>token privileges"]
    tools["tools/<br/>curated + generic"]
    audit[("audit.jsonl<br/>/data")]
    server --> policy --> caps --> tools
    tools --> audit
  end
  client -->|"Streamable HTTP + Bearer"| server
  client -->|"stdio (docker run -i)"| server
  tools -->|"HTTPS · API token"| pve["Proxmox VE API"]
  tools -->|"HTTPS · API token"| pbs["Proxmox Backup Server API"]
  tools -->|"SSH · dedicated key"| nodes["PVE nodes / PBS host"]
```

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

`docker compose` reads `.env`, mounts `./config` and `./ssh` read-only, keeps `/data`
(audit log, caches) in the named volume `pvehub-data`, runs the container read-only with
all capabilities dropped, and publishes `8080` on all interfaces. Bind it to LAN/VPN only:
put a TLS reverse proxy in front of it, or change the port mapping to
`127.0.0.1:8080:8080` and proxy from the same host.

The API token needs the privileges of the tools you want to use. Start read-only:

```
PVE:  Datastore.Audit, Sys.Audit, VM.Audit
PVE (exec/files): VM.GuestAgent.Unrestricted, VM.GuestAgent.FileRead, VM.GuestAgent.FileWrite,
                  VM.GuestAgent.Audit
PBS:  Datastore.Audit, Sys.Audit
```

Then widen the token ACL and restart the server. `pvehub_capabilities` shows what is
available, what policy blocks and what the token is missing.

## Clients

The server speaks **Streamable HTTP** at `http://<host>:8080/mcp` with
`Authorization: Bearer <PVEHUB_MCP_AUTH_TOKEN>`, or **stdio** when started with
`--transport stdio` / `PVEHUB_TRANSPORT=stdio` (no listener, no bearer token).

### Claude Code / generic HTTP client

```bash
claude mcp add --transport http pvehub http://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer $PVEHUB_MCP_AUTH_TOKEN"
```

Generic client entry (Claude Code `.mcp.json`, Cursor and similar):

```json
{
  "mcpServers": {
    "pvehub": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

### Claude Desktop (stdio via Docker)

Claude Desktop launches stdio servers itself. Run the same image with `-i` and no port:

```json
{
  "mcpServers": {
    "pvehub": {
      "command": "/usr/local/bin/docker",
      "args": [
        "run", "-i", "--rm",
        "--env-file", "/Users/you/pvehub/.env",
        "-e", "PVEHUB_TRANSPORT=stdio",
        "-v", "/Users/you/pvehub/config:/config:ro",
        "-v", "/Users/you/pvehub/ssh:/ssh:ro",
        "-v", "pvehub-data:/data",
        "pvehub-mcp:0.1.0"
      ]
    }
  }
}
```

Use the absolute path to `docker` (GUI apps often have a minimal `PATH`) and absolute host
paths for the mounts. Docker Desktop must be running. `-v pvehub-data:/data` creates a
volume of that name, separate from the compose volume (`<project>_pvehub-data`); point both
at the same host directory if they should share audit/cache state. The image's HTTP
healthcheck does not apply here; ignore the container health status in stdio mode.

### Hermes

`~/.hermes/config.yaml`:

```yaml
mcp_servers:
  pvehub:
    url: "http://127.0.0.1:8080/mcp"
    headers:
      Authorization: "Bearer ${PVEHUB_MCP_AUTH_TOKEN}"
```

Hermes expands `${VAR}` in `url`/`headers`; keep the token in the environment, not in the
file. For stdio, use `command: docker` with `args: ["run", "-i", "--rm", ...]` and
`env: { PVEHUB_TRANSPORT: "stdio" }` instead of `url`.

### Open WebUI

Admin Settings → Integrations → **External Tool Servers** → **+ Add Connection**:

- Type: **MCP (Streamable HTTP)**
- URL: `http://<docker-host>:8080/mcp`
- Auth: bearer token (`PVEHUB_MCP_AUTH_TOKEN`)

Open WebUI calls the tools through its backend, so the URL must be reachable from the
Open WebUI container, not just from your browser (use the LAN address or a shared Docker
network, not `127.0.0.1`).

## SSH access (optional)

Shell tools are the highest-risk part of the server. Host and PBS shells are disabled by
default (`exec.host: false`, `exec.pbs_host: false`); LXC and VM exec are enabled but
still require `confirm=true` and a VMID inside `exec.allowed_vmids`.

Minimum setup:

```bash
# 1. Dedicated key, no passphrase (it lives in the container)
ssh-keygen -t ed25519 -C pvehub-mcp -f ssh/id_ed25519 -N ''

# 2. Host keys, verified out of band before trusting them
ssh-keyscan -H 10.0.0.11 10.0.0.12 10.0.0.20 >> ssh/known_hosts
ssh-keygen -lf ssh/known_hosts        # compare with the node consoles

# 3. UID 10001 must be able to read the key
chown -R 10001:10001 ssh && chmod 700 ssh && chmod 600 ssh/id_ed25519 ssh/known_hosts
```

On every node, create a dedicated user, install the public key and map the PVE node name
to its address in `config/config.yaml`:

```yaml
ssh:
  nodes:
    pve1:
      host: 10.0.0.11
    pve2:
      host: 10.0.0.12
      sudo: true          # pct exec via passwordless sudo
  pbs:
    host: 10.0.0.20
```

Notes:

- The `nodes` key must be the **PVE node name**, not the hostname.
- `pct exec` needs root or passwordless sudo for `/usr/sbin/pct`; `sudo: true` runs
  `sudo -n pct exec ...`, so a missing NOPASSWD rule fails immediately instead of hanging.
- Keep `strict_host_key: true`. `known_hosts` must exist or the shell tools stay hidden.
- `authorized_keys` **cannot** use `command="..."` restrictions: the MCP server sends
  arbitrary commands (host shell, `pct exec` with a variable VMID). A forced command would
  break every call. Restrict by key (`from="10.0.0.20"`), a dedicated user, firewall rules
  and the policy instead. `restrict` (no forwarding, no agent, no pty) is fine.
- Revoke by removing the key from `authorized_keys`; the MCP server reconnects with the
  key on the next call.

## Security (short version)

- Bind the MCP port to LAN/VPN only; put TLS in front of it (reverse proxy).
- Always set `PVEHUB_MCP_AUTH_TOKEN` for non-loopback binds; the server refuses to start
  without it.
- Use a dedicated PVE/PBS API token with the minimum ACLs and no expiry surprises.
- Start with `config/examples/readonly.yaml`; widen to `operator.yaml` when needed.
  `admin.yaml` (destructive + host shells) is for trusted single-operator setups only.
- Shell access: dedicated SSH key, `known_hosts` verification, `exec.host` and
  `exec.pbs_host` stay `false` unless you really need them.
- Destructive and exec tools require `confirm=true`; destructive tools support `dry_run`
  where the API does.
- The generic API bridge always denies ticket/console endpoints (`/access/ticket`,
  token endpoints, `vncshell`, `spiceshell`, `termproxy`, QEMU `monitor`).
- Audit JSONL is written to `/data/audit.jsonl` with secret redaction; result bodies are
  opt-in (`PVEHUB_AUDIT_INCLUDE_RESULTS=true`).
- The container runs as UID 10001, read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `refusing to bind a non-loopback address without mcp_auth_token` | Set `PVEHUB_MCP_AUTH_TOKEN` (non-empty) or bind to `127.0.0.1` |
| `configuration error: ... extra_forbidden` | Unknown YAML key; compare with `docs/CONFIGURATION.md`. `extra="forbid"` is intentional |
| `policy error: ... invalid policy` | Unknown category or key in `policy.yaml`; valid categories are `read`, `lifecycle`, `write`, `destructive`, `exec`, `generic` |
| `401 unauthorized` on `/mcp` | Missing/wrong `Authorization: Bearer ...` header |
| `421 Invalid Host header` or DNS-rebinding error | Set `PVEHUB_ALLOWED_HOSTS` to the hostnames clients use (including port if non-default) |
| `docker compose` complains about `.env` | `cp .env.example .env` first; compose requires the file |
| Tool missing from `tools/list` | Policy deny, category deny, missing token privilege, missing SSH target/key, or `exec.host`/`exec.pbs_host` disabled. Ask `pvehub_capabilities` for `tools.blocked` reasons |
| `/health` shows `degraded` | Permission discovery failed for at least one instance; the server still serves tools per `capabilities_fail_open`. Check logs and token ACLs |
| SSH `key not found` / `known_hosts not found` | Wrong mount path, wrong UID/permissions, or missing `ssh.nodes` entry for the node |
| `sudo: a password is required` | `sudo: true` is set but no NOPASSWD rule for `pct` exists on the node |
| Container `unhealthy` while using stdio | Expected: there is no HTTP listener, so the `/health` check fails. Harmless for `docker run -i` |
| Changes to policy/token ACLs have no effect | Settings and policy are read at startup; restart the container |

## Documentation

| Document | Content |
|---|---|
| `docs/ARCHITECTURE.md` | components, request pipeline, why SSH is needed |
| `docs/CONFIGURATION.md` | every environment variable and YAML key, precedence, TLS, policy, audit |
| `docs/TOOLS.md` | generated tool catalog with categories and privileges |
| `docs/DECISIONS.md` | design decisions and trade-offs |
| `docs/PLAN.md` | phase plan |
| `docs/REUSE_AUDIT.md` | reference projects, licenses, what was reused |

## Development

```bash
make install        # uv sync --extra dev
make check          # ruff + mypy + pytest
make docs-tools     # regenerate docs/TOOLS.md from @hub.tool declarations
make docker-build   # docker build -t pvehub-mcp:0.1.0 .
```

The Docker image is built by CI (`.gitea/workflows/ci.yml`); the development sandbox has
no Docker daemon, so the image build is not executed there (see `docs/DECISIONS.md` D010).

## License

MIT — see `LICENSE`. Third-party inspiration: `THIRD_PARTY.md`.
