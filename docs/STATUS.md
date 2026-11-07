# Status

Last updated: 2026-11-07 (during implementation).

This document separates what was **actually executed** from what is covered by mocks and what
could not be tested in the build environment. Do not read it as a marketing status page.

## Environment used for verification

| Item | Value |
|---|---|
| Build sandbox | Linux container, Python 3.12.15 (uv), no Docker/Podman daemon |
| PVE test server | `10.0.10.3:8006` reachable; **no API token supplied** |
| PBS test server | `10.0.10.6:8007` reachable; **no API token supplied** |
| SSH test access | **no key/user supplied** |
| Gitea | `git.mls4tech.net`, repo `admin/PVEHub-MCP` |

Because no PVE/PBS API tokens or SSH keys were provided, all authenticated API and SSH
behaviour is covered by unit/contract tests with `respx` and in-memory fakes. The API
*surface* (paths, parameters, permissions endpoints, auth headers) was verified against the
live, unauthenticated `apidoc.js` of both servers and the official Proxmox documentation.

## Verified by execution

| Area | Evidence |
|---|---|
| Python package install | `uv sync --extra dev` |
| Lint | `uv run ruff check src tests` — clean |
| Typecheck | `uv run mypy src` — clean |
| Unit/contract tests | `uv run pytest -q` — see final test count in the release report |
| HTTP transport | local uvicorn start, `GET /health` → 200 JSON, `POST /mcp` without token → 401, with token → MCP `initialize` result |
| TLS fingerprint pinning | real TLS handshake against `10.0.10.3:8006`; correct SHA-256 accepted, wrong fingerprint rejected |
| PVE/PBS API schema | live `apidoc.js` fetched and parsed for endpoint/parameter verification |
| Policy gates | unit tests for read-only, deny lists, confirm, dry-run, VMID ranges, path traversal/encoding, command denylist |

## Mocked only

- All authenticated PVE/PBS API calls (guests, storage, snapshots, backup, PBS datastores,
  jobs, tasks).
- Token permission matrices for registration filtering (multiple synthetic permission sets).
- SSH connections, `pct exec`, SFTP and guest-agent exec/file transfer.
- Audit file writes (temp files) and redaction edge cases.

## Not tested

- `docker build` / `docker compose up` — no Docker daemon in the build sandbox. The Dockerfile
  and compose file are provided and statically validated; CI is configured to build them.
- Gitea Actions execution — depends on a runner being available for this repository.
- Live PVE/PBS permission discovery with a real token.
- Real SSH host-key verification and `pct exec` on a node.
- Multi-arch image build (amd64/arm64).
- Behaviour against PBS versions older than the test server's API schema.

## Known limitations

- The tool set is fixed at process start. A token permission change or policy edit requires a
  restart; periodic capability refresh updates reports and per-call checks, not `tools/list`.
- The generic API bridge exposes whatever the token can reach, minus hard-denied ticket and
  console endpoints. Operators must still scope the token ACL.
- The command denylist is best-effort; it is not a sandbox. Host/PBS shell remain opt-in.
- LXC file transfer is not exposed as a dedicated tool; use `exec_lxc` with `base64`/`tar` if
  needed (guest-agent file tools cover QEMU VMs, SFTP covers hosts).
- PBS snapshot "protect" and detail endpoints depend on the PBS version; tools are only
  registered for endpoints verified in the server's `apidoc.js`.
- No OAuth/OIDC for the MCP endpoint; a static bearer token is used. Put it behind a TLS
  reverse proxy and keep the port on LAN/VPN.
