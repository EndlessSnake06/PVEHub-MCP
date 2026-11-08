# Status

Last updated: 2026-11-08 (release 0.1.1).

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
| Unit/contract tests | `uv run pytest -o addopts="" -q` — **250 passed, 2 skipped** (integration) |
| HTTP transport | local uvicorn start, `GET /health` → 200 JSON, `POST /mcp` without token → 401, with token → MCP `initialize` result |
| stdio transport | real subprocess via MCP client: `tools/list` → 69 tools, `pvehub_health` call |
| TLS fingerprint pinning | real TLS handshake against `10.0.10.3:8006`; correct SHA-256 accepted, wrong fingerprint rejected |
| PVE/PBS API schema | live `apidoc.js` fetched and parsed for endpoint/parameter verification |
| Policy gates | unit tests for read-only, deny lists, confirm, dry-run, VMID ranges, path traversal/encoding, command denylist |
| Tool catalog | 74 tools generated from source; 69 registered with a full mock permission set, 5 shell/file tools correctly blocked without SSH configuration |
| Package build | `uv build --wheel`; wheel installed into a fresh venv, `pvehub-mcp --version` → `0.1.0` |
| Independent security review | `docs/SECURITY_REVIEW.md`; 15 findings, 10 fixed with regression tests, 5 accepted/justified; post-merge gate **250 passed, 2 skipped** |
| Docker image build | Gitea Actions run 2681: four jobs (lint, typecheck, test, docker) succeeded; `docker build --pull -t pvehub-mcp:ci .` completed and exported the image (`sha256:45b13474…`) |
| CI test gate | Gitea Actions run 2681: `250 passed, 2 skipped` on the runner |
| Compose runtime smoke | Gitea Actions compose job: `docker compose config`, `docker compose up -d --build`, `/health` 200 inside the container, `docker compose down -v`; policy `readonly.yaml` loaded |

## Mocked only

- All authenticated PVE/PBS API calls (guests, storage, snapshots, backup, PBS datastores,
  jobs, tasks).
- Token permission matrices for registration filtering (multiple synthetic permission sets).
- SSH connections, `pct exec`, SFTP and guest-agent exec/file transfer.
- Audit file writes (temp files) and redaction edge cases.

## Not tested

- Container hardening inspection (`docker inspect`: read-only rootfs, capabilities, UID) — the
  compose smoke ran the container but did not assert every runtime flag.
- Multi-arch build (amd64/arm64) — the CI runner built the host architecture only.
- Healthcheck transition from `starting` to `healthy` — the smoke asserted `/health` 200 inside
  the container, not Docker's health status after the 30 s start period.
- Live PVE/PBS permission discovery with a real token.
- Real SSH host-key verification and `pct exec` on a node.
- Behaviour against PBS versions older than the test server's API schema.

## Known limitations

- The tool set is fixed at process start. A token permission change or policy edit requires a
  restart; periodic capability refresh updates reports and per-call checks, not `tools/list`.
- The generic API bridge exposes whatever the token can reach, minus hard-denied ticket,
  console and guest-agent exec/file-write endpoints, and non-GET calls require `confirm=true`.
  Operators must still scope the token ACL; a token with config-write rights can change VM
  hookscripts, so treat generic API access as privileged.
- The command denylist is best-effort; it is not a sandbox. Host/PBS shell remain opt-in.
- LXC file transfer is not exposed as a dedicated tool; use `exec_lxc` with `base64`/`tar` if
  needed (guest-agent file tools cover QEMU VMs, SFTP covers hosts).
- PBS snapshot "protect" and detail endpoints depend on the PBS version; tools are only
  registered for endpoints verified in the server's `apidoc.js`.
- Capability pre-checks model AND-requirements only. Tokens holding an equivalent alternative
  privilege may see a tool hidden; PVE/PBS remain the enforcement point (review finding F-11).
- Upstream responses are parsed in full before the output limit is applied; `wait` timeouts are
  not capped. Impact is self-DoS by a trusted upstream (review finding F-12).
- No OAuth/OIDC for the MCP endpoint; a static bearer token is used. Put it behind a TLS
  reverse proxy and keep the port on LAN/VPN.
