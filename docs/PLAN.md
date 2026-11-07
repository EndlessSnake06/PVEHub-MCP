# PVEHub-MCP — Project Plan

Status legend: `[ ]` open · `[~]` in progress · `[x]` done · `[!]` blocked/deviated (see DECISIONS.md).

## Goal

One MCP server (one container, one endpoint) that exposes Proxmox VE (PVE) and Proxmox
Backup Server (PBS) through their REST APIs, plus shell access to PVE hosts, LXC containers,
QEMU VMs (guest agent) and the PBS host. Access is rights-aware (token permission discovery)
and every tool/category can be blocked through configuration.

## Phase 0 — Setup and audit

- [x] Repository `admin/PVEHub-MCP` confirmed, initial commit present, MIT license.
- [x] Reference projects cloned to `/tmp/ref` and audited (licenses, concepts) — `docs/REUSE_AUDIT.md`.
- [x] Build-vs-fork decision recorded — `docs/DECISIONS.md` D001.
- [x] Architecture and module layout documented — `docs/ARCHITECTURE.md`.
- [x] API facts verified against live, unauthenticated API documentation endpoints:
  PVE `apidoc.js` (4.3 MB) and PBS `apidoc.js` (1.4 MB), plus the official PVE API wiki.
  Verified: `/access/permissions` (PVE + PBS), guest-agent `exec`/`exec-status`,
  `file-read`/`file-write`, task `status`/`log`, PBS datastore/snapshot/prune/gc/verify/namespace,
  auth headers. No PVE/PBS API tokens were supplied; functional verification uses mocks.
- [x] Initial scaffold, `.gitignore`, `.env.example`, `Makefile`, docs.

**Acceptance:** documents committed, decisions justified. ✅

## Phase 1 — Core

- [x] `config.py`: env + YAML settings, profiles, validation, TLS options.
- [x] `policy.py`: categories, allow/deny, read-only, generic path/method rules, exec gates.
- [x] `audit.py`: JSONL audit trail with secret redaction and output limits.
- [x] `clients/pve.py`, `clients/pbs.py`: auth, retries, timeouts, task/UPID polling, schema cache.
- [x] `server.py`: Streamable HTTP at `/mcp`, stdio transport, bearer auth, `/health`.
- [x] Policy unit tests.

**Acceptance:** server starts, `tools/list` works, policy tests green. ✅ (verified 2026-11-07:
43 unit tests, ruff/mypy clean, HTTP `/health` + bearer 401 + MCP initialize against a local server)

## Phase 2 — Capabilities

- [x] PVE + PBS permission discovery (`/access/permissions`), periodic refresh.
- [x] Tool ↔ privilege mapping, registration filtering, per-call pre-check.
- [x] `pvehub_capabilities` tool (available / policy-blocked / missing token rights).
- [x] Tests: full access, audit-only, single-path token, discovery failure.

**Acceptance:** mock permission matrices tested; live discovery requires real tokens (not provided).

## Phase 3 — PVE tools

- [x] Generic `pve_api_schema` + `pve_api_call` with cached `apidoc.js` index.
- [x] Curated cluster/node/guest/snapshot/clone/migrate/storage/backup/restore/task/firewall/HA/network/access tools (40).
- [x] Unit tests with `respx`; category and confirmation coverage.
- [x] Privilege requirements aligned with the live `apidoc.js` permission checks.

## Phase 4 — PBS tools

- [x] Generic `pbs_api_schema` + `pbs_api_call`.
- [x] Datastores, namespaces, snapshots (protect/forget), prune dry-run, GC, verify, jobs, remotes, tasks, health (20).
- [x] Unit tests with `respx`; dry-run and confirm covered.

## Phase 5 — Shell / exec

- [x] `exec_vm` via guest agent (start, poll, stdout/stderr/exit code, timeout).
- [x] `exec_lxc` via SSH + `pct exec` with strict quoting; `exec_host` and `exec_pbs` opt-in.
- [x] File transfer (guest-agent read/write, SFTP for hosts) with size limits.
- [x] Exec gating: category, allowed VMIDs, confirm, output limits, audit.
- [x] Quoting tests with injection payloads (`'; rm -rf /`, backticks, `$()`, newlines) and a fake `pct`.

## Phase 6 — Docker, CI, docs

- [x] Multi-stage Dockerfile (non-root, healthcheck, multi-arch build instructions).
- [x] `docker-compose.yml`, example policies.
- [x] Gitea Actions workflow + `Makefile` fallback.
- [x] README (quickstart, Mermaid diagram, tool catalog, security, client examples).
- [x] `docs/CONFIGURATION.md`, `docs/TOOLS.md` (generated).
- [!] Image build and CI execution not possible in this sandbox (no Docker daemon/runner);
  static validation and local entrypoint installation were performed. See `docs/STATUS.md`.

## Phase 7 — Hardening and review

- [x] Independent review subagent: secrets in logs, policy bypasses, command injection,
  output-size DoS, TLS defaults.
- [x] Fixes + regression tests; `docs/SECURITY_REVIEW.md` (15 findings: 10 fixed, 5 accepted/justified).
- [!] Live integration run (read-only) not run: no PVE/PBS API tokens or SSH keys were supplied.
- [x] Post-review hardening: generic-API writes require `confirm=true`; guest-agent
  exec/file-write hard-denied in the generic bridge; `dry_run` only honored when implemented;
  API paths reject encoded dot segments; command/file bodies hashed in the audit log.

## Phase 8 — Release

- [x] Version `0.1.0`, `CHANGELOG.md`, git tag, local wheel build; image build/push not possible
  without a Docker daemon/registry.
- [x] `docs/STATUS.md` with honest tested/mocked/untested matrix.

## Working agreement

- One branch per phase/area; PRs merged after lint, typecheck and tests are green.
- `docs/PLAN.md` is updated at the end of every phase.
- No secrets in the repository, logs, PR bodies or commits. `.env.example` only.
