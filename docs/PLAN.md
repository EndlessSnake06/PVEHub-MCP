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

- [ ] `config.py`: env + YAML settings, profiles, validation, TLS options.
- [ ] `policy.py`: categories, allow/deny, read-only, generic path/method rules, exec gates.
- [ ] `audit.py`: JSONL audit trail with secret redaction and output limits.
- [ ] `clients/pve.py`, `clients/pbs.py`: auth, retries, timeouts, task/UPID polling, schema cache.
- [ ] `server.py`: Streamable HTTP at `/mcp`, stdio transport, bearer auth, `/health`.
- [ ] Policy unit tests.

**Acceptance:** server starts, `tools/list` works, policy tests green.

## Phase 2 — Capabilities

- [ ] PVE + PBS permission discovery (`/access/permissions`), periodic refresh.
- [ ] Tool ↔ privilege mapping, registration filtering, per-call pre-check.
- [ ] `pvehub_capabilities` tool (available / policy-blocked / missing token rights).
- [ ] Tests: full access, audit-only, single-path token, discovery failure.

## Phase 3 — PVE tools

- [ ] Generic `pve_api_schema` + `pve_api_call` with cached `apidoc.js` index.
- [ ] Curated cluster/node/guest/snapshot/clone/migrate/storage/backup/restore/task/firewall/HA/network/access tools.
- [ ] Unit tests with `respx`; category and confirmation coverage.

## Phase 4 — PBS tools

- [ ] Generic `pbs_api_schema` + `pbs_api_call`.
- [ ] Datastores, namespaces, snapshots (protect/forget), prune dry-run, GC, verify, jobs, remotes, tasks, health.
- [ ] Unit tests with `respx`.

## Phase 5 — Shell / exec

- [ ] `exec_vm` via guest agent (start, poll, stdout/stderr/exit code, timeout).
- [ ] `exec_lxc` via SSH + `pct exec` with strict quoting; `exec_host` and `exec_pbs` opt-in.
- [ ] File transfer (guest-agent read/write, SFTP for hosts) with size limits.
- [ ] Exec gating: category, allowed VMIDs, confirm, output limits, audit.
- [ ] Quoting tests with injection payloads.

## Phase 6 — Docker, CI, docs

- [ ] Multi-stage Dockerfile (non-root, healthcheck, multi-arch build instructions).
- [ ] `docker-compose.yml`, example policies.
- [ ] Gitea Actions workflow + `Makefile` fallback.
- [ ] README (quickstart, Mermaid diagram, tool catalog, security, client examples).
- [ ] `docs/CONFIGURATION.md`, `docs/TOOLS.md` (generated).

## Phase 7 — Hardening and review

- [ ] Independent review subagent: secrets in logs, policy bypasses, command injection,
  output-size DoS, TLS defaults.
- [ ] Fixes + regression tests; `docs/SECURITY_REVIEW.md`.
- [ ] Live integration run (read-only) only if credentials become available; otherwise documented as not run.

## Phase 8 — Release

- [ ] Version `0.1.0`, `CHANGELOG.md`, git tag, image build/push (if registry available).
- [ ] `docs/STATUS.md` with honest tested/mocked/untested matrix.

## Working agreement

- One branch per phase/area; PRs merged after lint, typecheck and tests are green.
- `docs/PLAN.md` is updated at the end of every phase.
- No secrets in the repository, logs, PR bodies or commits. `.env.example` only.
