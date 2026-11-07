# Independent security review — PVEHub-MCP 0.1.0

- **Repository:** `https://git.mls4tech.net/admin/PVEHub-MCP.git`
- **Reviewed revision:** `integration/v0.1.0` at `88cb2a7`
- **Review branch:** `fix/security-review`
- **Review type:** independent code review (reviewer did not author the code)
- **Date:** 2026-11-07

## Scope and method

Reviewed the complete request path: configuration and secrets (`config.py`), policy engine
(`policy.py`), capability pre-checks (`capabilities.py`), audit/redaction (`audit.py`), HTTP
and TLS clients (`clients/base.py`, `clients/pve.py`, `clients/pbs.py`, `clients/ssh.py`,
`tls.py`), all curated PVE/PBS tools (`tools/*.py`), MCP assembly/auth/health (`server.py`),
packaging (`Dockerfile`, `docker-compose.yml`, `.dockerignore`, `.env.example`,
`config/examples/*.yaml`) and CI (`.gitea/workflows/ci.yml`).

Method: manual data-flow review from MCP tool arguments to HTTP/SSH sinks; targeted probes of
URL normalisation (Python `httpx`/`urllib` semantics) and path matching; comparison of every
curated tool's declared `pve=`/`pbs=` privileges against the live apidoc schema snapshots
(`/tmp/apidoc_test.js`, `/tmp/pbsdoc_test.js`); focused regression tests with `respx` and
monkeypatched SSH/SFTP. No live PVE/PBS/SSH credentials or hosts were used.

Baseline at `88cb2a7`: `ruff` clean, `mypy` clean, `pytest` 218 passed / 2 skipped.

## Findings

Severity: **critical / high / medium / low / info**. Status: fixed, open, accepted-risk.

| ID | Sev | Location | Finding / evidence | Status | Fix and regression test |
|---|---|---|---|---|---|
| F-01 | **High** | `clients/base.py:56`, `tools/pve_guests.py:278,329`, `tools/pve_tasks.py:84,107,131`, `tools/pve_storage.py:84,112`, `tools/pve_network.py:110` | **API path traversal in curated tools.** User-controlled path segments (`snapname`, `upid`, `node`, `iface`, `storage`) were interpolated into API paths without validation; `httpx` normalises literal `..` before sending. Pre-fix probe: `pve_guest_snapshot_delete(vmid=100, snapname="../../../../../access/users/root@pam", confirm=true)` issued `DELETE https://…/api2/json/access/users/root@pam`; `pve_task_stop(node="pve1", upid="../../../access/users/root@pam")` issued the same DELETE. This escapes the intended resource (cross-VMID snapshot delete/rollback outside `exec.allowed_vmids`) and bypasses the generic-API hard-deny/`deny_methods` rules (e.g. token revocation, user deletion). | **fixed** | `validation.api_segment()` / `validation.task_upid()` applied to every user-controlled segment; defence-in-depth `quote_path()` rejects `.`/`..`, backslash and control characters. Tests: `test_snapshot_delete_rejects_traversal`, `test_snapshot_rollback_rejects_traversal`, `test_task_stop_rejects_traversal`, `test_task_status_rejects_traversal`, `test_storage_status_rejects_node_traversal`, `test_quote_path_rejects_dot_segments_and_backslashes`, `test_api_segment_rejects_traversal_and_url_metacharacters`. |
| F-02 | Medium | `policy.py:264-288` | **`exec.allowed_vmids` bypass through generic API parameters.** The generic bridge enforced the VMID range only for VMIDs in the URL path. `pve_api_call(POST, "/nodes/pve1/qemu", params={"vmid": 5000})` (create VM) and `POST /nodes/pve1/vzdump` (backup) accepted VMIDs outside `100-199`. | **fixed** | `_check_vmid_params()` checks `vmid`/`newid` in params for non-GET calls and requires ints. Tests: `test_generic_vmid_parameters_respect_allowed_vmids`. |
| F-03 | Medium | `server.py:570`, `audit.py:15-32` | **Secrets in audit log.** `_target()` wrote the raw command into the audit entry (`target=command=…`) without redaction; for `exec_pbs` (no `node`) this is the recorded target. Command strings also leaked JSON-style `"password":"…"`, `Authorization: Basic …` and `X-Token:` values; `content_base64` file payloads were logged in clear. Redaction could raise on deeply nested params despite the "audit never breaks a tool call" contract. | **fixed** | `_target()` redacts; added Basic-auth and JSON/form secret-value patterns; `content_base64` is a secret key; recursion depth capped; `_safe_redact` keeps writes best-effort. Tests: `test_audit_target_is_redacted`, `test_redact_command_strings_with_json_and_basic_auth`, `test_redact_bulk_file_payload`, `test_redact_deeply_nested_value_does_not_overflow`. |
| F-04 | Medium | `server.py:511-543` | **DNS-rebinding protection disabled for the default loopback bind.** `allowed_hosts` defaults to `[]`, and the old code then set `enable_dns_rebinding_protection=False`. The default deployment binds `127.0.0.1` and needs no bearer token, so a malicious web page could reach the MCP endpoint through DNS rebinding and read tool results. | **fixed** | Loopback binds now enable protection with loopback Host patterns; non-loopback binds without an allowlist keep the opt-in behaviour and log a warning. Evidence: ASGI POST `/mcp` with `Host: evil.example` → **421**, with `Host: 127.0.0.1:8080` → not 421. Test: `test_http_rejects_foreign_host_header_on_loopback`, `test_loopback_bind_enables_dns_rebinding_protection`. |
| F-05 | Medium | `resources.py:17-24` | **MCP resources bypass tool policy.** `proxmox://nodes`, `proxmox://guests`, `proxmox://storage` and `pbs://datastores` were registered unconditionally. A policy with `tools.allow` restricted to one tool, or `categories.deny: [read]`, still let any MCP client list every guest, node and datastore through `resources/read` (and without audit). | **fixed** | Resource registration is gated by the same `tool_decision(name, "read")` used for tools (`pvehub_resource_*`). Tests: `test_resources_respect_tool_allowlist`, `test_resources_respect_denied_read_category`, `test_resources_registered_by_default`. |
| F-06 | Medium | `tools/files.py:66-81,252,288` | **Symlink escape of `exec.files.allowed_roots`.** `policy.check_file_path()` compares the literal path; a symlink inside an allowed root pointing at `/etc/shadow` or `/root/.ssh/authorized_keys` passed the prefix check and SFTP followed it. | **fixed** | When roots are configured, the SFTP server resolves the path (`realpath`, parent for writes) and the resolved path is re-checked before the transfer. Tests: `test_file_pull_host_rejects_symlink_escape`, `test_file_push_host_rejects_symlinked_parent`, `test_file_path_policy_rejects_dot_segments`. Residual TOCTOU risk documented below. |
| F-07 | Medium | `.env.example:10`, `config.py:211-217` | **Shipped default bearer token / empty token accepted.** The quickstart copies `.env.example` with `PVEHUB_MCP_AUTH_TOKEN=change-me` and `PVEHUB_HOST=0.0.0.0`; leaving the placeholder yields a well-known credential on a non-loopback bind. Separately, YAML `mcp_auth_token: ""` produced `expected = "Bearer "` and accepted a request with that header (env path already treated empty as unset). | **fixed** | Template token is empty (startup fails until an operator generates one); `Settings` rejects blank/whitespace tokens. Tests: `test_env_example_requires_explicit_bearer_token`, `test_empty_bearer_token_is_rejected`. |
| F-08 | Low | `clients/ssh.py:72-92` | **SSH connection cache ignored host-key policy.** Connections were cached by `(host, port, user)`, so a target with `strict_host_key: false` and another target for the same address with `strict_host_key: true` shared one connection — whichever connected first decided whether host keys were verified. | **fixed** | Cache key includes key path, known_hosts path and strict flag. Test: `test_ssh_cache_key_includes_host_key_policy`. |
| F-09 | Low | `clients/ssh.py:201` | **Documented `sudo: true` was ignored** for `pct exec` (the tool never passed `sudo`, the pool never read `target.sudo`), so LXC exec failed on nodes that rely on passwordless sudo instead of working as documented. Functional, not an escalation (the config is explicit). | **fixed** | Pool uses `sudo or target.sudo`. Test: `test_exec_lxc_honours_configured_sudo`. |
| F-10 | Low | `policy.py:462-473` | **Generic secret-parameter filter only matched exact keys**, so `"new_password"`, `"client_secret"`, `"apiKey"` passed. | **fixed** | Substring matching for password/passwd/secret/token/api_key/apikey. Test: `test_generic_secret_parameters_reject_prefixed_keys`. |
| F-11 | Low | `capabilities.py:201-278` | **Privilege pre-check cannot express the API's "any-of"/ownership semantics.** Examples from the apidoc comparison: `GET agent/file-read` accepts `VM.GuestAgent.FileRead` **or** `Unrestricted`; `pve_storage_*` accept `Datastore.Audit` **or** `AllocateSpace`; PBS `snapshot forget` accepts `Datastore.Modify` **or** `Datastore.Prune`+owner; `pbs_job_run(verify)` needs `Datastore.Verify`, not `Modify`. The pre-check model only supports AND. | **open (accepted-risk)** | Fail-closed: a token holding only the alternative privilege sees the tool hidden, or the API returns 403 when the pre-check is too permissive. PVE/PBS remain the enforcement point. Full fix needs an any-of requirement model (out of scope for this review). |
| F-12 | Low | `clients/base.py:158-196`, `tools/pve_generic.py:48-55` | **Unbounded upstream response / wait timeout.** JSON responses are parsed in full before `max_output_bytes` truncation (a compromised/misbehaving PVE/PBS can force large allocations); `pve_api_call(wait=true, timeout=…)` accepts arbitrarily large timeouts. Async handlers mean this is self-DoS, not cross-request exhaustion. | **open (accepted-risk)** | Documented as hardening; no test because it requires changing response streaming. Recommend a `max_response_bytes` cap and a 3600 s wait cap in a follow-up. |
| F-13 | Low | `server.py:528-531` | `/health` is unauthenticated and exposes `status`, `version`, `transport` and tool count. Documented in `docs/CONFIGURATION.md`; useful for orchestrators, low information value. | **accepted-risk** | Keep; operator can block `/health` at the reverse proxy if required. |
| F-14 | Info | `Dockerfile:16,20`, `.gitea/workflows/ci.yml` | Base images are pinned by tag (`python:3.12-slim`, `uv:0.12.23`) but not by digest; GitHub/Gitea actions are referenced by tag (`actions/checkout@v4`), not commit SHA. Supply-chain hardening only. | **accepted-risk** | Recommend digest pinning + Renovate/Dependabot; not changed in this review. |
| F-15 | Info | `config.py:206`, `capabilities.py:213-268` | `capabilities_fail_open` defaults to `true`, so a failed `/access/permissions` call keeps tools visible. This is **not** an authorisation bypass: every actual API request still runs with the PVE/PBS token and the API enforces its ACL. | **accepted-risk** | Documented behaviour; operators wanting strict hiding set `capabilities_fail_open: false`. |

### Severity and status summary

| Severity | Total | Fixed | Open/accepted |
|---|---|---|---|
| High | 1 | 1 | 0 |
| Medium | 6 | 6 | 0 |
| Low | 6 | 3 | 3 |
| Info | 2 | 0 | 2 |
| **Total** | **15** | **10** | **5** |

## Verifications that found no defect (positive controls)

- **Shell/argument injection (LXC/host/PBS):** `pct exec <int> -- sh -c <shlex.quote(cmd)>` is built with an integer VMID and `shlex.quote`; existing round-trip tests with a fake `pct` prove payloads such as `'; rm -rf /`, `$(id)`, backticks and embedded newlines stay one argument. Host/PBS commands are intentionally arbitrary (opt-in) and gated by `confirm=true` plus the command denylist (best-effort, documented).
- **Guest-agent exec:** command array `["/bin/sh", "-c", command]` is sent as JSON to `/agent/exec`; no local shell and no server-side string concatenation.
- **Generic API hard deny:** `/access/ticket`, token endpoints, `vncshell`, `spiceshell`, `termproxy`, QEMU `monitor` remain denied after percent-decoding (single/double), case folding, duplicate-slash collapse and dot-segment rejection; a literal or encoded `?`/`#` is encoded by `quote_path`, so query/fragment smuggling into the path is not possible.
- **Generic method/read-only gates:** method is upper-cased before comparison; `read_only` allows only GET; `deny_methods` is validated; tool allow/deny/category deny are re-evaluated at call time (`check_call`), not only at registration.
- **TLS:** default is `verify=true`; `http://` instance URLs require explicit `allow_insecure_http`; `verify=false` logs a warning; fingerprint pinning is SHA-256 only and implemented for both `wrap_socket` and the `wrap_bio` path used by httpx/httpcore (verified that the instance `do_handshake` hook can be installed; no live TLS handshake was run).
- **Authentication:** bearer comparison uses `secrets.compare_digest`; non-loopback HTTP bind without a token is refused; empty/whitespace tokens are now refused.
- **Docker/packaging:** non-root UID 10001, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, no Docker socket, no build args/secrets, `.dockerignore` excludes `.env`, SSH material, config and tests; CI has no secret usage and no image push.
- **Secret handling in code:** token secrets use `pydantic.SecretStr`; `pve_guest_config` and `pbs_remotes_list` pass results through `redact_value`; error messages contain upstream status/path but not credentials.

## Not fixed / justified (`nicht behoben / begründet`)

- **F-11** — The capability pre-check is advisory. It can hide a tool from a token that holds an equivalent API privilege, or allow a call that the API then rejects with 403. Both directions are fail-closed; changing `Privilege` to an any-of/ownership model is a design change beyond this review. PVE/PBS enforce the real ACL.
- **F-12** — A response-size/streaming cap and a hard wait-timeout ceiling are worthwhile hardening but require changing the HTTP client's buffering model. The upstream is a trusted, operator-configured PVE/PBS; the impact is self-DoS, so it is recorded rather than patched under the timebox.
- **F-13** — `/health` metadata is intentional and documented; it contains no credentials, guest names or topology.
- **F-14** — Tag-pinned base images/actions are a supply-chain hardening item, not an exploitable defect in this code; changing pins without a dependency-update process risks stale images.
- **F-15** — `capabilities_fail_open` cannot bypass the PVE/PBS ACL; every request is still made with the configured token. Operators can set it to `false` for strict hiding.
- **TOCTOU in F-06** — The SFTP `realpath` check closes the static symlink escape; a local attacker who can rewrite the path between resolution and `open` could still race it. Fully closing this requires `openat`-style handling that the SFTP protocol does not expose to this client. The threat model is a trusted PVE node; residual risk is documented.

## Unverified due to environment/timebox

- Docker image build and `docker compose config`/runtime hardening were inspected statically only; no Docker daemon was used.
- CI workflow was reviewed statically; it was not executed.
- No live PVE/PBS API calls were made; privilege comparisons used the provided apidoc snapshots (`/tmp/apidoc_test.js`, `/tmp/pbsdoc_test.js`).
- No live SSH/SFTP/TLS handshake was performed; SSH/SFTP and fingerprint-pinning logic was exercised with mocks/unit tests only.

## Verification commands (final state of `fix/security-review`)

```
$ uv run ruff check src tests
All checks passed!

$ uv run mypy src
Success: no issues found in 39 source files

$ uv run pytest -o addopts="" -q
247 passed, 2 skipped
```

New regression coverage lives in `tests/test_security_review.py` (29 tests) plus updated
SFTP expectations in `tests/test_tools_exec_files.py`.

Post-merge integration gate after the follow-up hardening (generic-API confirm, hard-denied
guest-agent exec/file-write, dry-run signature check, encoded-dot-segment rejection):
`250 passed, 2 skipped`, `ruff` clean, `mypy` clean (39 source files). The review baseline
and the evidence above refer to `fix/security-review`; the merged tree is `integration/v0.1.0`.

## Addendum — 0.1.1 (2026-11-07)

- **F-13** (Low, previously accepted-risk) is resolved by design change, not accepted:
  `GET /health` no longer exposes `status`, `version`, `transport` or the tool count; it
  is a minimal liveness probe (`{"status": "ok"}`, always 200 while the process runs).
  The full health body moved to the authenticated `GET /ready` endpoint (503 while
  degraded), which the container healthchecks and the CI compose smoke now use (issues
  #23, #24; `docs/DECISIONS.md` D021). Regression coverage: the health-split tests in
  `tests/test_server.py` (exact `/health` body, `/ready` 401/200/503, dev-mode open).
- The per-client attribution follow-up of issue #16 (named MCP tokens, `client` field in
  the audit log) shipped in the same 0.1.1 release (D019, `PVEHUB_MCP_AUTH_TOKENS`).
