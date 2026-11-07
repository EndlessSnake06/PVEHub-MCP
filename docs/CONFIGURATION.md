# Configuration reference

PVEHub-MCP reads two independent configuration sources:

| Source | File | Purpose |
|---|---|---|
| Settings | `config.yaml` (`PVEHUB_CONFIG_FILE`) | transports, PVE/PBS instances, TLS, SSH, limits |
| Policy | `policy.yaml` (`PVEHUB_POLICY_FILE`) | which tools exist, which API paths/methods are allowed, exec gates |

Both are validated at startup with `extra="forbid"`. A typo in a key is a startup
error, never a silently ignored setting.

## Precedence

```
built-in defaults  <  config.yaml  <  environment (PVEHUB_*)
```

Policy has its own precedence:

```
policy defaults  <  policy.yaml  <  PVEHUB_* policy overrides
```

Details that matter in practice:

- `PVEHUB_CONFIG_FILE` selects the settings file. When unset, `/config/config.yaml`
  and then `./config/config.yaml` are tried; the first existing file wins. No file at
  all is valid — defaults plus environment are used.
- String values inside `config.yaml` support `${VAR}` expansion (recursively, in
  lists and mappings too). A missing variable expands to the empty string. Use this
  to keep token secrets out of the YAML file.
- `policy.yaml` does **not** expand environment variables; use the `PVEHUB_*` policy
  overrides for that.
- The `PVEHUB_PVE_*` / `PVEHUB_PBS_*` single-instance variables modify **the first
  instance** of that list. `PVEHUB_PVE_INSTANCES_JSON` / `PVEHUB_PBS_INSTANCES_JSON`
  replace the whole list instead.
- A missing `policy.yaml` is not an error: the built-in permissive defaults apply
  (`read_only: false`, generic `DELETE` denied, hard-denied paths blocked). Ship a
  policy file in production. `pvehub_capabilities` reports the effective source and
  SHA-256 of the file.
- Policy and settings are read once at startup. Restart after any change.

## Minimal `.env`

```dotenv
PVEHUB_TRANSPORT=http
PVEHUB_HOST=0.0.0.0
PVEHUB_PORT=8080
PVEHUB_MCP_AUTH_TOKEN=<openssl rand -hex 32>

PVEHUB_PVE_URL=https://pve.example.com:8006
PVEHUB_PVE_TOKEN_ID=pvehub@pve!mcp
PVEHUB_PVE_TOKEN_SECRET=<token secret>

PVEHUB_PBS_URL=https://pbs.example.com:8007
PVEHUB_PBS_TOKEN_ID=pvehub@pbs!mcp
PVEHUB_PBS_TOKEN_SECRET=<token secret>

PVEHUB_POLICY_FILE=/config/policy.yaml
```

Startup refuses a non-loopback `PVEHUB_HOST` without `PVEHUB_MCP_AUTH_TOKEN`, rejects
tokens shorter than 16 characters, refuses
`http://` instance URLs unless `PVEHUB_ALLOW_INSECURE_HTTP=true`, and requires at
least one PVE or PBS instance.

## Environment variables

### Server and transport

| Variable | Default | Meaning | Secret |
|---|---|---|---|
| `PVEHUB_CONFIG_FILE` | unset | Path to `config.yaml`; replaces the `/config/config.yaml` → `./config/config.yaml` search | no |
| `PVEHUB_TRANSPORT` | `http` | `http` (Streamable HTTP at `/mcp`) or `stdio` | no |
| `PVEHUB_HOST` | `127.0.0.1` | Bind address for HTTP | no |
| `PVEHUB_PORT` | `8080` | Bind port for HTTP | no |
| `PVEHUB_MCP_AUTH_TOKEN` | unset | Bearer token checked on every `/mcp` request; mandatory for non-loopback binds | **yes** |
| `PVEHUB_ALLOWED_HOSTS` | empty | Comma-separated `Host`/`Origin` allowlist; enables DNS-rebinding protection. Empty disables that protection | no |
| `PVEHUB_POLICY_FILE` | `/config/policy.yaml` | Path to the policy YAML | no |
| `PVEHUB_AUDIT_LOG` | `/data/audit.jsonl` | JSONL audit path. Disable with YAML `audit_log: null`; an empty env value is ignored | no |
| `PVEHUB_AUDIT_INCLUDE_RESULTS` | `false` | Also log tool result bodies (can contain secrets) | no |
| `PVEHUB_STATE_DIR` | `/data` | Cache/state directory (API schema cache) | no |
| `PVEHUB_TASK_TIMEOUT_SECONDS` | `300` | Default timeout for asynchronous PVE/PBS tasks (UPID) | no |
| `PVEHUB_MAX_OUTPUT_BYTES` | `65536` | Hard cap for a tool response (minimum 1024) | no |
| `PVEHUB_CAPABILITIES_REFRESH_SECONDS` | `300` | Interval for token-permission refresh | no |
| `PVEHUB_CAPABILITIES_FAIL_OPEN` | `true` | Register tools when permission discovery fails | no |
| `PVEHUB_WAIT_DEFAULT` | `true` | Default `wait` value for task-returning tools | no |
| `PVEHUB_LOG_LEVEL` | `INFO` | Python log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | no |
| `PVEHUB_ALLOW_INSECURE_HTTP` | `false` | Permit `http://` PVE/PBS URLs (isolated test environments only) | no |

### PVE instance (single-instance shortcut)

| Variable | Default | Meaning | Secret |
|---|---|---|---|
| `PVEHUB_PVE_NAME` | `default` | Instance name used by the `instance` argument | no |
| `PVEHUB_PVE_URL` | — (required) | `https://host:8006`, no trailing slash | no |
| `PVEHUB_PVE_TOKEN_ID` | — (required) | `USER@REALM!TOKENID` | no |
| `PVEHUB_PVE_TOKEN_SECRET` | — (required) | API token secret | **yes** |
| `PVEHUB_PVE_VERIFY` | `true` | TLS verification; environment accepts booleans only | no |
| `PVEHUB_PVE_CA_FILE` | unset | PEM CA bundle (private CA) | no |
| `PVEHUB_PVE_FINGERPRINT` | unset | SHA-256 certificate fingerprint | no |
| `PVEHUB_PVE_TIMEOUT_SECONDS` | `30` | HTTP timeout | no |
| `PVEHUB_PVE_MAX_RETRIES` | `2` | Retries for idempotent requests | no |
| `PVEHUB_PVE_INSTANCES_JSON` | unset | JSON array of instance objects; replaces the list | **contains secrets** |

### PBS instance (single-instance shortcut)

Same keys with the `PBS` prefix and PBS defaults:

| Variable | Default | Meaning | Secret |
|---|---|---|---|
| `PVEHUB_PBS_NAME` | `default` | Instance name | no |
| `PVEHUB_PBS_URL` | — (required) | `https://host:8007` | no |
| `PVEHUB_PBS_TOKEN_ID` | — (required) | `USER@REALM!TOKENID` | no |
| `PVEHUB_PBS_TOKEN_SECRET` | — (required) | API token secret | **yes** |
| `PVEHUB_PBS_VERIFY` | `true` | TLS verification (boolean via env) | no |
| `PVEHUB_PBS_CA_FILE` | unset | PEM CA bundle | no |
| `PVEHUB_PBS_FINGERPRINT` | unset | SHA-256 certificate fingerprint | no |
| `PVEHUB_PBS_TIMEOUT_SECONDS` | `30` | HTTP timeout | no |
| `PVEHUB_PBS_MAX_RETRIES` | `2` | Retry count | no |
| `PVEHUB_PBS_INSTANCES_JSON` | unset | JSON array of PBS instance objects | **contains secrets** |

### SSH targets

| Variable | Default | Meaning | Secret |
|---|---|---|---|
| `PVEHUB_SSH_USER` | `pvehub` | Default SSH user for all nodes | no |
| `PVEHUB_SSH_KEY_PATH` | `/ssh/id_ed25519` | Private key inside the container | no (key material!) |
| `PVEHUB_SSH_KNOWN_HOSTS` | `/ssh/known_hosts` | known_hosts file | no |
| `PVEHUB_SSH_PORT` | `22` | Default SSH port | no |
| `PVEHUB_SSH_STRICT_HOST_KEY_CHECKING` | `true` | Verify host keys against known_hosts | no |
| `PVEHUB_SSH_CONNECT_TIMEOUT` | `10` | Connect/login timeout in seconds | no |
| `PVEHUB_SSH_NODES_JSON` | unset | JSON object `{"<pve-node>": {"host": "...", ...}}` | no |
| `PVEHUB_SSH_PBS_HOST` | unset | PBS host for `exec_pbs` / PBS file tools | no |
| `PVEHUB_SSH_PBS_USER` | unset | PBS SSH user (target default `pvehub`, not `ssh.user`) | no |
| `PVEHUB_SSH_PBS_KEY_PATH` | unset | PBS key path (target default `/ssh/id_ed25519`) | no |

### Policy overrides

These are applied on top of `policy.yaml` (lists replace, they do not merge).

| Variable | Default | Meaning |
|---|---|---|
| `PVEHUB_READ_ONLY` | `false` | Block every non-read tool and non-GET generic call |
| `PVEHUB_DENY_TOOLS` | empty | Comma-separated tool names to remove |
| `PVEHUB_ALLOW_TOOLS` | empty | Comma-separated exclusive allowlist (non-empty = only these tools) |
| `PVEHUB_DENY_CATEGORIES` | empty | Comma-separated: `read`, `lifecycle`, `write`, `destructive`, `exec`, `generic` |
| `PVEHUB_GENERIC_DENY_PATHS` | built-in ticket/console list | Comma-separated path patterns; replaces the list, hard-denied paths still apply |
| `PVEHUB_GENERIC_DENY_METHODS` | `DELETE` | Comma-separated HTTP methods denied on the generic bridge |
| `PVEHUB_EXEC_HOST` | `false` | PVE host shell |
| `PVEHUB_EXEC_LXC` | `true` | `pct exec` into LXC containers |
| `PVEHUB_EXEC_VM` | `true` | QEMU guest-agent exec |
| `PVEHUB_EXEC_PBS_HOST` | `false` | PBS host shell |
| `PVEHUB_EXEC_ALLOWED_VMIDS` | `100-199` | Range list (`100-199,300`) for VMID-scoped operations |
| `PVEHUB_EXEC_TIMEOUT_SECONDS` | `60` | Default command timeout |
| `PVEHUB_EXEC_MAX_OUTPUT_BYTES` | `65536` | Per-command output cap |
| `PVEHUB_REQUIRE_CONFIRM` | `destructive,exec` | Categories that require `confirm=true` |

## `config.yaml` reference

```yaml
transport: http            # http | stdio
host: 0.0.0.0
port: 8080
mcp_auth_token: ${PVEHUB_MCP_AUTH_TOKEN}
allowed_hosts: ["pvehub.example.com", "192.168.1.20:8080"]

pve:
  - name: pve1
    url: https://pve1.example.com:8006
    token_id: pvehub@pve!mcp
    token_secret: ${PVE1_TOKEN_SECRET}
    api_path: /api2/json
    timeout_seconds: 30
    max_retries: 2
    verify: true
    # ca_file: /config/pve-ca.pem
    # fingerprint: "sha256:AB:CD:..."
  - name: pve2
    url: https://pve2.example.com:8006
    token_id: pvehub@pve!mcp
    token_secret: ${PVE2_TOKEN_SECRET}

pbs:
  - name: pbs1
    url: https://pbs1.example.com:8007
    token_id: pvehub@pbs!mcp
    token_secret: ${PBS1_TOKEN_SECRET}
    # api_path defaults to /api2/extjs for PBS

ssh:
  user: pvehub
  key_path: /ssh/id_ed25519
  known_hosts: /ssh/known_hosts
  port: 22
  strict_host_key: true
  connect_timeout: 10
  nodes:
    pve1:
      host: 10.0.0.11
    pve2:
      host: 10.0.0.12
      user: root
  pbs:
    host: 10.0.0.20

policy_file: /config/policy.yaml
audit_log: /data/audit.jsonl
audit_include_results: false
state_dir: /data
task_timeout_seconds: 300
max_output_bytes: 65536
capabilities_refresh_seconds: 300
capabilities_fail_open: true
wait_default: true
log_level: INFO
allow_insecure_http: false
```

### Settings keys

| Key | Type | Default | Notes |
|---|---|---|---|
| `transport` | `http` \| `stdio` | `http` | `http` serves `/mcp` and `/health` |
| `host` | string | `127.0.0.1` | non-loopback requires `mcp_auth_token` |
| `port` | int | `8080` | |
| `mcp_auth_token` | string (secret) | unset | constant-time bearer check on `/mcp` |
| `allowed_hosts` | list[str] | `[]` | enables DNS-rebinding protection; must contain the hostnames clients use |
| `pve` | list[instance] | `[]` | at least one PVE or PBS instance required |
| `pbs` | list[instance] | `[]` | |
| `ssh` | mapping | see below | optional; without it host/LXC/file tools stay hidden |
| `policy_file` | string | `/config/policy.yaml` | |
| `audit_log` | string \| null | `/data/audit.jsonl` | `null` disables audit |
| `audit_include_results` | bool | `false` | |
| `state_dir` | string | `/data` | |
| `task_timeout_seconds` | float | `300` | |
| `max_output_bytes` | int | `65536` | ≥ 1024 |
| `capabilities_refresh_seconds` | int | `300` | |
| `capabilities_fail_open` | bool | `true` | |
| `wait_default` | bool | `true` | |
| `log_level` | string | `INFO` | |
| `allow_insecure_http` | bool | `false` | |

### Instance keys (`pve[]` / `pbs[]`)

| Key | Type | Default | Notes |
|---|---|---|---|
| `name` | string | `default` | unique per group; used by the `instance` tool argument |
| `url` | string | required | absolute `https://` URL, trailing slash stripped |
| `token_id` | string | required | must contain `@` and `!` (`USER@REALM!TOKENID`) |
| `token_secret` | string (secret) | required | non-empty |
| `api_path` | string | `/api2/json` (PVE), `/api2/extjs` (PBS) | must start with `/`, no trailing `/` |
| `timeout_seconds` | float | `30` | |
| `max_retries` | int | `2` | |
| `verify` | bool \| string | `true` | `true`, `false`, or a CA bundle path (YAML only) |
| `ca_file` | string | unset | PEM CA bundle |
| `fingerprint` | string | unset | SHA-256, with or without `sha256:` and colons |

### SSH keys

| Key | Type | Default | Notes |
|---|---|---|---|
| `user` | string | `pvehub` | |
| `key_path` | string | `/ssh/id_ed25519` | must be readable by UID 10001 |
| `known_hosts` | string | `/ssh/known_hosts` | required while `strict_host_key: true` |
| `port` | int | `22` | |
| `strict_host_key` | bool | `true` | disable only in isolated test environments |
| `connect_timeout` | float | `10` | |
| `nodes` | mapping | `{}` | key = PVE node name, value = target |
| `pbs` | target or null | unset | PBS host target |

Target keys (under `nodes.<name>` and `pbs`): `host` (required), `port`, `user`,
`key_path`, `known_hosts`, `strict_host_key`, `connect_timeout`, `sudo`.
Entries under `nodes.<name>` inherit omitted values from `ssh.*`; the separate
`ssh.pbs` target does **not** inherit from `ssh.*` and falls back to the target
defaults (`pvehub`, `/ssh/id_ed25519`, port 22) — set `user`/`key_path` explicitly
when they differ. `sudo: true` wraps `pct exec` as `sudo -n` (passwordless sudo must
be configured on the node).

The node key must match the PVE node name exactly (`pvesh get /nodes`). SSH is only
used for the node that actually hosts the guest; the server does not guess.

## Multiple instances

```yaml
pve:
  - name: prod
    url: https://pve-prod.example.com:8006
    token_id: pvehub@pve!mcp
    token_secret: ${PROD_TOKEN_SECRET}
  - name: lab
    url: https://pve-lab.example.com:8006
    token_id: pvehub@pve!mcp
    token_secret: ${LAB_TOKEN_SECRET}
    verify: false        # lab only
```

Every tool accepts an optional `instance` argument; without it the first instance
of the group is used. Unknown names return an error that lists the configured names.
Names must be unique within a group.

Environment-only alternative (one line, contains secrets):

```bash
PVEHUB_PVE_INSTANCES_JSON='[{"name":"prod","url":"https://pve-prod:8006","token_id":"pvehub@pve!mcp","token_secret":"..."}]'
```

`PVEHUB_PVE_INSTANCES_JSON` replaces the entire `pve` list, so it wins over
`PVEHUB_PVE_URL`/`_TOKEN_ID`/`_TOKEN_SECRET`.

## TLS, CA bundles and fingerprint pinning

| Setting | Effect |
|---|---|
| `verify: true` (default) | system CA store, hostname verification |
| `verify: /path/ca.pem` or `ca_file: /path/ca.pem` | verify against a private CA bundle |
| `fingerprint: "sha256:AB:CD:..."` | pin the peer certificate's SHA-256 on every handshake |
| `verify: false` | no chain and no hostname verification; logs a warning at startup |

Fingerprint pinning does not disable hostname/chain checks: with `verify: true` the
certificate must still validate and match the URL hostname. For a self-signed
Proxmox certificate either provide its CA (`ca_file`) or explicitly combine
`verify: false` with `fingerprint` (pinning still detects a swapped certificate, but
a hostname mismatch is no longer checked).

`http://` URLs are rejected unless `allow_insecure_http: true`.

## Policy reference

```yaml
read_only: false

tools:
  deny: []          # exact tool names, removed at registration
  allow: []         # non-empty => exclusive allowlist

categories:
  deny: [destructive]

generic_api:
  deny_paths:
    - /access/ticket
    - /access/users/*/token/*
    - /access/users/*/token
    - /nodes/*/vncshell
    - /nodes/*/spiceshell
    - /nodes/*/termproxy
    - /nodes/*/qemu/*/monitor
  deny_methods: [DELETE]

exec:
  host: false
  lxc: true
  vm: true
  pbs_host: false
  allowed_vmids: ["100-199"]
  command_denylist: ["rm -rf /", "mkfs*", "dd if=*", ":(){:|:&};:", "shutdown*", "reboot*"]
  timeout_seconds: 60
  max_output_bytes: 65536
  files:
    allowed_roots: []

safety:
  require_confirm_for: [destructive, exec]
  dry_run_supported: true
```

| Key | Type | Default | Semantics |
|---|---|---|---|
| `read_only` | bool | `false` | only `read` and `generic` tools are registered; generic calls are GET-only |
| `tools.deny` | list[str] | `[]` | exact tool names, checked after `tools.allow` |
| `tools.allow` | list[str] | `[]` | non-empty list restricts registration to these names |
| `categories.deny` | list[category] | `[]` | categories are `read`, `lifecycle`, `write`, `destructive`, `exec`, `generic` |
| `generic_api.deny_paths` | list[str] | ticket/console list | `fnmatch` patterns, case-insensitive; a pattern without trailing `*` also covers child paths |
| `generic_api.deny_methods` | list[str] | `[DELETE]` | uppercase; allowed values `GET`, `POST`, `PUT`, `DELETE`, `PATCH` |
| `exec.host` | bool | `false` | enables PVE host shell tools |
| `exec.lxc` | bool | `true` | enables `pct exec` tools |
| `exec.vm` | bool | `true` | enables guest-agent exec tools |
| `exec.pbs_host` | bool | `false` | enables PBS host shell tools |
| `exec.allowed_vmids` | list[str] | `["100-199"]` | ranges `100-199`, single IDs; applies to **every** write/lifecycle/destructive/exec call that carries a `vmid` |
| `exec.command_denylist` | list[str] | see above | `fnmatch` patterns; a plain string also matches as substring |
| `exec.timeout_seconds` | int | `60` | command timeout |
| `exec.max_output_bytes` | int | `65536` | per-command output cap |
| `exec.files.allowed_roots` | list[str] | `[]` | path prefixes for file tools; empty means unrestricted |
| `safety.require_confirm_for` | list[category] | `[destructive, exec]` | calls must pass `confirm=true` unless `dry_run=true` is accepted |
| `safety.dry_run_supported` | bool | `true` | allow `dry_run=true` to skip the confirm requirement |

Always hard-denied through the generic bridge, regardless of policy: `/access/ticket`,
`/access/users/*/token`, `/access/users/*/token/*`, `/nodes/*/vncshell`,
`/nodes/*/spiceshell`, `/nodes/*/termproxy`, `/nodes/*/qemu/*/monitor`. These return
session tickets or interactive consoles and would bypass tool-level gating.

Policy is enforced twice: at registration (blocked tools do not appear in
`tools/list`) and on every call. Changing policy requires a restart.

### Policy examples

| File | Intent |
|---|---|
| `config/examples/readonly.yaml` | monitoring only: `read_only: true`, all mutating categories denied, no exec |
| `config/examples/operator.yaml` | day-to-day VM/LXC work: destructive denied, host/PBS shell off, generic `DELETE` denied |
| `config/examples/admin.yaml` | full access: destructive allowed, host/PBS shell enabled, generic `DELETE` allowed, hard-denied paths still blocked |

Copy one to `config/policy.yaml` and adjust it. See also `docs/TOOLS.md` for which
tools exist in the current tree.

## Audit

`audit_log` (`/data/audit.jsonl` in the container) receives one JSON object per tool
call:

```json
{"ts":"2026-11-07T10:00:00Z","tool":"pve_api_call","category":"generic","status":"ok","instance":"pve1","target":"path=/nodes","params":{"path":"/nodes"},"duration_ms":42}
```

- `status` is `ok`, `denied` (policy) or `error`.
- Parameter keys matching `pass`, `password`, `secret`, `token`, `api_key`,
  `private_key`, `authorization`, `cookie`, `csrf` are replaced with `***`; bearer
  tokens, `PVEAPIToken=`/`PBSAPIToken=` headers, private-key blocks and
  `password=`/`token=` query values are redacted inside strings.
- Result bodies are only written with `audit_include_results: true`.
- Writes are append-only and best-effort: an unwritable path disables auditing with
  a warning instead of failing calls. There is no built-in rotation; use logrotate
  or a log shipper on the host.
- The file must be writable by UID 10001 (the named volume is).

## Capabilities and tool visibility

At startup the server reads `GET /access/permissions` from each PVE/PBS instance and
maps the token's effective privileges onto the declared tool requirements
(`pve=[("VM.Audit", "/vms/{vmid}")]`).

- A tool whose requirements cannot be met by any configured instance is not
  registered; `pvehub_capabilities` lists it under `tools.blocked` with a reason
  (`policy: ...`, `capability: ...`, `prerequisite: ...`).
- `capabilities_fail_open: true` keeps tools registered when discovery fails (network
  error, old PBS). Each call still checks the concrete privilege and returns
  `permission_denied` instead of a raw 403. Set it to `false` for strict hiding.
- Permissions are refreshed every `capabilities_refresh_seconds`; the registered
  tool set is fixed for the process lifetime (restart to re-evaluate).
- Required token privileges for a read-only start: PVE `Datastore.Audit`,
  `Sys.Audit`, `VM.Audit`; PBS `Datastore.Audit`, `Sys.Audit`. For guest exec/files:
  PVE `VM.GuestAgent.Unrestricted`, `VM.GuestAgent.FileRead`, `VM.GuestAgent.FileWrite`,
  `VM.GuestAgent.Audit`.

## Container notes

- Writable paths: `/data` (named volume). `/config` and `/ssh` are mounted read-only.
- The process runs as UID/GID `10001`; SSH keys must be readable by that UID
  (`chown 10001:10001 ssh/id_ed25519 && chmod 600 ssh/id_ed25519`).
- The root filesystem is read-only in `docker-compose.yml`; `/tmp` is a tmpfs.
- `PVEHUB_CONFIG_FILE=/config/config.yaml` is baked into the image, so a missing
  `config/config.yaml` simply means "environment only".
- `/health` is unauthenticated and returns `status`, `version`, `transport` and the
  tool count. `status` is `degraded` when capability discovery failed; the endpoint
  still answers `200` so orchestrators do not restart a working server.
- In `stdio` transport there is no HTTP listener; the image healthcheck consequently
  reports `unhealthy`. Use stdio only via `docker run -i`, where that is harmless.
- CLI flags override environment values: `--transport`, `--host`, `--port`,
  `--config`, `--env-file`, `--log-level`, `--version`.

## Secrets checklist

Values that must never be committed or logged:

- `PVEHUB_MCP_AUTH_TOKEN`
- `PVEHUB_PVE_TOKEN_SECRET`, `PVEHUB_PBS_TOKEN_SECRET`
- token secrets inside `PVEHUB_PVE_INSTANCES_JSON` / `PVEHUB_PBS_INSTANCES_JSON`
- `token_secret` entries in `config.yaml`
- the SSH private key under `/ssh`

`.env` is git-ignored and excluded from the Docker build context. `config.yaml` can
reference `${VAR}` so the file itself stays secret-free.
