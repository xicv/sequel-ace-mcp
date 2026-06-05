# Connection reference

## Contents
- Direct connection
- SQLite file
- SSH tunnel
- SSH tunnel + remote Docker container
- TLS server name preservation (through tunnel)
- SSH host key verification
- Credential storage

## Direct connection

```text
sequel-mcp:add_connection
  name=local-dev host=127.0.0.1 port=3306 user=app database=mydb
  ssl=false policyPreset=dev
  → elicits password → stores in macOS Keychain under
    service="sequel-mcp : local-dev" account="app"
```

## SQLite file

```text
sequel-mcp:add_sqlite_connection
  name=local-sqlite path=~/Projects/app/dev.sqlite database=main
  policyPreset=read-only
  → stores only the file path in config; no password or Keychain entry
```

SQLite `database` is the schema name used for policy scope and metadata lookup. Use `main` unless the workflow relies on attached databases. `list_databases` maps to `PRAGMA database_list`; `describe_table` maps to `PRAGMA <schema>.table_info(...)`.

## SSH tunnel

```text
sequel-mcp:add_connection
  name=prod host=10.0.0.5 port=3306 user=readonly
  sshHost=bastion.example.com sshPort=22 sshUser=ops
  sshKeyPath=~/.ssh/id_ed25519
  policyPreset=read-only
```

The server opens a `ssh2` `forwardOut` tunnel to `10.0.0.5:3306` from the bastion. `mysql2` connects to `127.0.0.1:<ephemeral>` on this side. If a separate Keychain password exists under service `sequel-mcp : prod::ssh` it is used as the SSH key passphrase or password.

## SSH tunnel + remote Docker container

For MySQL/MariaDB running **inside** a Docker container on the bastion with no exposed port:

```text
sequel-mcp:add_connection
  name=prod-db host=mysql port=3306 user=app
  sshHost=bastion.example.com sshUser=ops sshKeyPath=~/.ssh/id_ed25519
  sshDockerContainer=mysql-prod sshDockerBridgeTool=nc
  policyPreset=dev
```

The server SSHes in, validates the container name against `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, runs `docker inspect` to confirm it's running, then bridges stdio via `docker exec -i <container> <nc|socat|ncat> <host> <port>`. Pick `bridgeTool` based on what's installed inside the image — `nc` is most common; the server verifies the binary exists with `command -v` before opening sockets.

Allowlist on container names + bridge tool is enforced to block shell-injection through user-supplied values.

## TLS server name preservation

When you tunnel a TLS-enabled MySQL, the server cert SAN is checked against the tunnel's `127.0.0.1`, which always fails. Set `sslServerName`:

```text
sequel-mcp:add_connection
  name=prod host=mysql.internal port=3306 user=app
  sshHost=bastion sshUser=ops sshKeyPath=~/.ssh/id_ed25519
  ssl=true sslServerName=mysql.internal
  policyPreset=read-only
```

`sslServerName` is forwarded to `tls.connect({ servername })` so the certificate SAN check succeeds against the real DB host's name.

## SSH host key verification

Default `sshHostKeyPolicy` is `lenient`: the SHA-256 host key fingerprint is logged on every connect, and `@revoked` entries in `known_hosts` are still rejected. Switch to strict mode on sensitive connections:

```text
sequel-mcp:add_connection ... sshHostKeyPolicy=strict
sequel-mcp:add_connection ... sshKnownHostsPath=~/.ssh/known_hosts
```

In strict mode, an unknown or mismatched host key aborts the tunnel.

## Credential storage

| Item | Location | Notes |
|------|----------|-------|
| MySQL password | macOS Keychain, service `sequel-mcp : <name>`, account `<user>` | `WhenUnlockedThisDeviceOnly`, non-syncable |
| SQLite file path | `~/.config/sequel-mcp/config.json` | No password; path metadata only |
| SSH key passphrase / password | Keychain, service `sequel-mcp : <name>::ssh`, account `<sshUser>` | Same protection class |
| Touch ID gate | `LocalAuthentication` framework via the bundled Swift helper | 15-minute idle re-use window |
| Connection metadata | `~/.config/sequel-mcp/config.json` (`mode 0600`, parent dir `0700`) | No secrets in file |

Passwords never appear in tool arguments, request logs, or the audit DB. The audit DB stores SQL (optionally redacted) but never connection credentials.
