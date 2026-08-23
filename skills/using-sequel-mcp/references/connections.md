# Connection reference

## Contents
- Adding connections in 0.10.0
- Direct connection
- SQLite file
- SSH tunnel
- SSH tunnel + remote Docker container
- TLS through a tunnel (server name + private CA)
- SSH host key verification
- Credential storage

## Adding connections in 0.10.0

The interactive `add_connection` tool is not yet re-implemented; MySQL/MariaDB connections are added by:

- `sequel-mcp:import_from_sequel_ace` — guided import of existing favorites (macOS, requires Sequel Ace), or
- the user editing `~/.config/sequel-mcp/config.json` directly (v2 shape below; passwords never go in the file — Keychain only).

SQLite connections have a first-class tool: `add_sqlite_connection`.

A MySQL/MariaDB connection entry (camelCase fields):

```jsonc
{
  "driver": "mysql",
  "name": "prod",
  "host": "10.0.0.5",
  "port": 3306,
  "user": "readonly",
  "database": "mydb",
  "ssl": true,
  "sslServerName": "mysql.internal",      // optional: TLS SAN check target
  "sslCaPath": "~/.ssl/company-ca.pem",   // optional: private CA (PEM/DER)
  "ssh": {                                 // optional tunnel
    "host": "bastion.example.com",
    "port": 22,
    "user": "ops",
    "authMethod": "key",                   // "key" | "password"
    "privateKeyPath": "~/.ssh/id_ed25519",
    "hostKeyPolicy": "strict",             // "strict" | "lenient"
    "knownHostsPath": "~/.ssh/known_hosts",
    "docker": { "container": "mysql-prod", "bridgeTool": "nc" }  // optional bridge
  },
  "policy": { /* baseline action set + caps */ },
  "tablePolicies": { /* db.table / db.* rules */ }
}
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

With `ssh` set (see the JSON above), the server opens a russh channel-multiplexed tunnel to `host:port` from the bastion; the MySQL client connects to a local ephemeral port. If a Keychain password exists under service `<name>::ssh` it is used as the SSH key passphrase or password. Tunnel leases carry a generation counter, so rotated credentials never reuse a stale pool.

## SSH tunnel + remote Docker container

For MySQL/MariaDB running **inside** a Docker container on the bastion with no exposed port, add `ssh.docker`:

```jsonc
"docker": { "container": "mysql-prod", "bridgeTool": "nc" }
```

The server SSHes in, validates the container name against `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, verifies the container is running, then bridges stdio via `docker exec -i <container> <nc|socat|ncat> <host> <port>`. Pick `bridgeTool` based on what's installed inside the image — `nc` is most common; the server verifies the binary exists before opening sockets. This path works even when the bastion sets `AllowTcpForwarding no`.

Allowlist on container names + bridge tool is enforced to block shell-injection through user-supplied values.

## TLS through a tunnel

When you tunnel a TLS-enabled MySQL, the cert SAN would be checked against the tunnel's `127.0.0.1`. Set `sslServerName` so the SAN check targets the real DB hostname, and `sslCaPath` when the server certificate chains to a private CA:

```jsonc
"ssl": true,
"sslServerName": "mysql.internal",
"sslCaPath": "~/.ssl/company-ca.pem"
```

## SSH host key verification

Default `hostKeyPolicy` is `lenient`: the SHA-256 host key fingerprint is logged on every connect, and `@revoked` entries in `known_hosts` are still rejected. Switch to `"strict"` on sensitive connections: an unknown or mismatched host key aborts the tunnel (fail-closed MitM signal). `knownHostsPath` scopes the check to a project file if desired.

## Credential storage

| Item | Location | Notes |
|------|----------|-------|
| MySQL password | macOS Keychain, service `sequel-mcp : <name>`, account `<user>` | `WhenUnlockedThisDeviceOnly`, non-syncable (direct SecItem API) |
| SQLite file path | `~/.config/sequel-mcp/config.json` | No password; path metadata only |
| SSH key passphrase / password | Keychain, service `sequel-mcp : <name>::ssh`, account `<sshUser>` | Same protection class |
| Touch ID gate | macOS `LocalAuthentication` (native, no helper process) | 15-minute idle re-use window |
| Connection metadata | `~/.config/sequel-mcp/config.json` (`mode 0600`, parent dir `0700`) | No secrets in file |

Passwords never appear in tool arguments, request logs, or the audit DB. The audit DB stores SQL (optionally redacted) but never connection credentials.
