# Migration plan

## Config v1 → v2

v1 (TypeScript, zod-validated) fields: `version: 1`, `connections[]`
(discriminated on `driver`, default `mysql`), `defaultConnection`,
`retention{…}`. Connection carries `policy` (full) and optional
`databasePolicies: { <db>: PartialPolicy }`.

v2 (Rust) keeps the same file path and adds:

```jsonc
{
  "version": 2,
  "revision": 42,                    // CAS field, bumped on every write
  "connections": [ /* same shapes plus: */ ],
  "defaultConnection": "name",
  "retention": { /* same fields */ }
}
```

Per-connection additions in v2:

- `tablePolicies`: map of `"<database>.*"` (wildcard) or `"<database>.<table>"`
  (exact) → `PartialPolicy`. Migrated from `databasePolicies` as `<db>.*`.
- `ssh.hostKeyPolicy`: unset in v1 ⇒ migrated as `"lenient"` **with**
  `ssh.hostKeyPolicyMigrated: true` so the GUI/doctor can warn prominently;
  connections created by v2 default to `"strict"`.
- legacy `databasePolicies` key is dropped after mapping (backup retains it).

Migration algorithm (executed by `sequel-mcp migrate` and lazily on first
load):

1. read + validate v1 (malformed ⇒ hard error, nothing written);
2. acquire inter-process lock (`fs4` on `<config>.lock`);
3. copy v1 → `<config>.pre-v2.<timestamp>.json` (mode 0600);
4. map policies (each `databasePolicies[db]` ⇒ `tablePolicies["db.*"]`),
   preserve every connection, order, defaults and retention;
5. write v2 to temp file in the same directory (0600), fsync file;
6. atomic rename over `config.json`; fsync parent directory;
7. reopen + validate; on any failure restore step 3's backup and leave v1
   intact;
8. two concurrent migrators: second waits on the lock, re-reads, sees v2,
   no-ops. Tested in `tests/migration/`.

`set_policy` / `set_retention` keep working on v2 via revision-checked
read-modify-write (GUI, CLI, MCP cannot silently overwrite each other).

## Legacy database-policy tools

`set_database_policy` / `clear_database_policy` / `list_database_policies`
remain with identical argument shapes; they operate on the corresponding
wildcard table rule `<database>.*` and are documented as compatibility
wrappers. Strictest-wins resolution gives exact rules precedence over
wildcard rules for the same table.

## Keychain

Service names are unchanged, so existing credentials keep working with no
re-entry:

- `sequel-mcp : <connection>` / account `<db user>` — MySQL password;
- `sequel-mcp : <connection>::ssh` / account `<ssh user>` — SSH
  password/passphrase;
- legacy `sequel-ace-mcp` namespace still migrated by `sequel-mcp migrate`
  (config copy + keychain copy, `--force`/`--purge`/`--json` preserved);
- Sequel Ace import reads `Sequel Ace : <name> (<id>)` /
  `Sequel Ace SSHTunnel : <name> (<id>)` as before.

New writes set `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and
non-synchronizing; pre-existing entries are readable regardless of their
attributes (read path does not filter on accessibility).

## Audit DB

Existing `audit.sqlite` (audit_log/backup/meta) opens unchanged. Versioned
schema migrations via `meta.schema_version`; v1 ⇒ v2 adds:

- `outcome` gains `cancelled`, `unavailable`, `expired` values (TEXT column,
  no DDL needed) and `approval` linkage columns: `approval_scope`,
  `approval_digest`, `policy_revision`;
- chain epoch rows: when retention deletes chained rows, a `chain_epoch`
  meta row records the truncation so verification treats the surviving chain
  as epoch-scoped rather than silently incomplete.

## Sequel Ace data

`Favorites.plist` parsing and `queryHistory.db` reading are ported as-is
(read-only, optional). Paths unchanged.

## Uninstall / rollback

The v1 backup written during migration plus git history of the Node
implementation allow full rollback: restore `config.pre-v2.*.json` over
`config.json`, reinstall the Node package from the pre-rewrite tag. The Rust
package writes no state outside `~/.config/sequel-mcp`,
`~/.local/share/sequel-mcp` and Keychain entries under the same service
names.
