import type { SqlCategory } from '../types.js';

export type GrantScope = 'once' | 'session';

interface GrantKey {
  connection: string;
  database: string | null;
  category: SqlCategory;
}

function keyString(k: GrantKey): string {
  return `${k.connection}::${k.database ?? '*'}::${k.category}`;
}

export interface GrantStore {
  consume(k: GrantKey): boolean;
  grantOnce(k: GrantKey): void;
  grantSession(k: GrantKey): void;
  clear(filter?: Partial<GrantKey>): void;
  snapshot(): Array<{ key: GrantKey; scope: GrantScope; remaining: number | null }>;
}

interface Entry {
  scope: GrantScope;
  remaining: number | null;
}

export function createGrantStore(): GrantStore {
  const store = new Map<string, Entry>();

  function consume(k: GrantKey): boolean {
    const id = keyString(k);
    const entry = store.get(id);
    if (!entry) return false;
    if (entry.scope === 'session') return true;
    if (entry.remaining !== null && entry.remaining > 1) {
      entry.remaining -= 1;
    } else {
      store.delete(id);
    }
    return true;
  }

  function grantOnce(k: GrantKey): void {
    store.set(keyString(k), { scope: 'once', remaining: 1 });
  }

  function grantSession(k: GrantKey): void {
    store.set(keyString(k), { scope: 'session', remaining: null });
  }

  function clear(filter?: Partial<GrantKey>): void {
    if (!filter) {
      store.clear();
      return;
    }
    for (const [id] of store) {
      const parts = id.split('::');
      const [connection, database, category] = parts as [string, string, SqlCategory];
      if (filter.connection !== undefined && filter.connection !== connection) continue;
      if (filter.database !== undefined && (filter.database ?? '*') !== database) continue;
      if (filter.category !== undefined && filter.category !== category) continue;
      store.delete(id);
    }
  }

  function snapshot(): Array<{ key: GrantKey; scope: GrantScope; remaining: number | null }> {
    return Array.from(store.entries()).map(([id, entry]) => {
      const [connection, database, category] = id.split('::') as [string, string, SqlCategory];
      return {
        key: {
          connection,
          database: database === '*' ? null : database,
          category,
        },
        scope: entry.scope,
        remaining: entry.remaining,
      };
    });
  }

  return { consume, grantOnce, grantSession, clear, snapshot };
}
