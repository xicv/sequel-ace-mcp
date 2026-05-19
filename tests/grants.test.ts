import { describe, expect, it } from 'vitest';
import { createGrantStore } from '../src/policy/grants.js';

describe('grant store', () => {
  it('consume returns false when no grant exists', () => {
    const g = createGrantStore();
    expect(g.consume({ connection: 'x', database: 'a', category: 'write' })).toBe(false);
  });

  it('grantOnce is consumed exactly once', () => {
    const g = createGrantStore();
    const key = { connection: 'x', database: 'a', category: 'write' as const };
    g.grantOnce(key);
    expect(g.consume(key)).toBe(true);
    expect(g.consume(key)).toBe(false);
  });

  it('grantSession is consumed repeatedly until cleared', () => {
    const g = createGrantStore();
    const key = { connection: 'x', database: 'a', category: 'ddl' as const };
    g.grantSession(key);
    expect(g.consume(key)).toBe(true);
    expect(g.consume(key)).toBe(true);
    expect(g.consume(key)).toBe(true);
  });

  it('grants are scoped per (connection, database, category)', () => {
    const g = createGrantStore();
    g.grantSession({ connection: 'a', database: 'd1', category: 'write' });
    expect(g.consume({ connection: 'a', database: 'd2', category: 'write' })).toBe(false);
    expect(g.consume({ connection: 'b', database: 'd1', category: 'write' })).toBe(false);
    expect(g.consume({ connection: 'a', database: 'd1', category: 'ddl' })).toBe(false);
    expect(g.consume({ connection: 'a', database: 'd1', category: 'write' })).toBe(true);
  });

  it('null database is its own scope (not a wildcard)', () => {
    const g = createGrantStore();
    g.grantSession({ connection: 'a', database: null, category: 'write' });
    expect(g.consume({ connection: 'a', database: 'd1', category: 'write' })).toBe(false);
    expect(g.consume({ connection: 'a', database: null, category: 'write' })).toBe(true);
  });

  it('clear() removes all grants', () => {
    const g = createGrantStore();
    g.grantSession({ connection: 'a', database: 'd1', category: 'write' });
    g.grantSession({ connection: 'b', database: 'd2', category: 'ddl' });
    g.clear();
    expect(g.consume({ connection: 'a', database: 'd1', category: 'write' })).toBe(false);
    expect(g.consume({ connection: 'b', database: 'd2', category: 'ddl' })).toBe(false);
  });

  it('clear({connection}) removes only matching grants', () => {
    const g = createGrantStore();
    g.grantSession({ connection: 'a', database: 'd1', category: 'write' });
    g.grantSession({ connection: 'b', database: 'd1', category: 'write' });
    g.clear({ connection: 'a' });
    expect(g.consume({ connection: 'a', database: 'd1', category: 'write' })).toBe(false);
    expect(g.consume({ connection: 'b', database: 'd1', category: 'write' })).toBe(true);
  });

  it('snapshot reports active grants', () => {
    const g = createGrantStore();
    g.grantSession({ connection: 'a', database: 'd1', category: 'write' });
    g.grantOnce({ connection: 'b', database: null, category: 'ddl' });
    const snap = g.snapshot();
    expect(snap).toHaveLength(2);
    const session = snap.find((s) => s.scope === 'session');
    const once = snap.find((s) => s.scope === 'once');
    expect(session?.key.connection).toBe('a');
    expect(once?.key.category).toBe('ddl');
    expect(once?.key.database).toBeNull();
  });
});
