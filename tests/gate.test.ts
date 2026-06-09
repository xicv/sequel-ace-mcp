import { describe, expect, it, vi } from 'vitest';
import { evaluatePolicy } from '../src/policy/gate.js';
import { createGrantStore } from '../src/policy/grants.js';
import { PolicySchema, PolicyDeniedError, PolicyConfirmationDeclinedError } from '../src/types.js';

const policy = PolicySchema.parse({});

describe('evaluatePolicy', () => {
  it('allows read by default without prompt', async () => {
    const elicit = vi.fn();
    const decision = await evaluatePolicy({
      policy,
      category: 'read',
      statement: 'SELECT 1',
      connectionName: 'x',
      elicitConfirm: elicit,
    });
    expect(decision.action).toBe('allow');
    expect(elicit).not.toHaveBeenCalled();
  });

  it('confirms write and proceeds when user picks "once"', async () => {
    const elicit = vi.fn(async () => 'once' as const);
    const decision = await evaluatePolicy({
      policy,
      category: 'write',
      statement: 'UPDATE t SET x = 1',
      connectionName: 'x',
      elicitConfirm: elicit,
    });
    expect(decision.action).toBe('confirm');
    expect(decision.confirmed).toBe(true);
    expect(decision.choiceApplied).toBe('once');
    expect(elicit).toHaveBeenCalledOnce();
  });

  it('rejects when user declines confirmation', async () => {
    const elicit = vi.fn(async () => 'decline' as const);
    await expect(
      evaluatePolicy({
        policy,
        category: 'write',
        statement: 'UPDATE t SET x = 1',
        connectionName: 'x',
        elicitConfirm: elicit,
      }),
    ).rejects.toBeInstanceOf(PolicyConfirmationDeclinedError);
  });

  it('denies DDL by default without prompt', async () => {
    const elicit = vi.fn();
    await expect(
      evaluatePolicy({
        policy,
        category: 'ddl',
        statement: 'DROP TABLE x',
        connectionName: 'x',
        elicitConfirm: elicit,
      }),
    ).rejects.toBeInstanceOf(PolicyDeniedError);
    expect(elicit).not.toHaveBeenCalled();
  });

  it('skips elicit when a session grant covers (conn, db, category)', async () => {
    const grants = createGrantStore();
    grants.grantSession({ connection: 'x', database: 'app', category: 'write' });
    const elicit = vi.fn();

    const decision = await evaluatePolicy({
      policy,
      category: 'write',
      statement: 'UPDATE t SET x = 1',
      connectionName: 'x',
      grantDatabase: 'app',
      elicitConfirm: elicit,
      grants,
    });
    expect(decision.confirmed).toBe(true);
    expect(decision.grantUsed).toBe('session');
    expect(elicit).not.toHaveBeenCalled();

    const decision2 = await evaluatePolicy({
      policy,
      category: 'write',
      statement: 'UPDATE t SET x = 2',
      connectionName: 'x',
      grantDatabase: 'app',
      elicitConfirm: elicit,
      grants,
    });
    expect(decision2.confirmed).toBe(true);
    expect(elicit).not.toHaveBeenCalled();
  });

  it('"session" choice registers a session grant for subsequent statements', async () => {
    const grants = createGrantStore();
    const elicit = vi
      .fn<(p: unknown) => Promise<'once' | 'session' | 'decline'>>()
      .mockResolvedValueOnce('session');

    await evaluatePolicy({
      policy,
      category: 'write',
      statement: 'UPDATE t SET x = 1',
      connectionName: 'x',
      grantDatabase: 'app',
      elicitConfirm: elicit,
      grants,
    });

    await evaluatePolicy({
      policy,
      category: 'write',
      statement: 'UPDATE t SET x = 2',
      connectionName: 'x',
      grantDatabase: 'app',
      elicitConfirm: elicit,
      grants,
    });

    expect(elicit).toHaveBeenCalledOnce();
  });

  it('session grant is scoped to its (conn, db, category) — does not leak across databases', async () => {
    const grants = createGrantStore();
    grants.grantSession({ connection: 'x', database: 'staging', category: 'write' });
    const elicit = vi.fn(async () => 'decline' as const);

    await expect(
      evaluatePolicy({
        policy,
        category: 'write',
        statement: 'UPDATE t SET x = 1',
        connectionName: 'x',
        grantDatabase: 'prod',
        elicitConfirm: elicit,
        grants,
      }),
    ).rejects.toBeInstanceOf(PolicyConfirmationDeclinedError);
    expect(elicit).toHaveBeenCalledOnce();
  });
});
