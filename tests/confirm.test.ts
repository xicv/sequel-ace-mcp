import { describe, expect, it, vi } from 'vitest';
import { makeConfirmFn } from '../src/elicit/confirm.js';

const baseArgs = {
  category: 'write' as const,
  statement: 'UPDATE t SET x = 1',
  connectionName: 'conn',
  database: 'db',
};

function fakeServer(opts: {
  capabilities?: unknown;
  capabilitiesThrows?: unknown;
  elicitResult?: unknown;
  elicitThrows?: unknown;
}) {
  return {
    getClientCapabilities: vi.fn(() => {
      if (opts.capabilitiesThrows !== undefined) throw opts.capabilitiesThrows;
      return opts.capabilities;
    }),
    elicitInput: vi.fn(async () => {
      if (opts.elicitThrows !== undefined) throw opts.elicitThrows;
      return opts.elicitResult;
    }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
}

describe('makeConfirmFn', () => {
  it('reports unavailable when the client declares no elicitation capability at all', async () => {
    const server = fakeServer({ capabilities: {} });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
    expect(server.elicitInput).not.toHaveBeenCalled();
  });

  it('reports unavailable when elicitation is declared but "form" mode is not (regression: doctor previously reported this as supported)', async () => {
    // A client can declare `elicitation: {}` (e.g. only `url` mode, or a stub
    // capability object) without supporting the 'form' mode this server always
    // requests. A bare truthy check on `capabilities.elicitation` misses this.
    const server = fakeServer({ capabilities: { elicitation: {} } });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
    expect(server.elicitInput).not.toHaveBeenCalled();
  });

  it('reports unavailable when getClientCapabilities throws', async () => {
    const server = fakeServer({ capabilitiesThrows: new Error('boom') });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
    if (outcome.choice === 'unavailable') expect(outcome.reason).toContain('boom');
  });

  it('reports unavailable (not decline) when the client cancels without an explicit choice', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'cancel' },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
  });

  it('treats a top-level spec "decline" action as a real decline', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'decline' },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('decline');
  });

  it('returns the chosen grant on accept with a valid choice ("once")', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'accept', content: { choice: 'once' } },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('once');
  });

  it('returns the chosen grant on accept with a valid choice ("session")', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'accept', content: { choice: 'session' } },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('session');
  });

  it('treats accept with content.choice === "decline" as a real, explicit decline', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'accept', content: { choice: 'decline' } },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('decline');
  });

  it('reports unavailable (not decline) on accept with missing content (regression)', async () => {
    // This is the exact shape that produced "User declined confirmation" for a
    // prompt that was never actually shown: the SDK only schema-validates
    // elicitInput's response when `content` is truthy, so an accept with no
    // content sails through unvalidated.
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'accept', content: undefined },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
    if (outcome.choice === 'unavailable') {
      expect(outcome.reason).toContain('accepted but did not return a valid choice');
    }
  });

  it('reports unavailable (not decline) on accept with an empty content object', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'accept', content: {} },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
  });

  it('reports unavailable (not decline) on accept with an invalid choice value', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitResult: { action: 'accept', content: { choice: 'bogus' } },
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
  });

  it('reports unavailable when elicitInput itself throws', async () => {
    const server = fakeServer({
      capabilities: { elicitation: { form: true } },
      elicitThrows: new Error('transport closed'),
    });
    const confirm = makeConfirmFn(server);
    const outcome = await confirm(baseArgs);
    expect(outcome.choice).toBe('unavailable');
    if (outcome.choice === 'unavailable') expect(outcome.reason).toContain('transport closed');
  });
});
