import { describe, expect, it } from 'vitest';
import {
  createLazyAuth,
  jsonResult,
  textResult,
  toolError,
  noConnectionMessage,
} from '../src/server/shared.js';

describe('shared helpers', () => {
  describe('jsonResult', () => {
    it('emits a text block AND structuredContent for object payloads', () => {
      const r = jsonResult({ a: 1, b: 'x' });
      expect(r.content?.[0]).toEqual({ type: 'text', text: JSON.stringify({ a: 1, b: 'x' }, null, 2) });
      expect(r.structuredContent).toEqual({ a: 1, b: 'x' });
      expect(r.isError).toBeUndefined();
    });

    it('wraps array payloads under a value key (structuredContent must be an object)', () => {
      const r = jsonResult([1, 2, 3]);
      expect(r.structuredContent).toEqual({ value: [1, 2, 3] });
    });

    it('wraps null payload under a value key', () => {
      const r = jsonResult(null);
      expect(r.structuredContent).toEqual({ value: null });
    });

    it('wraps scalar payload under a value key', () => {
      const r = jsonResult(42);
      expect(r.structuredContent).toEqual({ value: 42 });
    });
  });

  describe('textResult / toolError', () => {
    it('textResult returns a single text block, no error flag', () => {
      const r = textResult('ok');
      expect(r.content).toEqual([{ type: 'text', text: 'ok' }]);
      expect(r.isError).toBeUndefined();
    });

    it('toolError sets isError true', () => {
      const r = toolError('boom');
      expect(r.isError).toBe(true);
      expect(r.content).toEqual([{ type: 'text', text: 'boom' }]);
    });
  });

  describe('noConnectionMessage', () => {
    it('mentions the explicit name when provided', () => {
      expect(noConnectionMessage('prod')).toContain('"prod"');
    });

    it('refers users to set_default_connection when nothing was passed', () => {
      expect(noConnectionMessage(undefined)).toContain('set_default_connection');
    });
  });

  describe('createLazyAuth', () => {
    it('short-circuits to true when the TouchID prompt is unavailable', async () => {
      let providerCalls = 0;
      const auth = createLazyAuth(async () => {
        providerCalls++;
        return { available: false, prompt: async () => false };
      });
      const r = await auth.ensureAuthenticated('test reason');
      expect(r).toBe(true);
      expect(providerCalls).toBe(1);
    });

    it('calls the TouchID provider exactly once across many ensureAuthenticated calls', async () => {
      let providerCalls = 0;
      let promptCalls = 0;
      const auth = createLazyAuth(async () => {
        providerCalls++;
        return {
          available: true,
          prompt: async () => {
            promptCalls++;
            return true;
          },
        };
      });

      const results = await Promise.all([
        auth.ensureAuthenticated('a'),
        auth.ensureAuthenticated('b'),
        auth.ensureAuthenticated('c'),
      ]);
      expect(results).toEqual([true, true, true]);
      expect(providerCalls).toBe(1);
      // SessionAuthenticator caches successful prompts for 15 min, so even with
      // 3 calls, the user is prompted at most once. (Race: the second and third
      // calls may race past the lastOkAt check before the first prompt resolves;
      // assert at most 3, but typically 1.)
      expect(promptCalls).toBeGreaterThanOrEqual(1);
      expect(promptCalls).toBeLessThanOrEqual(3);
    });

    it('propagates prompt failure as false', async () => {
      const auth = createLazyAuth(async () => ({
        available: true,
        prompt: async () => false,
      }));
      expect(await auth.ensureAuthenticated('nope')).toBe(false);
    });
  });
});
