import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { configureFingerprint, resetFingerprintConfig } from '../src/config.js';
import { clearFingerprint, getSessionFingerprint, storeFingerprint, validateFingerprint } from '../src/middleware/validation.js';

describe('fingerprint validation privacy boundary', () => {
  beforeEach(() => resetFingerprintConfig());

  it('does not store an untransformed fingerprint or veto auth when the hash port is missing', async () => {
    const rawSession = 'session-bearer-no-hash';
    const rawFingerprint = 'fingerprint-secret-no-hash';
    const logs = [
      vi.spyOn(console, 'log').mockImplementation(() => {}),
      vi.spyOn(console, 'warn').mockImplementation(() => {}),
      vi.spyOn(console, 'error').mockImplementation(() => {}),
    ];
    try {
      await storeFingerprint(rawSession, 'user-secret', rawFingerprint);
      expect(getSessionFingerprint(rawSession)).toBeNull();
      const verdict = await validateFingerprint({
        headers: { get: () => null }, url: 'https://example.com/private?token=secret',
        session: { id: rawSession, userId: 'user-secret' },
        user: { id: 'user-secret' },
        cookies: { get: (key) => key === 'fp_id' ? rawFingerprint : undefined },
      });
      expect(verdict).toEqual({ valid: true, reason: 'fingerprint_hash_unavailable' });
      const telemetry = JSON.stringify(logs.map((spy) => spy.mock.calls));
      for (const secret of [rawSession, rawFingerprint, 'user-secret', 'token=secret']) {
        expect(telemetry).not.toContain(secret);
      }
    } finally {
      logs.forEach((spy) => spy.mockRestore());
    }
  });

  it('preserves mismatch verdict without logging raw bearer or fingerprint prefixes', async () => {
    const rawSession = 'session-bearer-with-hash';
    const expectedFingerprint = 'fingerprint-expected-secret';
    const receivedFingerprint = 'fingerprint-received-secret';
    configureFingerprint({ hashFingerprint: (value) => createHash('sha256').update(value).digest('hex') });
    const logs = [
      vi.spyOn(console, 'log').mockImplementation(() => {}),
      vi.spyOn(console, 'warn').mockImplementation(() => {}),
      vi.spyOn(console, 'error').mockImplementation(() => {}),
    ];
    try {
      await storeFingerprint(rawSession, 'user-secret', expectedFingerprint);
      expect(getSessionFingerprint(rawSession)).toMatchObject({
        fingerprintHash: createHash('sha256').update(expectedFingerprint).digest('hex'),
      });
      expect(getSessionFingerprint(rawSession)).not.toHaveProperty('sessionId');
      const verdict = await validateFingerprint({
        headers: { get: () => null }, url: 'https://example.com/private?token=secret',
        session: { id: rawSession, userId: 'user-secret' },
        user: { id: 'user-secret' },
        cookies: { get: (key) => key === 'fp_id' ? receivedFingerprint : undefined },
      });
      expect(verdict).toEqual({ valid: false, reason: 'fingerprint_mismatch' });
      clearFingerprint(rawSession);
      const telemetry = JSON.stringify(logs.map((spy) => spy.mock.calls));
      for (const secret of [rawSession, expectedFingerprint, receivedFingerprint, 'user-secret', 'token=secret']) {
        expect(telemetry).not.toContain(secret);
      }
      expect(telemetry).not.toContain('session.id');
    } finally {
      logs.forEach((spy) => spy.mockRestore());
    }
  });
});
