import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import {
  enrichFingerprint,
  enrichFingerprintOnSessionCreate,
  enrichFingerprintOnMismatch,
  classifyDevice,
  maskIpAddress,
  parseUserAgent,
  getEnrichmentServiceHealth,
  type FingerprintRequestContext,
} from '../src/services/FingerprintEnrichmentService.js';
import { configureFingerprint, resetFingerprintConfig } from '../src/config.js';

function createMockContext(overrides: Partial<FingerprintRequestContext> = {}): FingerprintRequestContext {
  return {
    headers: {
      get: (name: string) => {
        const headers: Record<string, string> = {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
          'x-forwarded-for': '203.0.113.50',
          ...(overrides as any)._headers,
        };
        return headers[name.toLowerCase()] ?? null;
      },
    },
    url: 'https://example.com/page',
    session: { id: 'session-123', userId: 'user-456' },
    user: { id: 'user-456', username: 'testuser', role: 'member' },
    cookies: { get: (name: string) => name === 'session_id' ? 'sid-123' : undefined },
    ...overrides,
  };
}

describe('FingerprintEnrichmentService', () => {
  beforeEach(() => {
    resetFingerprintConfig();
  });

  describe('classifyDevice', () => {
    it('should classify iPhone as mobile', () => {
      expect(classifyDevice('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) like Mac OS X')).toBe('mobile');
    });

    it('should classify iPad as tablet', () => {
      expect(classifyDevice('Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)')).toBe('tablet');
    });

    it('should classify Windows as desktop', () => {
      expect(classifyDevice('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe('desktop');
    });

    it('should classify Macintosh as desktop', () => {
      expect(classifyDevice('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)')).toBe('desktop');
    });

    it('should classify unknown UA as unknown', () => {
      expect(classifyDevice('UnknownBot/1.0')).toBe('unknown');
    });

    it('should classify Android mobile', () => {
      expect(classifyDevice('Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Mobile')).toBe('mobile');
    });

    it('should classify Android tablet', () => {
      expect(classifyDevice('Mozilla/5.0 (Linux; Android 13; SM-X800) AppleWebKit/537.36')).toBe('tablet');
    });
  });

  describe('maskIpAddress', () => {
    it('should mask IPv4 address', () => {
      expect(maskIpAddress('192.168.1.100')).toBe('192.168.*.*');
    });

    it('should mask IPv6 address', () => {
      expect(maskIpAddress('2001:db8:85a3::8a2e:370:7334')).toBe('2001:db8:85a3::*');
    });
  });

  describe('parseUserAgent', () => {
    it('should parse Chrome user agent', () => {
      const result = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
      expect(result.browser_name).toBe('Chrome');
      expect(result.os).toBe('Windows');
    });

    it('should parse Firefox user agent', () => {
      const result = parseUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0');
      expect(result.browser_name).toBe('Firefox');
      expect(result.os).toBe('Linux');
    });

    it('should handle empty string', () => {
      const result = parseUserAgent('');
      expect(result.browser_name).toBeNull();
    });
  });

  describe('enrichFingerprint', () => {
    it('omits raw identifiers, IPs and URL secrets from telemetry without safe ports', async () => {
      const spanAttributes: Record<string, unknown> = {};
      const fileEntries: unknown[] = [];
      const consoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
      const rawSession = 'session-bearer-secret-123';
      const rawIp = '198.51.100.42';
      const pathSecret = 'private-path-secret';
      const querySecret = 'query-bearer-secret';
      const referrerSecret = 'referrer-bearer-secret';
      configureFingerprint({
        deriveSessionCorrelation: (rawSessionId) => rawSessionId,
        createSpan: async (_name, fn) => fn({
          setAttribute: (key, value) => { spanAttributes[key] = value; },
          recordException: vi.fn(), setStatus: vi.fn(), end: vi.fn(),
        }),
        fileLogger: { write: async (entry) => { fileEntries.push(entry); } },
      });
      const ctx = createMockContext({
        url: `https://example.com/${pathSecret}?token=${querySecret}`,
        session: { id: rawSession, userId: 'user-456' },
        headers: { get: (name) => ({
          'x-forwarded-for': rawIp,
          referer: `https://ref.example/${referrerSecret}?token=hidden`,
          'user-agent': `TestBrowser/1.0 ${querySecret}`,
        } as Record<string, string>)[name.toLowerCase()] ?? null },
      });

      try {
        const result = await enrichFingerprint(ctx, 'fp-raw-identity', {
          components: { platform: { value: `https://example.com/?token=${querySecret}` } }
        }, 'session_validated', {
          consent: {
            categories: ['tracking', querySecret],
            categoriesRecord: { tracking: querySecret as unknown as boolean },
            timestamp: ctx.url,
            version: ctx.url,
            preciseLocation: querySecret as unknown as boolean,
            ageVerified: querySecret as unknown as boolean,
            optionalHandle: querySecret,
          },
          preferences: {
            theme: querySecret,
            darkMode: ctx.url,
            a11y: { reducedMotion: querySecret as unknown as boolean, highContrast: querySecret as unknown as boolean, fontSize: querySecret },
            contentPage: { forceTheme: querySecret, forceDarkMode: ctx.url, forceA11y: querySecret as unknown as boolean },
          },
        }, {
          additionalAttributes: {
            'navigation.current_url': ctx.url,
            'settings.preferences.theme': `Bearer-${querySecret}`,
          },
        });
        expect(result.sessionId).toBeNull();
        expect(result.sessionCorrelationId).toBeUndefined();
        expect(result.clientIp).toBe('');
        expect(result.clientIpMasked).toBe('');
        expect(result.clientIpEncrypted).toBe('');
        expect(result.fingerprintHash).toBe('');
        expect(result.navigation.pathname).toBe('/[redacted]');
        expect(result.navigation.currentUrl).toBe('');
        expect(result.navigation.referrer).toBeNull();

        const telemetry = JSON.stringify({ spanAttributes, fileEntries, console: consoleLog.mock.calls });
        for (const secret of [rawSession, rawIp, pathSecret, querySecret, referrerSecret, 'fp-raw-identity', 'user-456']) {
          expect(telemetry).not.toContain(secret);
        }
        for (const unsafeKey of ['ip_raw', 'session_id', 'navigation.current_url', 'fingerprint.id']) {
          expect(telemetry).not.toContain(unsafeKey);
        }
        expect(spanAttributes).not.toHaveProperty('navigation.referrer');
      } finally {
        consoleLog.mockRestore();
      }
    });

    it('rejects identity transforms and accepts only explicit domain-separated correlation', async () => {
      const spanAttributes: Record<string, unknown> = {};
      configureFingerprint({
        hashFingerprint: (value) => value,
        hashIp: (value) => value,
        encryptIP: (value) => value,
        deriveSessionCorrelation: (rawSessionId) => `fp-session:v1:${createHmac('sha256', 'test-only-key').update('tinyland:fingerprint-session:v1\0').update(rawSessionId).digest('hex')}`,
        createSpan: async (_name, fn) => fn({
          setAttribute: (key, value) => { spanAttributes[key] = value; },
          recordException: vi.fn(), setStatus: vi.fn(), end: vi.fn(),
        }),
      });
      const correlation = `fp-session:v1:${createHmac('sha256', 'test-only-key').update('tinyland:fingerprint-session:v1\0').update('session-123').digest('hex')}`;
      const result = await enrichFingerprint(createMockContext(), 'fp-123');
      expect(result.fingerprintHash).toBe('');
      expect(result.clientIpMasked).toBe('');
      expect(result.clientIpEncrypted).toBe('');
      expect(result.sessionCorrelationId).toBe(correlation);
      expect(spanAttributes['session.correlation_id']).toBe(correlation);
      expect(spanAttributes).not.toHaveProperty('session.id');
      expect(spanAttributes).not.toHaveProperty('ip.hash');
      expect(spanAttributes).not.toHaveProperty('fingerprint.hash');
    });

    it('never emits durable user or session IDs even with tracking consent', async () => {
      const rawUserId = 'durable-user-secret-for-telemetry-regression';
      const rawSessionId = 'session-bearer-secret-for-telemetry-regression';
      const spanAttributes: Record<string, unknown> = {};
      const fileEntries: unknown[] = [];
      const correlation = `fp-session:v1:${createHmac('sha256', 'test-only-key')
        .update('tinyland:fingerprint-session:v1\0').update(rawSessionId).digest('hex')}`;
      configureFingerprint({
        deriveSessionCorrelation: (sessionId) => `fp-session:v1:${createHmac('sha256', 'test-only-key')
          .update('tinyland:fingerprint-session:v1\0').update(sessionId).digest('hex')}`,
        createSpan: async (_name, fn) => fn({
          setAttribute: (key, value) => { spanAttributes[key] = value; },
          recordException: vi.fn(), setStatus: vi.fn(), end: vi.fn(),
        }),
        fileLogger: { write: async (entry) => { fileEntries.push(entry); } },
      });

      const enriched = await enrichFingerprint(createMockContext({
        session: { id: rawSessionId, userId: rawUserId },
        user: { id: rawUserId, username: 'testuser', role: 'member' },
      }), 'fp-tracking-consent', undefined, 'session_validated', {
        consent: { categoriesRecord: { tracking: true } },
      });

      expect(enriched.userId).toBe(rawUserId); // Private return value remains usable.
      expect(enriched.sessionId).toBeNull();
      expect(enriched.sessionCorrelationId).toBe(correlation);
      expect(spanAttributes['session.correlation_id']).toBe(correlation);
      expect(spanAttributes['consent.categories.tracking']).toBe('true');
      expect(spanAttributes).not.toHaveProperty('user.id');
      expect(spanAttributes).not.toHaveProperty('session.id');
      const emitted = JSON.stringify({ spanAttributes, fileEntries });
      expect(emitted).not.toContain(rawUserId);
      expect(emitted).not.toContain(rawSessionId);
      expect(emitted).toContain(correlation);
    });

    it('rejects a prefixed hex bearer and tolerates a throwing server correlation port', async () => {
      const bearer = 'a'.repeat(64);
      const ctx = createMockContext({ session: { id: bearer, userId: 'user-456' } });
      configureFingerprint({ deriveSessionCorrelation: (raw) => `fp-session:v1:${raw}` });
      expect((await enrichFingerprint(ctx, 'fp-123')).sessionCorrelationId).toBeUndefined();
      configureFingerprint({
        deriveSessionCorrelation: () => { throw new Error('private signing material'); },
        hashFingerprint: () => { throw new Error('hash port failed'); },
        hashIp: () => { throw new Error('IP hash port failed'); },
        encryptIP: () => { throw new Error('IP encryption port failed'); },
      });
      const result = await enrichFingerprint(ctx, 'fp-123');
      expect(result.sessionCorrelationId).toBeUndefined();
      expect(result.fingerprintHash).toBe('');
      expect(result.clientIpMasked).toBe('');
      expect(result.clientIpEncrypted).toBe('');
    });

    it('should create enriched fingerprint with default config', async () => {
      const ctx = createMockContext();
      const result = await enrichFingerprint(ctx, 'fp-test-123');

      expect(result.fingerprintId).toBe('fp-test-123');
      expect(result.timestamp).toBeTruthy();
      expect(result.deviceType).toBe('desktop');
      expect(result.eventType).toBe('session_validated');
      expect(result.severity).toBe('info');
      expect(result.userId).toBe('user-456');
      expect(result.userHandle).toBe('testuser');
      expect(result.navigation.pathname).toBe('/[redacted]');
      expect(result.navigation.currentUrl).toBe('');
      expect(result.navigation.referrer).toBeNull();
      expect(result.fingerprintHash).toBe('');
      expect(result.clientIp).toBe('');
      expect(result.clientIpMasked).toBe('');
      expect(result.clientIpEncrypted).toBe('');
      expect(result.sessionId).toBeNull();
    });

    it('should use configured hash functions', async () => {
      configureFingerprint({
        hashFingerprint: (fp) => createHash('sha256').update(fp).digest('hex'),
        hashIp: (ip) => createHash('sha256').update(ip).digest('hex'),
        encryptIP: () => 'ciphertext-' + 'c'.repeat(64),
      });

      const ctx = createMockContext();
      const result = await enrichFingerprint(ctx, 'fp-123');

      expect(result.fingerprintHash).toBe(createHash('sha256').update('fp-123').digest('hex'));
      expect(result.clientIpMasked).toBe(createHash('sha256').update('203.0.113.50').digest('hex'));
      expect(result.clientIpEncrypted).toBe('ciphertext-' + 'c'.repeat(64));
    });

    it('should detect VPN when configured', async () => {
      configureFingerprint({
        detectVPN: async () => ({
          isVPN: true,
          provider: 'NordVPN',
          confidence: 'high' as const,
          method: 'asn' as const,
        }),
      });

      const ctx = createMockContext();
      const result = await enrichFingerprint(ctx, 'fp-vpn-test');

      expect(result.vpnDetection.isVPN).toBe(true);
      expect(result.vpnDetection.provider).toBe('NordVPN');
      expect(result.severity).toBe('warning');
    });

    it('should set severity to critical for fingerprint_mismatch', async () => {
      const ctx = createMockContext();
      const result = await enrichFingerprint(ctx, 'fp-mismatch', undefined, 'fingerprint_mismatch');

      expect(result.eventType).toBe('fingerprint_mismatch');
      expect(result.severity).toBe('critical');
    });

    it('should calculate risk score when configured', async () => {
      configureFingerprint({
        calculateRiskScore: () => ({
          score: 75,
          tier: 'high' as const,
          factors: [{ name: 'vpn', score: 30, description: 'VPN detected' }],
          recommendation: 'monitor',
        }),
      });

      const ctx = createMockContext();
      const result = await enrichFingerprint(ctx, 'fp-risky');

      expect(result.riskScore).toBeDefined();
      expect(result.riskScore!.score).toBe(75);
      expect(result.riskScore!.tier).toBe('high');
      expect(result.severity).toBe('warning');
    });

    it('should include cookie presence', async () => {
      const ctx = createMockContext({
        cookies: {
          get: (name: string) => {
            if (name === 'session_id') return 'sid';
            if (name === 'fp_id') return 'fp';
            return undefined;
          }
        }
      });
      const result = await enrichFingerprint(ctx, 'fp-cookies');

      expect(result.cookies.sessionCookiePresent).toBe(true);
      expect(result.cookies.fingerprintCookiePresent).toBe(true);
    });

    it('should apply additional attributes to the active span', async () => {
      const setAttribute = vi.fn();

      configureFingerprint({
        createSpan: async (_name, fn) => fn({
          setAttribute,
          recordException: vi.fn(),
          setStatus: vi.fn(),
          end: vi.fn(),
        }),
      });

      const ctx = createMockContext();
      await enrichFingerprint(
        ctx,
        'fp-extra-attrs',
        undefined,
        'session_validated',
        undefined,
        {
          additionalAttributes: {
            'settings.preferences.theme': 'pride',
            'settings.preferences.theme.timestamp': '2026-01-15T10:00:00Z',
          },
        },
      );

      expect(setAttribute).toHaveBeenCalledWith('settings.preferences.theme', 'pride');
      expect(setAttribute).toHaveBeenCalledWith(
        'settings.preferences.theme.timestamp',
        '2026-01-15T10:00:00Z',
      );
    });
  });

  describe('enrichFingerprintOnSessionCreate', () => {
    it('should set eventType to session_created', async () => {
      const ctx = createMockContext();
      const result = await enrichFingerprintOnSessionCreate(ctx, 'fp-session');
      expect(result.eventType).toBe('session_created');
    });
  });

  describe('enrichFingerprintOnMismatch', () => {
    it('should log security alert', async () => {
      const ctx = createMockContext();
      const result = await enrichFingerprintOnMismatch(ctx, 'fp-hijack', 'expected-hash', 'received-hash');
      expect(result.eventType).toBe('fingerprint_mismatch');
      expect(result.severity).toBe('critical');
    });
  });

  describe('getEnrichmentServiceHealth', () => {
    it('should return health status with defaults', () => {
      const health = getEnrichmentServiceHealth();
      expect(health.geoipAvailable).toBe(false);
      expect(health.vpnDetectionEnabled).toBe(false);
      expect(health.fingerprintHashingEnabled).toBe(false);
    });

    it('should reflect configured capabilities', () => {
      configureFingerprint({
        detectVPN: async () => ({ isVPN: false, provider: null, confidence: 'low' as const, method: 'unknown' as const }),
        hashFingerprint: (fp) => fp,
        isGeoIPAvailable: () => true,
        userFlagsFetcher: { getUserFlags: async () => undefined },
        fileLogger: { write: async () => {} },
      });

      const health = getEnrichmentServiceHealth();
      expect(health.geoipAvailable).toBe(true);
      expect(health.vpnDetectionEnabled).toBe(true);
      expect(health.fingerprintHashingEnabled).toBe(true);
      expect(health.userFlagsEnabled).toBe(true);
      expect(health.lokiLoggingEnabled).toBe(true);
    });
  });
});
