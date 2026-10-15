











import { getScopedLogger, getFingerprintConfig, withSpan, type FingerprintSpan } from '../config.js';
import type { EnrichedFingerprint, DeviceType } from '../types/fingerprint.js';
import { UAParser } from 'ua-parser-js';

const logger = getScopedLogger('fingerprint-enrichment');


export type { EnrichedFingerprint } from '../types/fingerprint.js';




export interface ConsentPreferenceData {
  consent?: {
    categories?: string[];
    categoriesRecord?: {
      essential?: boolean;
      preferences?: boolean;
      functional?: boolean;
      tracking?: boolean;
      performance?: boolean;
    };
    timestamp?: string;
    version?: string;
    preciseLocation?: boolean;
    ageVerified?: boolean;
    optionalHandle?: string;
  };
  preferences?: {
    theme?: string;
    darkMode?: boolean | string;
    a11y?: {
      reducedMotion?: boolean;
      highContrast?: boolean;
      fontSize?: string;
    };
    contentPage?: {
      forceTheme?: string;
      forceDarkMode?: boolean | string;
      forceA11y?: boolean;
    };
  };
}




export interface FingerprintRequestContext {
  headers: {
    get: (name: string) => string | null;
  };
  url: string;
  
  session?: {
    id?: string;
    userId?: string;
  };
  user?: {
    id?: string;
    username?: string;
    role?: string;
  };
  
  cookies?: {
    get: (name: string) => string | undefined;
  };
  
  getClientAddress?: () => string;
}

export type FingerprintAdditionalAttributes = Record<
  string,
  string | boolean | number
>;

export interface FingerprintEnrichmentOptions {
  additionalAttributes?: FingerprintAdditionalAttributes;
}

const SESSION_CORRELATION_PATTERN = /^fp-session:v1:[0-9a-f]{64}$/;
const SAFE_THEMES = new Set([
  'trans', 'pride', 'tinyland', 'high-contrast', 'cerberus', 'rose', 'catppuccin', 'pine', 'system'
]);

function safeDarkMode(value: unknown): value is boolean | string {
  return typeof value === 'boolean' || value === 'system' || value === 'light' ||
    value === 'dark' || value === 'true' || value === 'false';
}

function safeTransform(input: string, transform?: (value: string) => string): string {
  if (!transform || !input || input === 'unknown') return '';
  try {
    const output = transform(input);
    return typeof output === 'string' && output.length >= 32 && !output.includes(input) ? output : '';
  } catch {
    return '';
  }
}

function safeAdditionalAttribute(key: string, value: string | boolean | number): boolean {
  if (!/^settings\.(?:preferences\.(?:theme|darkMode)|a11y\.(?:reducedMotion|highContrast|fontSize))(?:\.timestamp)?$/.test(key)) return false;
  if (key.endsWith('.timestamp')) {
    return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value);
  }
  if (key === 'settings.preferences.theme') {
    return typeof value === 'string' && SAFE_THEMES.has(value);
  }
  if (key === 'settings.a11y.fontSize') {
    return typeof value === 'string' && ['small', 'medium', 'large'].includes(value);
  }
  if (key === 'settings.preferences.darkMode') return safeDarkMode(value);
  return typeof value === 'boolean';
}




export function classifyDevice(userAgent: string): DeviceType {
  const ua = userAgent.toLowerCase();
  if (/(iphone|ipod|android.*mobile|windows phone|blackberry)/i.test(ua)) return 'mobile';
  if (/(ipad|android(?!.*mobile)|tablet)/i.test(ua)) return 'tablet';
  if (/(windows|macintosh|linux|x11)/i.test(ua)) return 'desktop';
  return 'unknown';
}






export function maskIpAddress(ip: string): string {
  if (ip.includes(':')) {
    const parts = ip.split(':');
    return parts.slice(0, Math.min(3, parts.length)).join(':') + '::*';
  } else {
    const parts = ip.split('.');
    return parts.slice(0, 2).join('.') + '.*.*';
  }
}




function parseDetailedComponents(detailedFingerprint: any): EnrichedFingerprint['components'] {
  if (!detailedFingerprint || !detailedFingerprint.components) {
    return {};
  }

  const components = detailedFingerprint.components;

  return {
    canvas: components.canvas?.value?.toString(),
    webgl: components.webgl?.value?.toString(),
    audio: components.audio?.value?.toString(),
    fonts: components.fonts?.value,
    plugins: components.plugins?.value?.map((p: any) => p.name),
    screenResolution: components.screenResolution?.value
      ? `${components.screenResolution.value[0]}x${components.screenResolution.value[1]}`
      : undefined,
    timezone: components.timezone?.value,
    language: components.languages?.value?.[0]?.[0],
    platform: components.platform?.value,
    cookiesEnabled: components.cookieEnabled?.value,
    localStorage: components.localStorage?.value
  };
}




export function parseUserAgent(userAgent: string) {
  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  return {
    browser_name: result.browser.name || null,
    browser_version: result.browser.version || null,
    browser_major_version: result.browser.major ? parseInt(result.browser.major) : null,
    os: result.os.name || null,
    os_version: result.os.version || null,
    engine: result.engine.name || null,
    engine_version: result.engine.version || null
  };
}













export async function enrichFingerprint(
  ctx: FingerprintRequestContext,
  fingerprintId: string,
  detailedFingerprint?: any,
  eventType: EnrichedFingerprint['eventType'] = 'session_validated',
  consentPreferences?: ConsentPreferenceData,
  options: FingerprintEnrichmentOptions = {}
): Promise<EnrichedFingerprint> {
  const config = getFingerprintConfig();
  const safeEventType = [
    'session_created', 'session_validated', 'fingerprint_mismatch', 'fingerprint_stored', 'consent_submission'
  ].includes(eventType) ? eventType : 'session_validated';

  return withSpan('fingerprint.enrichment', async (span: FingerprintSpan) => {
    span.setAttribute('fingerprint.event_type', safeEventType);

    
    const rawIpWithPort =
      ctx.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
      ctx.headers.get('x-real-ip') ||
      (ctx.getClientAddress ? ctx.getClientAddress() : null) ||
      'unknown';

    const rawIp = rawIpWithPort.includes(':') && !rawIpWithPort.startsWith('[')
      ? rawIpWithPort.split(':')[0]
      : rawIpWithPort;

    
    const isPrivateIPFn = config.isPrivateIP ?? (() => false);

    let fingerprintHash = '';
    if (config.hashFingerprint) {
      try {
        const candidate = await Promise.resolve(config.hashFingerprint(fingerprintId));
        if (typeof candidate === 'string' && candidate.length >= 32 && !candidate.includes(fingerprintId)) {
          fingerprintHash = candidate;
        }
      } catch {
        // Optional identity telemetry must not veto the caller's auth flow.
      }
    }
    const encryptedIp = safeTransform(rawIp, config.encryptIP);
    const hashedIp = safeTransform(rawIp, config.hashIp);
    let sessionCorrelationId: string | undefined;
    if (ctx.session?.id && config.deriveSessionCorrelation) {
      try {
        const candidate = await Promise.resolve(config.deriveSessionCorrelation(ctx.session.id));
        if (typeof candidate === 'string' && SESSION_CORRELATION_PATTERN.test(candidate) &&
            !candidate.includes(ctx.session.id)) {
          sessionCorrelationId = candidate;
        }
      } catch {
        // Correlation is optional telemetry. A failed port must never veto auth.
      }
    }

    
    const userAgent = ctx.headers.get('user-agent') || 'unknown';
    const deviceType = classifyDevice(userAgent);

    
    span.setAttribute('device.type', deviceType);
    if (fingerprintHash) span.setAttribute('fingerprint.hash', fingerprintHash);
    if (sessionCorrelationId) span.setAttribute('session.correlation_id', sessionCorrelationId);
    if (hashedIp) span.setAttribute('ip.hash', hashedIp);
    const ipType = rawIp === 'unknown' ? 'unknown' : isPrivateIPFn(rawIp) ? 'private' : 'public';
    span.setAttribute('ip.type', ipType);

    
    // Paths, queries and referrers can contain credentials. Retain only coarse
    // navigation shape, never a raw URL or user-controlled path segment.
    const rawReferrer = ctx.headers.get('referer') || null;
    const referrer = null;
    const currentUrl = '';
    let pathname = '/';
    let hostname = 'unknown';
    try {
      const url = new URL(ctx.url);
      pathname = url.pathname === '/' ? '/' : '/[redacted]';
      hostname = url.hostname;
    } catch {
      
    }

    span.setAttribute('navigation.pathname', pathname);
    span.setAttribute('navigation.hostname', hostname);
    if (rawReferrer) {
      try {
        const referrerUrl = new URL(rawReferrer);
        span.setAttribute('navigation.referrer_hostname', referrerUrl.hostname);
        span.setAttribute('navigation.is_external_referral', referrerUrl.hostname !== hostname);
      } catch {
        
      }
    }

    
    let geoLocation: EnrichedFingerprint['geoLocation'] = null;

    const devLat = ctx.headers.get('x-dev-latitude');
    const devLng = ctx.headers.get('x-dev-longitude');
    const devAccuracy = ctx.headers.get('x-dev-accuracy');

    if (devLat && devLng) {
      const latitude = parseFloat(devLat);
      const longitude = parseFloat(devLng);
      const accuracyRadius = devAccuracy ? parseFloat(devAccuracy) : null;

      span.setAttribute('geo.method', 'browser-geolocation');
      span.setAttribute('geo.latitude', latitude);
      span.setAttribute('geo.longitude', longitude);

      if (config.reverseGeocode) {
        const reverseGeoResult = await config.reverseGeocode(latitude, longitude, {
          fingerprintId,
          sessionId: null,
          sessionCorrelationId
        });

        if (reverseGeoResult) {
          geoLocation = {
            ...reverseGeoResult,
            latitude,
            longitude,
            accuracyRadius,
            source: 'browser-geolocation' as const
          };
        } else {
          geoLocation = {
            country: 'Unknown',
            countryCode: 'XX',
            city: null,
            latitude,
            longitude,
            timezone: null,
            accuracyRadius,
            source: 'browser-geolocation' as const
          };
        }
      } else {
        geoLocation = {
          country: 'Unknown',
          countryCode: 'XX',
          city: null,
          latitude,
          longitude,
          timezone: null,
          accuracyRadius,
          source: 'browser-geolocation' as const
        };
      }
    } else if (config.isGeoIPAvailable?.() && config.getLocation && rawIp !== 'unknown') {
      span.setAttribute('geo.method', 'maxmind-geoip');
      const location = config.getLocation(rawIp);

      if (location) {
        geoLocation = { ...location, source: 'maxmind-geoip' as const };
        if (typeof location.latitude === 'number' && Number.isFinite(location.latitude)) span.setAttribute('geo.latitude', location.latitude);
        if (typeof location.longitude === 'number' && Number.isFinite(location.longitude)) span.setAttribute('geo.longitude', location.longitude);
      } else {
        span.setAttribute('geo.lookup_result', 'not_found');
      }
    } else {
      span.setAttribute('geo.lookup_result', 'skipped');
    }

    
    const detectVPNFn = config.detectVPN ?? (async () => ({
      isVPN: false,
      provider: null,
      confidence: 'low' as const,
      method: 'unknown' as const
    }));
    const vpnDetection = await detectVPNFn(rawIp);

    
    const sessionCookiePresent = !!ctx.cookies?.get('session_id');
    const fingerprintCookiePresent = !!ctx.cookies?.get('fp_id');

    
    const userId = ctx.session?.userId || ctx.user?.id || null;
    const userHandle = ctx.user?.username || null;
    const userRole = ctx.user?.role || null;
    const sessionId = null;

    
    let userFlags: EnrichedFingerprint['userFlags'] | undefined;
    if (userId && config.userFlagsFetcher) {
      try {
        userFlags = await config.userFlagsFetcher.getUserFlags(userId);
      } catch (error) {
        logger.error('Failed to fetch user flags', {
          category: 'user_flags_fetch_failed'
        });
      }
    }

    
    const components = parseDetailedComponents(detailedFingerprint);

    
    let severity: EnrichedFingerprint['severity'] = 'info';
    if (safeEventType === 'fingerprint_mismatch') {
      severity = 'critical';
    } else if (vpnDetection.isVPN && vpnDetection.confidence === 'high') {
      severity = 'warning';
    }

    
    const enriched: EnrichedFingerprint = {
      fingerprintId,
      fingerprintHash,
      timestamp: new Date().toISOString(),
      sessionId,
      sessionCorrelationId,
      userId,
      userHandle,
      userRole,
      clientIp: '',
      clientIpEncrypted: encryptedIp,
      clientIpMasked: hashedIp,
      geoLocation,
      vpnDetection,
      userAgent,
      deviceType,
      navigation: { referrer, currentUrl, pathname, hostname },
      components,
      cookies: { sessionCookiePresent, fingerprintCookiePresent },
      userFlags,
      eventType: safeEventType,
      severity
    };

    
    if (config.calculateRiskScore) {
      try {
        const riskScore = config.calculateRiskScore(enriched, {
          previousLocation: null, 
          concurrentSessions: undefined
        });

        if (typeof riskScore.score === 'number' && Number.isFinite(riskScore.score)) span.setAttribute('risk.score', riskScore.score);
        if (['low', 'medium', 'high', 'critical'].includes(riskScore.tier)) span.setAttribute('risk.tier', riskScore.tier);
        if (Array.isArray(riskScore.factors)) span.setAttribute('risk.factor_count', riskScore.factors.length);

        if (riskScore.tier === 'critical') {
          enriched.severity = 'critical';
        } else if (riskScore.tier === 'high' && enriched.severity !== 'critical') {
          enriched.severity = 'warning';
        }

        enriched.riskScore = riskScore;
      } catch (riskError) {
        logger.warn('Failed to calculate risk score', {
          category: 'risk_score_failed'
        });
      }
    }

    
    span.setAttribute('enrichment.severity', enriched.severity);
    span.setAttribute('enrichment.vpn_detected', vpnDetection.isVPN === true);
    if (enriched.riskScore && ['low', 'medium', 'high', 'critical'].includes(enriched.riskScore.tier)) {
      span.setAttribute('enrichment.risk_tier', enriched.riskScore.tier);
    }

    
    if (geoLocation) {
      if (typeof geoLocation.latitude === 'number' && Number.isFinite(geoLocation.latitude)) {
        span.setAttribute('geo.latitude', geoLocation.latitude);
      }
      if (typeof geoLocation.longitude === 'number' && Number.isFinite(geoLocation.longitude)) {
        span.setAttribute('geo.longitude', geoLocation.longitude);
      }
    }

    
    if (consentPreferences?.consent) {
      const { categories, categoriesRecord, timestamp, version, preciseLocation, ageVerified } = consentPreferences.consent;

      if (categories && categories.length > 0 && categories.every((category) =>
        ['essential', 'preferences', 'functional', 'tracking', 'performance'].includes(category))) {
        span.setAttribute('consent.categories', JSON.stringify(categories));
      }
      if (categoriesRecord) {
        if (typeof categoriesRecord.essential === 'boolean') span.setAttribute('consent.categories.essential', String(categoriesRecord.essential));
        if (typeof categoriesRecord.preferences === 'boolean') span.setAttribute('consent.categories.preferences', String(categoriesRecord.preferences));
        if (typeof categoriesRecord.functional === 'boolean') span.setAttribute('consent.categories.functional', String(categoriesRecord.functional));
        if (typeof categoriesRecord.tracking === 'boolean') span.setAttribute('consent.categories.tracking', String(categoriesRecord.tracking));
        if (typeof categoriesRecord.performance === 'boolean') span.setAttribute('consent.categories.performance', String(categoriesRecord.performance));
      }
      if (timestamp && safeAdditionalAttribute('settings.preferences.theme.timestamp', timestamp)) span.setAttribute('consent.timestamp', timestamp);
      if (version && /^v?[0-9]+(?:\.[0-9]+){0,2}$/.test(version)) span.setAttribute('consent.version', version);
      if (typeof preciseLocation === 'boolean') span.setAttribute('consent.preciseLocation', String(preciseLocation));
      if (typeof ageVerified === 'boolean') span.setAttribute('consent.ageVerified', String(ageVerified));
      // Optional handle is user-controlled identity data, not needed in telemetry.
    }

    if (consentPreferences?.preferences) {
      const { theme, darkMode, a11y, contentPage } = consentPreferences.preferences;
      if (theme !== undefined && safeAdditionalAttribute('settings.preferences.theme', theme)) span.setAttribute('preferences.theme', theme);
      if (safeDarkMode(darkMode)) span.setAttribute('preferences.darkMode', darkMode);
      if (typeof a11y?.reducedMotion === 'boolean') span.setAttribute('preferences.a11y.reducedMotion', a11y.reducedMotion);
      if (typeof a11y?.highContrast === 'boolean') span.setAttribute('preferences.a11y.highContrast', a11y.highContrast);
      if (a11y?.fontSize && safeAdditionalAttribute('settings.a11y.fontSize', a11y.fontSize)) span.setAttribute('preferences.a11y.fontSize', a11y.fontSize);
      if (contentPage?.forceTheme && safeAdditionalAttribute('settings.preferences.theme', contentPage.forceTheme)) span.setAttribute('preferences.contentPage.forceTheme', contentPage.forceTheme);
      if (safeDarkMode(contentPage?.forceDarkMode)) span.setAttribute('preferences.contentPage.forceDarkMode', contentPage.forceDarkMode);
      if (typeof contentPage?.forceA11y === 'boolean') span.setAttribute('preferences.contentPage.forceA11y', contentPage.forceA11y);
    }

    if (options.additionalAttributes) {
      for (const [key, value] of Object.entries(options.additionalAttributes)) {
        if (safeAdditionalAttribute(key, value)) span.setAttribute(key, value);
      }
    }

    
    await logEnrichedFingerprint(enriched);

    return enriched;
  }, { kind: 1  });
}




async function logEnrichedFingerprint(enriched: EnrichedFingerprint): Promise<void> {
  const config = getFingerprintConfig();

  const stringLogData: Record<string, string> = {
    ...(enriched.fingerprintHash ? { fingerprint_hash: enriched.fingerprintHash } : {}),
    ...(enriched.sessionCorrelationId ? { session_correlation_id: enriched.sessionCorrelationId } : {}),
    ...(enriched.clientIpEncrypted ? { ip_encrypted: enriched.clientIpEncrypted } : {}),
    ...(enriched.clientIpMasked ? { ip_hash: enriched.clientIpMasked } : {}),
    vpn_detected: String(enriched.vpnDetection.isVPN === true),
    device_type: enriched.deviceType,
    event_type: enriched.eventType,
    severity: enriched.severity,
    component: 'fingerprint-enrichment',
    ...(Number.isFinite(enriched.riskScore?.score) ? { risk_score: String(enriched.riskScore?.score) } : {}),
  };

  logger.info('Fingerprint enrichment logged', stringLogData);

  
  if (config.fileLogger) {
    await config.fileLogger.write({
      level: enriched.severity === 'critical' ? 'warn' : 'info',
      message: 'Fingerprint enrichment logged',
      timestamp: Date.now(),
      component: 'fingerprint-enrichment',
      event_type: enriched.eventType,
      ...stringLogData
    });
  }
}




export async function enrichFingerprintOnSessionCreate(
  ctx: FingerprintRequestContext,
  fingerprintId: string,
  detailedFingerprint?: any,
  consentPreferences?: ConsentPreferenceData
): Promise<EnrichedFingerprint> {
  return enrichFingerprint(ctx, fingerprintId, detailedFingerprint, 'session_created', consentPreferences);
}




export async function enrichFingerprintOnValidation(
  ctx: FingerprintRequestContext,
  fingerprintId: string,
  consentPreferences?: ConsentPreferenceData
): Promise<EnrichedFingerprint> {
  return enrichFingerprint(ctx, fingerprintId, undefined, 'session_validated', consentPreferences);
}




export async function enrichFingerprintOnMismatch(
  ctx: FingerprintRequestContext,
  fingerprintId: string,
  expectedHash: string,
  receivedHash: string,
  consentPreferences?: ConsentPreferenceData
): Promise<EnrichedFingerprint> {
  const enriched = await enrichFingerprint(ctx, fingerprintId, undefined, 'fingerprint_mismatch', consentPreferences);

  logger.error('SECURITY ALERT: Fingerprint mismatch detected', {
    ...(enriched.fingerprintHash ? { fingerprint_hash: enriched.fingerprintHash } : {}),
    ...(enriched.sessionCorrelationId ? { session_correlation_id: enriched.sessionCorrelationId } : {}),
    alert_type: 'session_hijacking',
    risk_level: 'critical',
    vpn_detected: enriched.vpnDetection.isVPN ? 'true' : 'false',
    device_type: enriched.deviceType,
  });

  return enriched;
}




export function getEnrichmentServiceHealth() {
  const config = getFingerprintConfig();
  return {
    geoipAvailable: config.isGeoIPAvailable?.() ?? false,
    vpnDetectionEnabled: !!config.detectVPN,
    fingerprintHashingEnabled: !!config.hashFingerprint,
    userFlagsEnabled: !!config.userFlagsFetcher,
    lokiLoggingEnabled: !!config.fileLogger
  };
}
