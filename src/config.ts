












export interface FingerprintLogger {
  info: (...args: any[]) => void;
  warn: (...args: any[]) => void;
  error: (...args: any[]) => void;
  debug: (...args: any[]) => void;
}




export interface FingerprintFileLogger {
  write: (entry: {
    level: string;
    message: string;
    timestamp: number;
    component: string;
    event_type: string;
    [key: string]: any;
  }) => Promise<void>;
}




export interface FingerprintSpan {
  setAttribute: (key: string, value: any) => void;
  recordException: (error: Error) => void;
  setStatus: (status: { code: number; message?: string }) => void;
  end: () => void;
}




export interface FingerprintTracer {
  startActiveSpan: <T>(name: string, fn: (span: FingerprintSpan) => Promise<T>) => Promise<T>;
}




export interface GeoLocationResult {
  country: string;
  countryCode: string;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  accuracyRadius: number | null;
  source?: 'browser-geolocation' | 'maxmind-geoip' | 'mock-development';
}




export interface VPNDetectionResult {
  isVPN: boolean;
  provider: string | null;
  confidence: 'low' | 'medium' | 'high';
  method: 'asn' | 'datacenter' | 'unknown';
  details?: string;
}




export interface RiskScoreResult {
  score: number;
  tier: 'low' | 'medium' | 'high' | 'critical';
  factors: Array<{ name: string; score: number; description: string }>;
  recommendation: string;
}




export interface ObservabilityFetcher {
  fetchLoki: (path: string, options?: RequestInit) => Promise<Response>;
}




export interface TempoQueryServiceInterface {
  queryFingerprints: (
    timeRange: string,
    filters: Record<string, string>,
    limit?: number
  ) => Promise<any[]>;
  searchTraces: (
    traceQL: string,
    startSeconds: number,
    endSeconds: number
  ) => Promise<any[]>;
  getTagValueSuggestions: (
    tagName: string,
    prefix: string,
    limit?: number
  ) => Promise<string[]>;
}




export interface ChildSpanReaderInterface {
  readGeo: (trace: any) => Promise<{
    country: string;
    city: string | null;
    latitude: number | null;
    longitude: number | null;
    source: string;
  } | null>;
}




export interface UserFlagsFetcher {
  getUserFlags: (userId: string) => Promise<{
    totpEnabled: boolean;
    isActive: boolean;
    lastLogin: string | null;
    loginCount: number;
    failedLoginAttempts: number;
  } | undefined>;
}




export type ReverseGeocodeFn = (
  latitude: number,
  longitude: number,
  context?: { fingerprintId?: string; sessionId?: string | null; sessionCorrelationId?: string }
) => Promise<GeoLocationResult | null>;




export interface ConsentCategories {
  essential: boolean;
  preferences: boolean;
  functional: boolean;
  tracking: boolean;
  performance: boolean;
}




export const DEFAULT_CONSENT: ConsentCategories = {
  essential: true,
  preferences: false,
  functional: false,
  tracking: false,
  performance: false,
};




export interface RestorableSettings {
  lastKnownLocation: {
    city: string | null;
    country: string;
    latitude: number | null;
    longitude: number | null;
  };
  deviceContext: {
    deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown';
    browserName: string;
    browserVersion: string;
    os: string;
  };
  lastVisit: {
    pathname: string;
    timestamp: string;
    referrerHostname: string | null;
  };
  userContext: {
    handle: string | null;
    role: string | null;
  };
  a11yPreferences: {
    reducedMotion: boolean;
    highContrast: boolean;
    screenReaderDetected: boolean;
  };
  preferences?: {
    theme?: string;
    darkMode?: 'light' | 'dark' | 'system';
    a11y?: {
      reducedMotion?: boolean;
      highContrast?: boolean;
      fontSize?: 'normal' | 'large' | 'x-large';
    };
  };
  consentCategories?: ConsentCategories;
}




export interface ConsentRecord {
  fingerprintId: string;
  categories: ConsentCategories;
  preciseLocation: boolean;
  ageVerified: boolean;
  optionalHandle: string | null;
  preferences: {
    theme: string;
    darkMode: 'light' | 'dark' | 'system';
  };
  consentTimestamp: string;
  consentVersion: string;
}










export interface FingerprintConfig {
  
  logger?: FingerprintLogger;
  scopedLogger?: (scope: string) => FingerprintLogger;

  
  createSpan?: <T>(
    name: string,
    fn: (span: FingerprintSpan) => Promise<T>,
    options?: { kind?: number }
  ) => Promise<T>;
  getTracer?: () => FingerprintTracer;

  
  hashFingerprint?: (fp: string) => string | Promise<string>;
  hashIp?: (ip: string) => string;
  encryptIP?: (ip: string) => string;
  /** Server-only HMAC derivation; never pass through the raw bearer value. */
  deriveSessionCorrelation?: (rawSessionId: string) => string | Promise<string>;
  calculateRiskScore?: (enriched: any, context?: any) => RiskScoreResult;
  detectVPN?: (ip: string) => Promise<VPNDetectionResult>;
  isPrivateIP?: (ip: string) => boolean;
  getLocation?: (ip: string) => GeoLocationResult | null;
  isGeoIPAvailable?: () => boolean;
  reverseGeocode?: ReverseGeocodeFn;

  
  fileLogger?: FingerprintFileLogger;

  
  observabilityFetcher?: ObservabilityFetcher;
  tempoQueryService?: TempoQueryServiceInterface;
  childSpanReader?: ChildSpanReaderInterface;

  
  userFlagsFetcher?: UserFlagsFetcher;

  
  lokiUrl?: string;

  
  dataDir?: string;

  
  defaultConsent?: ConsentCategories;

  
  nodeEnv?: string;
}





const noopLogger: FingerprintLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
};

const consoleLogger: FingerprintLogger = {
  info: (...args: any[]) => console.log('[fingerprint:info]', ...args),
  warn: (...args: any[]) => console.warn('[fingerprint:warn]', ...args),
  error: (...args: any[]) => console.error('[fingerprint:error]', ...args),
  debug: (...args: any[]) => console.debug('[fingerprint:debug]', ...args),
};

let _config: FingerprintConfig = {};
















export function configureFingerprint(config: Partial<FingerprintConfig>): void {
  _config = { ..._config, ...config };
}






export function getFingerprintConfig(): Required<
  Pick<FingerprintConfig, 'logger' | 'nodeEnv' | 'defaultConsent'>
> &
  FingerprintConfig {
  return {
    ..._config,
    logger: _config.logger ?? consoleLogger,
    nodeEnv: _config.nodeEnv ?? (typeof process !== 'undefined' ? process.env.NODE_ENV ?? 'development' : 'development'),
    defaultConsent: _config.defaultConsent ?? DEFAULT_CONSENT,
  };
}







export function getScopedLogger(scope: string): FingerprintLogger {
  const config = getFingerprintConfig();
  if (config.scopedLogger) {
    return config.scopedLogger(scope);
  }
  return config.logger;
}




export function resetFingerprintConfig(): void {
  _config = {};
}




export const noopSpan: FingerprintSpan = {
  setAttribute: () => {},
  recordException: () => {},
  setStatus: () => {},
  end: () => {},
};




export async function withSpan<T>(
  name: string,
  fn: (span: FingerprintSpan) => Promise<T>,
  options?: { kind?: number }
): Promise<T> {
  const config = getFingerprintConfig();
  if (config.createSpan) {
    return config.createSpan(name, fn, options);
  }
  return fn(noopSpan);
}




export async function withTracerSpan<T>(
  name: string,
  fn: (span: FingerprintSpan) => Promise<T>
): Promise<T> {
  const config = getFingerprintConfig();
  if (config.getTracer) {
    const tracer = config.getTracer();
    return tracer.startActiveSpan(name, fn);
  }
  return fn(noopSpan);
}
