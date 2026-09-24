









import type { RiskScoreResult } from '../config.js';




export type DeviceType = 'mobile' | 'tablet' | 'desktop' | 'unknown';





export interface EnrichedFingerprint {
  
  fingerprintId: string; 
  fingerprintHash: string; // Empty unless a non-identity hash port is configured.
  timestamp: string; 

  
  sessionId: string | null; // Kept for source compatibility; always null on new enrichment.
  /** Server-supplied non-bearer correlation; never a raw session ID. */
  sessionCorrelationId?: string;
  userId: string | null;
  userHandle: string | null;
  userRole: string | null;

  
  clientIp: string; // Raw IP is never returned; always empty on new enrichment.
  clientIpEncrypted: string; // Empty unless a non-identity encryption port is configured.
  clientIpMasked: string; // Empty unless a non-identity hash port is configured.

  
  geoLocation: {
    country: string;
    countryCode: string;
    city: string | null;
    latitude: number | null;
    longitude: number | null;
    timezone: string | null;
    accuracyRadius: number | null;
    source?: 'browser-geolocation' | 'maxmind-geoip' | 'mock-development';
  } | null;

  
  vpnDetection: {
    isVPN: boolean;
    provider: string | null; 
    confidence: 'low' | 'medium' | 'high';
    method: 'asn' | 'datacenter' | 'unknown'; 
    details?: string;
  };

  
  userAgent: string; 
  deviceType: DeviceType; 

  
  navigation: {
    referrer: string | null; 
    currentUrl: string; 
    pathname: string; 
    hostname: string; 
  };

  
  components: {
    canvas?: string; 
    webgl?: string; 
    audio?: string; 
    fonts?: string[]; 
    plugins?: string[]; 
    screenResolution?: string; 
    timezone?: string; 
    language?: string; 
    platform?: string; 
    cookiesEnabled?: boolean;
    localStorage?: boolean;
  };

  
  cookies: {
    sessionCookiePresent: boolean;
    fingerprintCookiePresent: boolean;
    
  };

  
  userFlags?: {
    totpEnabled: boolean;
    isActive: boolean;
    lastLogin: string | null;
    loginCount: number;
    failedLoginAttempts: number;
  };

  
  eventType:
    | 'session_created'
    | 'session_validated'
    | 'fingerprint_mismatch'
    | 'fingerprint_stored'
    | 'consent_submission';
  severity: 'info' | 'warning' | 'critical';

  
  riskScore?: RiskScoreResult;
}
