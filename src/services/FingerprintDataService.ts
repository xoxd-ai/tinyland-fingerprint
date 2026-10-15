/**
 * Service for fetching fingerprint intelligence data.
 *
 * **ARCHITECTURE**:
 * - PRIMARY: Tempo traces (FingerprintEnrichmentService writes spans with rich attributes)
 * - FALLBACK 1: Loki logs (component="fingerprint-enrichment")
 * - FALLBACK 2: Local file (development only)
 *
 * All external dependencies are injected via the config module.
 *
 * @module services/FingerprintDataService
 */

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { getScopedLogger, getFingerprintConfig } from '../config.js';
import type { MapMarker, HeatmapPoint, FingerprintGeoData } from '../types/maps.js';

const logger = getScopedLogger('fingerprint-data-service');

/**
 * Fingerprint record from Loki/Tempo/file sources.
 */
export interface FingerprintRecord {
  timestamp: string;
  fingerprintId: string;
  fingerprintHash: string;
  userId?: string;
  userHandle?: string;
  sessionId?: string;

  // Geographic data
  geoCountry?: string;
  geoCity?: string;
  geoLatitude?: number;
  geoLongitude?: number;

  // VPN detection
  vpnDetected: boolean;
  vpnProvider?: string;
  vpnConfidence?: string;

  // Device & browser info
  deviceType?: string;
  browserName?: string;
  browserVersion?: string;
  os?: string;
  osVersion?: string;
  userAgent?: string;

  // Request details
  url?: string;
  clientIp?: string;

  // Navigation context
  referrer?: string | null;
  currentUrl?: string;
  pathname?: string;
  hostname?: string;

  // Risk scoring
  riskScore?: number;
  riskTier?: string;
  eventType: string;
}

export interface FingerprintUserSelector {
  userId?: string;
  userHandle?: string | null;
}

export type FingerprintDataPlaneSource = 'tempo' | 'loki' | 'file';

export interface FingerprintDataPlaneHealth {
  tempoAvailable?: boolean;
  lokiAvailable?: boolean;
  localFileAvailable?: boolean;
  nodeEnv?: string;
}

export interface FingerprintDataPlaneAvailability {
  primarySource: 'tempo';
  recordSourceOrder: readonly FingerprintDataPlaneSource[];
  activeRecordSources: readonly FingerprintDataPlaneSource[];
  primaryAvailable: boolean;
  fallbackAvailable: boolean;
  recordsAvailable: boolean;
  statsAvailable: boolean;
  geoAvailable: boolean;
  searchAvailable: boolean;
  historyAvailable: boolean;
}

export const FINGERPRINT_DATA_PLANE_CONTRACT = {
  primarySource: 'tempo',
  recordSourceOrder: ['tempo', 'loki', 'file'],
  fallbackSources: ['loki'],
  developmentOnlySources: ['file'],
  searchSource: 'tempo',
  historySource: 'tempo'
} as const satisfies {
  primarySource: 'tempo';
  recordSourceOrder: readonly FingerprintDataPlaneSource[];
  fallbackSources: readonly FingerprintDataPlaneSource[];
  developmentOnlySources: readonly FingerprintDataPlaneSource[];
  searchSource: 'tempo';
  historySource: 'tempo';
};

/**
 * Resolve the package-owned fingerprint data-plane contract for app consumers.
 *
 * Tempo is the primary authority. Loki is a records/stats fallback. Local file
 * reads are development-only. Search and per-user history remain Tempo-only.
 */
export function resolveFingerprintDataPlaneAvailability(
  health: FingerprintDataPlaneHealth = {}
): FingerprintDataPlaneAvailability {
  const nodeEnv = health.nodeEnv
    ?? (typeof process !== 'undefined' ? process.env.NODE_ENV ?? 'development' : 'development');
  const primaryAvailable = health.tempoAvailable === true;
  const lokiAvailable = health.lokiAvailable === true;
  const fileAvailable = nodeEnv !== 'production' && health.localFileAvailable === true;
  const activeRecordSources = FINGERPRINT_DATA_PLANE_CONTRACT.recordSourceOrder.filter((source) => {
    if (source === 'tempo') return primaryAvailable;
    if (source === 'loki') return lokiAvailable;
    return fileAvailable;
  });
  const recordsAvailable = activeRecordSources.length > 0;

  return {
    primarySource: FINGERPRINT_DATA_PLANE_CONTRACT.primarySource,
    recordSourceOrder: FINGERPRINT_DATA_PLANE_CONTRACT.recordSourceOrder,
    activeRecordSources,
    primaryAvailable,
    fallbackAvailable: !primaryAvailable && (lokiAvailable || fileAvailable),
    recordsAvailable,
    statsAvailable: recordsAvailable,
    geoAvailable: recordsAvailable,
    searchAvailable: primaryAvailable,
    historyAvailable: primaryAvailable
  };
}

/**
 * Shape of a Loki `query_range` stream response, as read by this service.
 * `Response.json()` is typed `Promise<unknown>` in current undici/@types/node,
 * so the parsed body is narrowed to this explicitly.
 */
interface LokiStreamQueryResponse {
  data?: {
    result?: Array<{
      stream?: Record<string, string>;
      values: Array<[string, string]>;
    }>;
  };
}

interface FingerprintStats {
  totalFingerprints: number;
  vpnUsers: number;
  vpnPercentage: number;
  highRiskCount: number;
  uniqueCountries: number;
  byCountry: Array<{ name: string; code: string; flag: string; count: number; vpnPercentage: number }>;
  byDevice: Array<{ device: string; count: number }>;
  highRiskFingerprints: Array<{ id: string; country: string; riskScore: number; userId?: string }>;
  recentChanges: Array<{ timestamp: string; userId: string; userHandle?: string; country: string; eventType: string }>;
}

/**
 * Service for fetching fingerprint intelligence data.
 */
export class FingerprintDataService {
  private lokiUrl: string;
  private useTempo: boolean;

  constructor() {
    const config = getFingerprintConfig();
    this.lokiUrl = config.lokiUrl ?? 'http://localhost:3100';
    // Enable Tempo by default (can be disabled via env var for rollback)
    this.useTempo = typeof process !== 'undefined'
      ? process.env.DISABLE_TEMPO_FINGERPRINTS !== 'true'
      : true;
  }

  private getExpandedLimit(limit: number): number {
    return Math.min(Math.max(limit * 10, 200), 1000);
  }

  private matchesUserRecord(record: FingerprintRecord, selector: FingerprintUserSelector): boolean {
    return Boolean(
      (selector.userId && record.userId === selector.userId) ||
      (selector.userHandle && record.userHandle === selector.userHandle)
    );
  }

  private deduplicateRecords(records: FingerprintRecord[]): FingerprintRecord[] {
    const seen = new Set<string>();
    return records.filter((record) => {
      const key = `${record.timestamp}|${record.fingerprintId}|${record.sessionId ?? ''}|${record.userId ?? ''}|${record.userHandle ?? ''}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  private getUserFilters(selector: FingerprintUserSelector): Record<string, string>[] {
    const filters: Record<string, string>[] = [];
    if (selector.userId) {
      filters.push({ 'user.id': selector.userId });
    }
    if (selector.userHandle && selector.userHandle !== selector.userId) {
      filters.push({ 'user.handle': selector.userHandle });
    }
    return filters;
  }

  private async getFingerprintRecordsFromLokiQuery(
    query: string,
    timeRange: string = '7d',
    limit: number = 200
  ): Promise<FingerprintRecord[]> {
    const config = getFingerprintConfig();
    if (!config.observabilityFetcher) {
      return [];
    }

    const end = Date.now();
    const start = end - this.parseTimeRange(timeRange);
    const cappedLimit = Math.min(limit, 1000);
    const path = `/loki/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}000000&end=${end}000000&limit=${cappedLimit}`;

    const response = await config.observabilityFetcher.fetchLoki(path);
    if (!response.ok) {
      throw new Error(`Loki query failed: ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as LokiStreamQueryResponse;
    const records: FingerprintRecord[] = [];

    if (data.data?.result) {
      for (const stream of data.data.result) {
        for (const [timestamp, logLine] of stream.values) {
          try {
            const parsed = JSON.parse(logLine as string);
            records.push({
              timestamp: new Date(parseInt(timestamp as string) / 1000000).toISOString(),
              fingerprintId: parsed.fingerprint_id,
              fingerprintHash: parsed.fingerprint_hash,
              userId: parsed.user_id,
              userHandle: parsed.user_handle,
              sessionId: parsed.session_id,
              geoCountry: parsed.geo_country,
              geoCity: parsed.geo_city,
              geoLatitude: parsed.geo_latitude != null ? parseFloat(parsed.geo_latitude) : undefined,
              geoLongitude: parsed.geo_longitude != null ? parseFloat(parsed.geo_longitude) : undefined,
              vpnDetected: parsed.vpn_detected === true || parsed.vpn_detected === 'true',
              vpnProvider: parsed.vpn_provider,
              vpnConfidence: parsed.vpn_confidence,
              deviceType: parsed.device_type,
              browserName: parsed.browser_name,
              browserVersion: parsed.browser_version,
              os: parsed.os,
              osVersion: parsed.os_version,
              userAgent: parsed.user_agent,
              url: parsed.current_url || parsed.pathname,
              clientIp: parsed.ip_raw || parsed.client_ip,
              riskScore: parsed.risk_score ? parseInt(parsed.risk_score) : undefined,
              riskTier: parsed.risk_tier,
              eventType: parsed.event_type
            });
          } catch (_err) {
            logger.warn('Failed to parse fingerprint log line');
          }
        }
      }
    }

    return records.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  /**
   * Development fallback: Read fingerprint records from local log file.
   */
  private async getFingerprintRecordsFromFile(timeRange: string = '7d', limit: number = 500): Promise<FingerprintRecord[]> {
    try {
      const config = getFingerprintConfig();
      const LOG_FILE = config.nodeEnv === 'production'
        ? '/app/logs/observability.log'
        : join(config.dataDir ?? process.cwd(), 'logs', 'observability.log');

      if (!existsSync(LOG_FILE)) {
        logger.info('Local log file does not exist', { path: LOG_FILE });
        return [];
      }

      logger.info('Reading fingerprint records from local file (development fallback)', { path: LOG_FILE });

      const content = await readFile(LOG_FILE, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);

      const end = Date.now();
      const start = end - this.parseTimeRange(timeRange);

      const records: FingerprintRecord[] = [];

      for (const line of lines.slice(-limit)) {
        try {
          const parsed = JSON.parse(line);

          // Filter by component and time range
          if (parsed.component !== 'fingerprint-enrichment') continue;

          const timestamp = parsed.timestamp || Date.now();
          if (timestamp < start || timestamp > end) continue;

          records.push({
            timestamp: new Date(timestamp).toISOString(),
            fingerprintId: parsed.fingerprint_id,
            fingerprintHash: parsed.fingerprint_hash,
            userId: parsed.user_id,
            userHandle: parsed.user_handle,
            sessionId: parsed.session_id,

            // Geographic
            geoCountry: parsed.geo_country,
            geoCity: parsed.geo_city,
            geoLatitude: parsed.geo_latitude != null ? parseFloat(parsed.geo_latitude) : undefined,
            geoLongitude: parsed.geo_longitude != null ? parseFloat(parsed.geo_longitude) : undefined,

            // VPN
            vpnDetected: parsed.vpn_detected === true || parsed.vpn_detected === 'true',
            vpnProvider: parsed.vpn_provider,
            vpnConfidence: parsed.vpn_confidence,

            // Device & Browser
            deviceType: parsed.device_type,
            browserName: parsed.browser_name,
            browserVersion: parsed.browser_version,
            os: parsed.os,
            osVersion: parsed.os_version,
            userAgent: parsed.user_agent,

            // Request details
            url: parsed.url,
            clientIp: parsed.client_ip || parsed.ip_raw,

            // Navigation context
            referrer: parsed.referrer,
            currentUrl: parsed.current_url,
            pathname: parsed.pathname,
            hostname: parsed.hostname,

            // Risk
            riskScore: parsed.risk_score ? parseInt(parsed.risk_score) : undefined,
            riskTier: parsed.risk_tier,
            eventType: parsed.event_type
          });
        } catch (_err) {
          // Skip malformed lines
          logger.debug('Skipped malformed log line');
        }
      }

      logger.info('Fetched fingerprint records from local file', { count: records.length });
      return records.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    } catch (error) {
      logger.error('Failed to read fingerprint records from local file', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Query fingerprint data with cascading fallback.
   *
   * 1. PRIMARY: Tempo traces (if enabled)
   * 2. FALLBACK 1: Loki logs
   * 3. FALLBACK 2: Local file (development only)
   */
  async getFingerprintRecords(timeRange: string = '7d', limit: number = 200): Promise<FingerprintRecord[]> {
    const config = getFingerprintConfig();

    // Try Tempo first (primary source)
    if (this.useTempo && config.tempoQueryService) {
      try {
        logger.info('Fetching fingerprint records from Tempo (primary)', { timeRange, limit });
        const tempoRecords = await config.tempoQueryService.queryFingerprints(timeRange, {}, limit);
        const records = this.convertTempoRecords(tempoRecords);
        logger.info('Tempo query successful', { count: records.length, source: 'tempo' });
        return records;
      } catch (tempoError) {
        logger.warn('Tempo query failed, falling back to Loki', {
          error: tempoError instanceof Error ? tempoError.message : String(tempoError),
          source: 'tempo'
        });
      }
    }

    // Fallback 1: Loki logs
    if (config.observabilityFetcher) {
      try {
        const end = Date.now();
        const start = end - this.parseTimeRange(timeRange);

        const query = `{component="fingerprint-enrichment"} | json`;
        const cappedLimit = Math.min(limit, 1000);
        const path = `/loki/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}000000&end=${end}000000&limit=${cappedLimit}`;

        logger.info('Fetching fingerprint records from Loki (fallback)', { timeRange, limit, query });

        const response = await config.observabilityFetcher.fetchLoki(path);
        if (!response.ok) {
          throw new Error(`Loki query failed: ${response.status} ${response.statusText}`);
        }

        const data = (await response.json()) as LokiStreamQueryResponse;

        const records: FingerprintRecord[] = [];
        if (data.data?.result) {
          for (const stream of data.data.result) {
            for (const [timestamp, logLine] of stream.values) {
              try {
                const parsed = JSON.parse(logLine as string);
                records.push({
                  timestamp: new Date(parseInt(timestamp as string) / 1000000).toISOString(),
                  fingerprintId: parsed.fingerprint_id,
                  fingerprintHash: parsed.fingerprint_hash,
                  userId: parsed.user_id,
                  userHandle: parsed.user_handle,
                  sessionId: parsed.session_id,
                  geoCountry: parsed.geo_country,
                  geoCity: parsed.geo_city,
                  geoLatitude: parsed.geo_latitude != null ? parseFloat(parsed.geo_latitude) : undefined,
                  geoLongitude: parsed.geo_longitude != null ? parseFloat(parsed.geo_longitude) : undefined,
                  vpnDetected: parsed.vpn_detected === true || parsed.vpn_detected === 'true',
                  vpnProvider: parsed.vpn_provider,
                  vpnConfidence: parsed.vpn_confidence,
                  deviceType: parsed.device_type,
                  browserName: parsed.browser_name,
                  browserVersion: parsed.browser_version,
                  os: parsed.os,
                  osVersion: parsed.os_version,
                  userAgent: parsed.user_agent,
                  url: parsed.current_url || parsed.pathname,
                  clientIp: parsed.ip_raw || parsed.client_ip,
                  riskScore: parsed.risk_score ? parseInt(parsed.risk_score) : undefined,
                  riskTier: parsed.risk_tier,
                  eventType: parsed.event_type
                });
              } catch (_err) {
                logger.warn('Failed to parse fingerprint log line');
              }
            }
          }
        }

        logger.info('Loki query successful', { count: records.length, source: 'loki' });
        return records.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
      } catch (error) {
        logger.warn('Loki query failed, falling back to local file (development)', {
          error: error instanceof Error ? error.message : 'Unknown error',
          source: 'loki'
        });
      }
    }

    // Fallback 2: Read from local file in development
    if (config.nodeEnv !== 'production') {
      const records = await this.getFingerprintRecordsFromFile(timeRange, limit);
      logger.info('Local file read successful', { count: records.length, source: 'file' });
      return records;
    }

    logger.error('All fingerprint data sources failed', { source: 'all' });
    return [];
  }

  async getFingerprintRecordsForUser(
    selector: FingerprintUserSelector,
    timeRange: string = '7d',
    limit: number = 200
  ): Promise<FingerprintRecord[]> {
    const config = getFingerprintConfig();
    const filters = this.getUserFilters(selector);

    if (filters.length === 0) {
      return [];
    }

    const tempoRecords = await this.getTempoFingerprintRecordsForUser(selector, timeRange, limit);
    if (tempoRecords.length > 0) {
      return tempoRecords;
    }

    if (this.useTempo && config.tempoQueryService) {
      logger.info('Tempo user fingerprint query returned no records, falling back to targeted non-Tempo queries', {
        userId: selector.userId,
        userHandle: selector.userHandle,
        source: 'tempo'
      });
    }

    if (config.observabilityFetcher) {
      try {
        const lokiQueries = [
          selector.userId ? `{component="fingerprint-enrichment"} | json | user_id="${selector.userId}"` : null,
          selector.userHandle && selector.userHandle !== selector.userId
            ? `{component="fingerprint-enrichment"} | json | user_handle="${selector.userHandle}"`
            : null
        ].filter((query): query is string => Boolean(query));

        const lokiResults = await Promise.all(
          lokiQueries.map((query) => this.getFingerprintRecordsFromLokiQuery(query, timeRange, limit))
        );
        const records = this.deduplicateRecords(
          lokiResults
            .flat()
            .filter((record) => this.matchesUserRecord(record, selector))
        ).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

        if (records.length > 0) {
          logger.info('Loki user fingerprint query successful', {
            userId: selector.userId,
            userHandle: selector.userHandle,
            count: records.length,
            source: 'loki'
          });
          return records.slice(0, limit);
        }
      } catch (lokiError) {
        logger.warn('Loki user fingerprint query failed, falling back to targeted file filtering', {
          userId: selector.userId,
          userHandle: selector.userHandle,
          error: lokiError instanceof Error ? lokiError.message : String(lokiError),
          source: 'loki'
        });
      }
    }

    if (config.nodeEnv !== 'production') {
      const fileRecords = await this.getFingerprintRecordsFromFile(timeRange, this.getExpandedLimit(limit));
      return fileRecords
        .filter((record) => this.matchesUserRecord(record, selector))
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, limit);
    }

    logger.info('No targeted fingerprint records found for user selector', {
      userId: selector.userId,
      userHandle: selector.userHandle,
      source: 'none'
    });
    return [];
  }

  async getTempoFingerprintRecordsForUser(
    selector: FingerprintUserSelector,
    timeRange: string = '7d',
    limit: number = 200
  ): Promise<FingerprintRecord[]> {
    const config = getFingerprintConfig();
    const filters = this.getUserFilters(selector);

    if (filters.length === 0 || !this.useTempo || !config.tempoQueryService) {
      return [];
    }

    try {
      const tempoResults = await Promise.all(
        filters.map((filter) => config.tempoQueryService!.queryFingerprints(timeRange, filter, limit))
      );
      const records = this.deduplicateRecords(
        tempoResults
          .flatMap((result) => this.convertTempoRecords(result))
          .filter((record) => this.matchesUserRecord(record, selector))
      ).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      if (records.length > 0) {
        logger.info('Tempo user fingerprint query successful', {
          userId: selector.userId,
          userHandle: selector.userHandle,
          count: records.length,
          source: 'tempo'
        });
        return records.slice(0, limit);
      }
    } catch (tempoError) {
      logger.warn('Tempo user fingerprint query failed', {
        userId: selector.userId,
        userHandle: selector.userHandle,
        error: tempoError instanceof Error ? tempoError.message : String(tempoError),
        source: 'tempo'
      });
    }
    return [];
  }

  /**
   * Convert Tempo records to FingerprintRecord format.
   */
  private convertTempoRecords(tempoRecords: any[]): FingerprintRecord[] {
    return tempoRecords.map((tr: any) => ({
      timestamp: tr.timestamp,
      fingerprintId: tr.fingerprintId,
      fingerprintHash: tr.fingerprintHash || '',
      userId: tr.userId,
      userHandle: tr.userHandle,
      sessionId: tr.sessionId,
      geoCountry: tr.geoCountry,
      geoCity: tr.geoCity,
      geoLatitude: tr.geoLatitude,
      geoLongitude: tr.geoLongitude,
      vpnDetected: tr.vpnDetected || false,
      vpnProvider: tr.vpnProvider,
      vpnConfidence: tr.vpnConfidence,
      deviceType: tr.deviceType,
      riskScore: tr.riskScore,
      riskTier: tr.riskTier,
      eventType: tr.eventType
    }));
  }

  /**
   * Get all records for a specific fingerprint within time window.
   */
  async getFingerprintRecordsById(
    fingerprintId: string,
    timeRange: string = '7d'
  ): Promise<FingerprintRecord[]> {
    const config = getFingerprintConfig();
    try {
      // Try Tempo first (if enabled)
      if (this.useTempo && config.tempoQueryService) {
        try {
          const tempoRecords = await config.tempoQueryService.queryFingerprints(timeRange, { 'fingerprint.id': fingerprintId });
          if (tempoRecords.length > 0) {
            logger.info('Tempo query successful', {
              fingerprintId,
              count: tempoRecords.length,
              source: 'tempo'
            });
            return this.convertTempoRecords(tempoRecords).sort(
              (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
            );
          }
        } catch (tempoError) {
          logger.warn('Tempo query failed, falling back to Loki', {
            fingerprintId,
            error: tempoError instanceof Error ? tempoError.message : 'Unknown error'
          });
        }
      }

      // Fallback to Loki
      if (config.observabilityFetcher) {
        const response = await config.observabilityFetcher.fetchLoki('/loki/api/v1/query_range', {
          method: 'POST',
          body: JSON.stringify({
            query: `{job="stonewall-observability"} | json | component="fingerprint-enrichment" | fingerprint_id="${fingerprintId}"`,
            start: this.calculateStartTime(timeRange),
            end: Date.now() * 1000000,
            limit: 10000
          })
        });

        const data = (await response.json()) as LokiStreamQueryResponse;
        const records: FingerprintRecord[] = [];

        if (data.data?.result) {
          for (const stream of data.data.result) {
            for (const [timestamp, logLine] of stream.values) {
              try {
                const parsed = JSON.parse(logLine as string);
                records.push({
                  timestamp: new Date(parseInt(timestamp as string) / 1000000).toISOString(),
                  fingerprintId: parsed.fingerprint_id,
                  fingerprintHash: parsed.fingerprint_hash,
                  userId: parsed.user_id,
                  userHandle: parsed.user_handle,
                  sessionId: parsed.session_id,
                  geoCountry: parsed.geo_country,
                  geoCity: parsed.geo_city,
                  geoLatitude: parsed.geo_latitude != null ? parseFloat(parsed.geo_latitude) : undefined,
                  geoLongitude: parsed.geo_longitude != null ? parseFloat(parsed.geo_longitude) : undefined,
                  vpnDetected: parsed.vpn_detected === true || parsed.vpn_detected === 'true',
                  vpnProvider: parsed.vpn_provider,
                  vpnConfidence: parsed.vpn_confidence,
                  deviceType: parsed.device_type,
                  riskScore: parsed.risk_score ? parseInt(parsed.risk_score) : undefined,
                  riskTier: parsed.risk_tier,
                  eventType: parsed.event_type,
                  url: parsed.url,
                  clientIp: parsed.client_ip || parsed.ip_raw,
                  referrer: parsed.referrer,
                  currentUrl: parsed.current_url,
                  pathname: parsed.pathname,
                  hostname: parsed.hostname,
                  browserName: this.parseBrowserName(parsed.user_agent),
                  browserVersion: this.parseBrowserVersion(parsed.user_agent),
                  os: this.parseOperatingSystem(parsed.user_agent),
                  userAgent: parsed.user_agent
                });
              } catch (_err) {
                logger.warn('Failed to parse fingerprint log line');
              }
            }
          }
        }

        logger.info('Loki query successful', {
          fingerprintId,
          count: records.length,
          source: 'loki'
        });

        return records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      }

      return [];
    } catch (error) {
      logger.error('Failed to get fingerprint records by ID', {
        fingerprintId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Get total unique fingerprints.
   */
  async getTotalFingerprints(timeRange: string = '7d'): Promise<number> {
    try {
      const records = await this.getFingerprintRecords(timeRange);
      const uniqueFingerprints = new Set(records.map(r => r.fingerprintId));
      return uniqueFingerprints.size;
    } catch (error) {
      logger.error('Failed to get total fingerprints', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return 0;
    }
  }

  /**
   * Get count of users using VPN.
   */
  async getVpnUserCount(timeRange: string = '7d'): Promise<number> {
    try {
      const records = await this.getFingerprintRecords(timeRange);
      const vpnFingerprints = new Set(
        records.filter(r => r.vpnDetected).map(r => r.fingerprintId)
      );
      return vpnFingerprints.size;
    } catch (error) {
      logger.error('Failed to get VPN user count', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return 0;
    }
  }

  /**
   * Get fingerprints by country with VPN percentage.
   */
  async getFingerprintsByCountry(timeRange: string = '7d', limit: number = 10): Promise<FingerprintStats['byCountry']> {
    try {
      const records = await this.getFingerprintRecords(timeRange);
      const countryMap = new Map<string, { count: number; vpnCount: number; code: string }>();

      for (const record of records) {
        if (!record.geoCountry) continue;
        const country = record.geoCountry;
        const code = record.geoCountry.substring(0, 2).toUpperCase();
        const existing = countryMap.get(country) || { count: 0, vpnCount: 0, code };
        existing.count++;
        if (record.vpnDetected) existing.vpnCount++;
        countryMap.set(country, existing);
      }

      const getFlag = (code: string): string => {
        if (code.length !== 2) return '';
        const codePoints = code
          .toUpperCase()
          .split('')
          .map(char => 127397 + char.charCodeAt(0));
        return String.fromCodePoint(...codePoints);
      };

      const byCountry = Array.from(countryMap.entries())
        .map(([name, data]) => ({
          name,
          code: data.code,
          flag: getFlag(data.code),
          count: data.count,
          vpnPercentage: data.count > 0 ? Math.round((data.vpnCount / data.count) * 100) : 0
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);

      return byCountry;
    } catch (error) {
      logger.error('Failed to get fingerprints by country', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Get fingerprints by device type.
   */
  async getFingerprintsByDevice(timeRange: string = '7d'): Promise<FingerprintStats['byDevice']> {
    try {
      const records = await this.getFingerprintRecords(timeRange);
      const deviceMap = new Map<string, number>();

      for (const record of records) {
        const device = record.deviceType || 'unknown';
        deviceMap.set(device, (deviceMap.get(device) || 0) + 1);
      }

      const byDevice = Array.from(deviceMap.entries())
        .map(([device, count]) => ({ device, count }))
        .sort((a, b) => b.count - a.count);

      return byDevice;
    } catch (error) {
      logger.error('Failed to get fingerprints by device', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Get high-risk fingerprints (risk score > 50).
   */
  async getHighRiskFingerprints(timeRange: string = '7d', limit: number = 10): Promise<FingerprintStats['highRiskFingerprints']> {
    try {
      const records = await this.getFingerprintRecords(timeRange);

      const highRisk = records
        .filter(r => r.riskScore && r.riskScore > 50)
        .map(r => ({
          id: r.fingerprintId,
          country: r.geoCountry || 'Unknown',
          riskScore: r.riskScore || 0,
          userId: r.userId
        }))
        .sort((a, b) => b.riskScore - a.riskScore)
        .slice(0, limit);

      const uniqueHighRisk = Array.from(
        new Map(highRisk.map(item => [item.id, item])).values()
      );

      return uniqueHighRisk;
    } catch (error) {
      logger.error('Failed to get high-risk fingerprints', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Get recent fingerprint changes (mismatches).
   */
  async getRecentFingerprintChanges(timeRange: string = '7d', limit: number = 20): Promise<FingerprintStats['recentChanges']> {
    try {
      const records = await this.getFingerprintRecords(timeRange);

      const changes = records
        .filter(r => r.eventType === 'fingerprint_mismatch')
        .map(r => ({
          timestamp: r.timestamp,
          userId: r.userId || 'unknown',
          userHandle: r.userHandle,
          country: r.geoCountry || 'Unknown',
          eventType: r.eventType
        }))
        .slice(0, limit);

      return changes;
    } catch (error) {
      logger.error('Failed to get recent fingerprint changes', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  /**
   * Get geographic coordinates for all fingerprints (for map visualization).
   */
  async getFingerprintGeoData(timeRange: string = '7d'): Promise<FingerprintGeoData> {
    try {
      const records = await this.getFingerprintRecords(timeRange);

      const uniqueMarkers = new Map<string, MapMarker>();
      const locationCounts = new Map<string, number>();

      for (const record of records) {
        if (typeof record.geoLatitude !== 'number' || typeof record.geoLongitude !== 'number') continue;
        if (isNaN(record.geoLatitude) || isNaN(record.geoLongitude)) continue;
        if (record.geoLatitude < -90 || record.geoLatitude > 90) continue;
        if (record.geoLongitude < -180 || record.geoLongitude > 180) continue;

        const markerKey = `${record.fingerprintId}_${record.geoLatitude}_${record.geoLongitude}`;
        const locationKey = `${record.geoLatitude},${record.geoLongitude}`;

        if (!uniqueMarkers.has(markerKey)) {
          locationCounts.set(locationKey, (locationCounts.get(locationKey) || 0) + 1);

          let riskTier: 'low' | 'medium' | 'high' | 'critical' = 'low';
          if (record.riskScore !== undefined) {
            if (record.riskScore >= 80) riskTier = 'critical';
            else if (record.riskScore >= 60) riskTier = 'high';
            else if (record.riskScore >= 40) riskTier = 'medium';
          } else if (record.riskTier) {
            riskTier = record.riskTier as 'low' | 'medium' | 'high' | 'critical';
          }

          uniqueMarkers.set(markerKey, {
            id: record.fingerprintId,
            position: [record.geoLatitude, record.geoLongitude],
            country: record.geoCountry || 'Unknown',
            city: record.geoCity || null,
            isVPN: record.vpnDetected,
            riskTier,
            deviceType: (record.deviceType as 'mobile' | 'tablet' | 'desktop') || 'unknown',
            timestamp: record.timestamp,
            userId: record.userId,
            sessionId: record.sessionId,
            userHandle: record.userHandle
          });
        }
      }

      const markers = Array.from(uniqueMarkers.values());

      const heatmapPoints: HeatmapPoint[] = Array.from(locationCounts.entries()).map(([key, count]) => {
        const [lat, lng] = key.split(',').map(Number);
        return { position: [lat, lng] as [number, number], intensity: count };
      });

      const totalFingerprints = markers.length;
      const vpnCount = markers.filter(m => m.isVPN).length;
      const vpnPercentage = totalFingerprints > 0 ? Math.round((vpnCount / totalFingerprints) * 100) : 0;
      const highRiskCount = markers.filter(m => m.riskTier === 'high' || m.riskTier === 'critical').length;

      logger.info('Generated fingerprint geo data for map', {
        totalMarkers: markers.length,
        heatmapPoints: heatmapPoints.length,
        vpnPercentage,
        highRiskCount
      });

      return { markers, locationCounts: heatmapPoints, totalFingerprints, vpnPercentage, highRiskCount };
    } catch (error) {
      logger.error('Failed to get fingerprint geo data', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return { markers: [], locationCounts: [], totalFingerprints: 0, vpnPercentage: 0, highRiskCount: 0 };
    }
  }

  /**
   * Get comprehensive fingerprint statistics.
   */
  async getFingerprintStats(timeRange: string = '7d'): Promise<FingerprintStats> {
    try {
      const [
        records,
        totalFingerprints,
        vpnUsers,
        byCountry,
        byDevice,
        highRiskFingerprints,
        recentChanges
      ] = await Promise.all([
        this.getFingerprintRecords(timeRange),
        this.getTotalFingerprints(timeRange),
        this.getVpnUserCount(timeRange),
        this.getFingerprintsByCountry(timeRange, 10),
        this.getFingerprintsByDevice(timeRange),
        this.getHighRiskFingerprints(timeRange, 10),
        this.getRecentFingerprintChanges(timeRange, 20)
      ]);

      const vpnPercentage = totalFingerprints > 0 ? Math.round((vpnUsers / totalFingerprints) * 100) : 0;
      const highRiskCount = records.filter(r => r.riskScore && r.riskScore > 50).length;
      const uniqueCountries = new Set(records.map(r => r.geoCountry).filter(Boolean)).size;

      return {
        totalFingerprints,
        vpnUsers,
        vpnPercentage,
        highRiskCount,
        uniqueCountries,
        byCountry,
        byDevice,
        highRiskFingerprints,
        recentChanges
      };
    } catch (error) {
      logger.error('Failed to get fingerprint stats', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return {
        totalFingerprints: 0,
        vpnUsers: 0,
        vpnPercentage: 0,
        highRiskCount: 0,
        uniqueCountries: 0,
        byCountry: [],
        byDevice: [],
        highRiskFingerprints: [],
        recentChanges: []
      };
    }
  }

  /**
   * Parse time range string to milliseconds.
   */
  parseTimeRange(timeRange: string): number {
    const match = timeRange.match(/^(\d+)([smhd])$/);
    if (!match) {
      logger.warn('Invalid time range format, defaulting to 7d', { timeRange });
      return 7 * 24 * 60 * 60 * 1000;
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000
    };

    return value * multipliers[unit];
  }

  /**
   * Parse browser name from user agent string.
   */
  parseBrowserName(userAgent?: string): string {
    if (!userAgent) return 'Unknown';
    if (userAgent.includes('Firefox/')) return 'Firefox';
    if (userAgent.includes('Chrome/')) {
      if (userAgent.includes('Edg/')) return 'Edge';
      if (userAgent.includes('OPR/')) return 'Opera';
      return 'Chrome';
    }
    if (userAgent.includes('Safari/') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('MSIE')) return 'Internet Explorer';
    return 'Unknown';
  }

  /**
   * Parse browser version from user agent string.
   */
  parseBrowserVersion(userAgent?: string): string {
    if (!userAgent) return 'Unknown';
    const firefoxMatch = userAgent.match(/Firefox\/(\d+(?:\.\d+)?)/);
    if (firefoxMatch) return firefoxMatch[1];
    const chromeMatch = userAgent.match(/Chrome\/(\d+(?:\.\d+)?)/);
    if (chromeMatch && !userAgent.includes('Edg') && !userAgent.includes('OPR')) return chromeMatch[1];
    const edgeMatch = userAgent.match(/Edg\/(\d+(?:\.\d+)?)/);
    if (edgeMatch) return edgeMatch[1];
    const safariMatch = userAgent.match(/Safari\/(\d+(?:\.\d+)?)/);
    if (safariMatch && !userAgent.includes('Chrome')) return safariMatch[1];
    const operaMatch = userAgent.match(/OPR\/(\d+(?:\.\d+)?)/);
    if (operaMatch) return operaMatch[1];
    return 'Unknown';
  }

  /**
   * Parse operating system from user agent string.
   */
  parseOperatingSystem(userAgent?: string): string {
    if (!userAgent) return 'Unknown';
    if (userAgent.includes('Windows NT 10')) return 'Windows 10';
    if (userAgent.includes('Windows NT 6.3')) return 'Windows 8.1';
    if (userAgent.includes('Windows NT 6.1')) return 'Windows 7';
    if (userAgent.includes('Windows')) return 'Windows';
    if (userAgent.includes('Mac OS X 10_15')) return 'macOS Catalina';
    if (userAgent.includes('Mac OS X 10_14')) return 'macOS Mojave';
    if (userAgent.includes('Mac OS X 10_13')) return 'macOS High Sierra';
    if (userAgent.includes('Mac OS X')) return 'macOS';
    if (userAgent.includes('Macintosh')) return 'macOS';
    if (userAgent.includes('Ubuntu')) return 'Ubuntu';
    if (userAgent.includes('Android')) return 'Android';
    if (userAgent.includes('Linux')) return 'Linux';
    if (userAgent.includes('iPhone')) return 'iOS';
    if (userAgent.includes('iPad')) return 'iPadOS';
    if (userAgent.includes('iOS')) return 'iOS';
    return 'Unknown';
  }

  /**
   * Calculate start time for Loki queries based on time range.
   */
  private calculateStartTime(timeRange: string): number {
    const now = Date.now() * 1000000; // Convert to nanoseconds
    const ranges: Record<string, number> = {
      '1h': 1 * 60 * 60 * 1000000000,
      '24h': 24 * 60 * 60 * 1000000000,
      '7d': 7 * 24 * 60 * 60 * 1000000000,
      '30d': 30 * 24 * 60 * 60 * 1000000000,
    };
    const duration = ranges[timeRange] || ranges['7d'];
    return now - duration;
  }
}
