








import { getScopedLogger, getFingerprintConfig } from '../config.js';
import type { FingerprintRequestContext, ConsentPreferenceData } from '../services/FingerprintEnrichmentService.js';
import { enrichFingerprintOnMismatch, enrichFingerprintOnValidation } from '../services/FingerprintEnrichmentService.js';

const logger = getScopedLogger('fingerprint-validation');

interface SessionFingerprint {
  fingerprintHash: string;
  createdAt: Date;
  lastValidated: Date;
  userId: string;
}


const sessionFingerprints = new Map<string, SessionFingerprint>();

async function safeFingerprintHash(fingerprint: string): Promise<string | null> {
  const hashPort = getFingerprintConfig().hashFingerprint;
  if (!hashPort) return null;
  try {
    const hash = await Promise.resolve(hashPort(fingerprint));
    return typeof hash === 'string' && hash.length >= 32 && !hash.includes(fingerprint)
      ? hash : null;
  } catch {
    return null;
  }
}






export async function storeFingerprint(
  sessionId: string,
  userId: string,
  fingerprint: string
): Promise<void> {
  const fingerprintHash = await safeFingerprintHash(fingerprint);
  if (!fingerprintHash) {
    logger.warn('Fingerprint storage skipped', { category: 'hash_port_unavailable' });
    return;
  }

  sessionFingerprints.set(sessionId, {
    fingerprintHash,
    createdAt: new Date(),
    lastValidated: new Date(),
    userId
  });

  logger.info('Fingerprint stored for session', {
    'trace_context': 'fingerprint_store'
  });
}






export async function validateFingerprint(
  ctx: FingerprintRequestContext
): Promise<{ valid: boolean; reason?: string }> {
  
  if (!ctx.user || !ctx.session) {
    return { valid: true };
  }

  const sessionId = ctx.session.id;
  if (!sessionId) return { valid: true, reason: 'missing_session_id' };
  const clientFingerprint = ctx.cookies?.get('fp_id');

  
  if (!clientFingerprint) {
    logger.warn('Missing fingerprint cookie', {
      'alert.type': 'missing_fingerprint',
      'severity': 'low'
    });
    return { valid: true, reason: 'missing_fingerprint_cookie' };
  }

  const clientFingerprintHash = await safeFingerprintHash(clientFingerprint);
  if (!clientFingerprintHash) {
    logger.warn('Fingerprint comparison skipped', { category: 'hash_port_unavailable' });
    return { valid: true, reason: 'fingerprint_hash_unavailable' };
  }

  
  const stored = sessionFingerprints.get(sessionId);
  if (!stored) {
    logger.warn('No stored fingerprint for session', {
      'alert.type': 'missing_stored_fingerprint',
      'severity': 'low'
    });
    await storeFingerprint(sessionId, ctx.user.id!, clientFingerprint);
    return { valid: true };
  }

  
  if (clientFingerprintHash !== stored.fingerprintHash) {
    
    logger.error('Session hijacking detected: Fingerprint mismatch', {
      'fingerprint.created_at': stored.createdAt.toISOString(),
      'fingerprint.last_validated': stored.lastValidated.toISOString(),
      'alert.type': 'session_hijacking',
      'severity': 'critical',
    });

    try {
      await enrichFingerprintOnMismatch(
        ctx,
        clientFingerprint,
        stored.fingerprintHash,
        clientFingerprintHash
      );
    } catch {
      logger.warn('Failed to enrich fingerprint on mismatch', {
        category: 'enrichment_failed'
      });
    }

    return { valid: false, reason: 'fingerprint_mismatch' };
  }

  
  stored.lastValidated = new Date();
  sessionFingerprints.set(sessionId, stored);

  
  try {
    await enrichFingerprintOnValidation(ctx, clientFingerprint);
    logger.info('Fingerprint enriched on validation', {
      'trace_context': 'fingerprint_validation'
    });
  } catch {
    logger.error('Failed to enrich fingerprint on validation', {
      category: 'enrichment_failed'
    });
  }

  return { valid: true };
}




export function clearFingerprint(sessionId: string): void {
  const removed = sessionFingerprints.delete(sessionId);

  if (removed) {
    logger.info('Fingerprint cleared for session', {
      'trace_context': 'fingerprint_clear'
    });
  }
}




export function getSessionFingerprint(sessionId: string): SessionFingerprint | null {
  return sessionFingerprints.get(sessionId) || null;
}





export function cleanExpiredFingerprints(): number {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  let removed = 0;

  for (const [sessionId, fp] of sessionFingerprints.entries()) {
    if (fp.lastValidated < thirtyDaysAgo) {
      sessionFingerprints.delete(sessionId);
      removed++;
    }
  }

  if (removed > 0) {
    logger.info('Cleaned expired fingerprints', {
      'fingerprints.removed': removed.toString(),
      'trace_context': 'fingerprint_cleanup'
    });
  }

  return removed;
}
