import { config } from '../config.ts';
import { canonicalJson, sha256Hash, signRecord } from './crypto.ts';
import { getEntryByEventId, listEntries } from '../db/queries.ts';
import { pool } from '../db/client.ts';
import { QuotaExceededError } from '../types/index.ts';
import type { DecisionPayload, IngestResponse, LedgerEntry, ListFilters, ListDecisionsResponse } from '../types/index.ts';

export async function ingestDecision(tenantId: string, payload: DecisionPayload): Promise<{ entry: LedgerEntry; created: boolean }> {
  // 1. Check idempotency — if event_id already exists, return existing
  const existing = await getEntryByEventId(tenantId, payload.event_id);
  if (existing) {
    return { entry: existing, created: false };
  }

  // 2. Use a transaction with advisory lock to serialize writes per tenant.
  //    This prevents two concurrent requests from reading the same last entry
  //    and computing duplicate sequence numbers / broken hash chains.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Advisory lock keyed on tenant_id hash — serializes ingestion per tenant
    // without blocking other tenants. pg_advisory_xact_lock auto-releases on COMMIT/ROLLBACK.
    const lockKey = Buffer.from(tenantId).reduce((hash, byte) => ((hash << 5) - hash + byte) | 0, 0);
    await client.query('SELECT pg_advisory_xact_lock($1)', [lockKey]);

    // --- Monthly record quota check (inside lock — no race condition) ---
    const tierResult = await client.query('SELECT tier FROM tenants WHERE id = $1', [tenantId]);
    const tier = tierResult.rows[0]?.tier || 'free';
    const monthlyLimit = config.recordLimits[tier] ?? config.recordLimits.free;

    if (monthlyLimit !== Infinity) {
      const monthStart = new Date();
      monthStart.setDate(1);
      monthStart.setHours(0, 0, 0, 0);

      const { rows: [{ count }] } = await client.query(
        'SELECT COUNT(*)::int AS count FROM ledger_entries WHERE tenant_id = $1 AND ingested_at >= $2',
        [tenantId, monthStart.toISOString()]
      );

      if (count >= monthlyLimit) {
        const nextMonth = new Date(monthStart);
        nextMonth.setMonth(nextMonth.getMonth() + 1);
        throw new QuotaExceededError(count, monthlyLimit, nextMonth.toISOString());
      }
    }

    // Now safe to read last entry — no other transaction for this tenant can be between our read and write
    const lastResult = await client.query(
      'SELECT record_hash, sequence_number FROM ledger_entries WHERE tenant_id = $1 ORDER BY sequence_number DESC LIMIT 1',
      [tenantId]
    );
    const lastEntry = lastResult.rows[0] || null;
    const previousHash = lastEntry?.record_hash || config.genesisHash;
    const sequenceNumber = lastEntry ? lastEntry.sequence_number + 1 : 1;

    // 3. Build the canonical record for hashing (single source of truth for field values)
    const record = {
      tenant_id: tenantId,
      sequence_number: sequenceNumber,
      event_id: payload.event_id,
      decision: payload.decision,
      score: payload.score ?? null,
      reason_codes: payload.reason_codes,
      feature_contributions: payload.feature_contributions ?? null,
      model_version: payload.model_version ?? null,
      policy_version: payload.policy_version ?? null,
      decided_at: payload.decided_at,
      metadata: payload.metadata ?? null,
      input_hash: payload.input_hash ?? null,
      previous_hash: previousHash,
    };

    // 4. Compute SHA-256 hash of canonical JSON
    const recordHash = sha256Hash(canonicalJson(record));

    // 5. Sign the hash with platform Ed25519 key
    const platformSignature = signRecord(recordHash, config.ed25519PrivateKey);

    // 6. Store in the ledger (within same transaction).
    //    JSON columns are serialized from the same record object used for hashing.
    const insertResult = await client.query(
      `INSERT INTO ledger_entries (
        tenant_id, sequence_number, event_id, decision, score,
        reason_codes, feature_contributions, model_version, policy_version,
        decided_at, metadata, input_hash, record_hash, previous_hash, platform_signature
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *`,
      [
        record.tenant_id,
        record.sequence_number,
        record.event_id,
        record.decision,
        record.score,
        JSON.stringify(record.reason_codes),
        record.feature_contributions ? JSON.stringify(record.feature_contributions) : null,
        record.model_version,
        record.policy_version,
        record.decided_at,
        record.metadata ? JSON.stringify(record.metadata) : null,
        record.input_hash,
        recordHash,
        record.previous_hash,
        platformSignature,
      ]
    );

    await client.query('COMMIT');
    return { entry: insertResult.rows[0], created: true };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export function toIngestResponse(entry: LedgerEntry): IngestResponse {
  return {
    ledger_entry_id: entry.id,
    sequence_number: entry.sequence_number,
    record_hash: entry.record_hash,
    previous_hash: entry.previous_hash,
    platform_signature: entry.platform_signature,
    ingested_at: entry.ingested_at,
  };
}

export async function getDecision(tenantId: string, eventId: string): Promise<LedgerEntry | null> {
  return getEntryByEventId(tenantId, eventId);
}

export async function listDecisions(tenantId: string, filters: ListFilters): Promise<ListDecisionsResponse> {
  const { rows, totalCount } = await listEntries(tenantId, filters);
  const limit = Math.min(filters.limit || 50, 200);

  // Build cursor from last record's sequence number
  const lastRecord = rows[rows.length - 1];
  const cursor = lastRecord && rows.length === limit
    ? Buffer.from(String(lastRecord.sequence_number)).toString('base64')
    : null;

  return {
    records: rows,
    pagination: {
      cursor,
      has_more: cursor !== null,
    },
    total_count: totalCount,
  };
}
