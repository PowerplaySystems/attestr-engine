import { config } from '../config.ts';
import { canonicalJson, sha256Hash, signRecord } from './crypto.ts';
import { getLastEntryForTenant, getEntryByEventId, insertLedgerEntry, listEntries } from '../db/queries.ts';
import type { DecisionPayload, IngestResponse, LedgerEntry, ListFilters, ListDecisionsResponse } from '../types/index.ts';

export async function ingestDecision(tenantId: string, payload: DecisionPayload): Promise<{ entry: LedgerEntry; created: boolean }> {
  // 1. Check idempotency — if event_id already exists, return existing
  const existing = await getEntryByEventId(tenantId, payload.event_id);
  if (existing) {
    return { entry: existing, created: false };
  }

  // 2. Get the previous record's hash (or genesis hash for first record)
  const lastEntry = await getLastEntryForTenant(tenantId);
  const previousHash = lastEntry?.record_hash || config.genesisHash;
  const sequenceNumber = lastEntry ? lastEntry.sequence_number + 1 : 1;

  // 3. Build the canonical record for hashing
  const canonicalRecord = {
    tenant_id: tenantId,
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
    sequence_number: sequenceNumber,
    previous_hash: previousHash,
  };

  // 4. Compute SHA-256 hash of canonical JSON
  const recordHash = sha256Hash(canonicalJson(canonicalRecord));

  // 5. Sign the hash with platform Ed25519 key
  const platformSignature = signRecord(recordHash, config.ed25519PrivateKey);

  // 6. Store in the ledger
  const entry = await insertLedgerEntry({
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
    record_hash: recordHash,
    previous_hash: previousHash,
    platform_signature: platformSignature,
  });

  return { entry, created: true };
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
