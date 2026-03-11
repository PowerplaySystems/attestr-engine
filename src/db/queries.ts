import { pool } from './client.ts';
import type {
  Tenant, LedgerEntry, ListFilters, MerkleBatch, MerkleTree,
  AnomalyAlert, AnomalyType, AnomalySeverity, TenantBaseline, WindowStats, AnomalyAlertFilters,
} from '../types/index.ts';

// === Tenant Queries ===

export async function getTenantById(tenantId: string): Promise<Tenant | null> {
  const result = await pool.query(
    'SELECT * FROM tenants WHERE id = $1 AND is_active = true',
    [tenantId]
  );
  return result.rows[0] || null;
}

// === Ledger Queries ===

export async function getEntryByEventId(tenantId: string, eventId: string): Promise<LedgerEntry | null> {
  const result = await pool.query(
    'SELECT * FROM ledger_entries WHERE tenant_id = $1 AND event_id = $2',
    [tenantId, eventId]
  );
  return result.rows[0] || null;
}

export async function listEntries(tenantId: string, filters: ListFilters): Promise<{ rows: LedgerEntry[]; totalCount: number }> {
  const conditions: string[] = ['tenant_id = $1'];
  const params: unknown[] = [tenantId];
  let paramIdx = 2;

  if (filters.from) {
    conditions.push(`decided_at >= $${paramIdx}`);
    params.push(filters.from);
    paramIdx++;
  }
  if (filters.to) {
    conditions.push(`decided_at <= $${paramIdx}`);
    params.push(filters.to);
    paramIdx++;
  }
  if (filters.decision) {
    conditions.push(`decision = $${paramIdx}`);
    params.push(filters.decision);
    paramIdx++;
  }
  if (filters.min_score !== undefined) {
    conditions.push(`score >= $${paramIdx}`);
    params.push(filters.min_score);
    paramIdx++;
  }
  if (filters.max_score !== undefined) {
    conditions.push(`score <= $${paramIdx}`);
    params.push(filters.max_score);
    paramIdx++;
  }

  // Cursor-based pagination: cursor is base64-encoded sequence_number
  if (filters.cursor) {
    try {
      const cursorSeq = parseInt(Buffer.from(filters.cursor, 'base64').toString('utf-8'), 10);
      conditions.push(`sequence_number < $${paramIdx}`);
      params.push(cursorSeq);
      paramIdx++;
    } catch {
      // Invalid cursor, ignore
    }
  }

  const where = conditions.join(' AND ');
  const limit = Math.min(filters.limit || 50, 200);

  // Get total count (without cursor/limit)
  const countConditions = conditions.filter(c => !c.includes('sequence_number <'));
  const countParams = params.slice(0, countConditions.length);
  const countResult = await pool.query(
    `SELECT COUNT(*)::int as count FROM ledger_entries WHERE ${countConditions.join(' AND ')}`,
    countParams
  );

  // Get paginated results
  const result = await pool.query(
    `SELECT * FROM ledger_entries WHERE ${where} ORDER BY sequence_number DESC LIMIT $${paramIdx}`,
    [...params, limit + 1] // fetch one extra to check has_more
  );

  const hasMore = result.rows.length > limit;
  const rows = hasMore ? result.rows.slice(0, limit) : result.rows;

  return {
    rows,
    totalCount: countResult.rows[0].count,
  };
}

// === Merkle Batch Queries ===

export async function insertMerkleBatch(batch: {
  tenant_id: string;
  batch_number: number;
  start_sequence: number;
  end_sequence: number;
  root_hash: string;
  root_signature: string;
  tree_data: MerkleTree;
}): Promise<MerkleBatch> {
  const result = await pool.query(
    `INSERT INTO merkle_batches (
      tenant_id, batch_number, start_sequence, end_sequence,
      root_hash, root_signature, tree_data
    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *`,
    [
      batch.tenant_id,
      batch.batch_number,
      batch.start_sequence,
      batch.end_sequence,
      batch.root_hash,
      batch.root_signature,
      JSON.stringify(batch.tree_data),
    ]
  );
  return result.rows[0];
}

export async function getLastMerkleBatch(tenantId: string): Promise<MerkleBatch | null> {
  const result = await pool.query(
    'SELECT * FROM merkle_batches WHERE tenant_id = $1 ORDER BY batch_number DESC LIMIT 1',
    [tenantId]
  );
  return result.rows[0] || null;
}

export async function getMerkleBatchForSequence(
  tenantId: string,
  sequenceNumber: number
): Promise<MerkleBatch | null> {
  const result = await pool.query(
    'SELECT * FROM merkle_batches WHERE tenant_id = $1 AND start_sequence <= $2 AND end_sequence >= $2',
    [tenantId, sequenceNumber]
  );
  return result.rows[0] || null;
}

export async function getEntriesInRange(
  tenantId: string,
  startSeq: number,
  endSeq: number
): Promise<LedgerEntry[]> {
  const result = await pool.query(
    'SELECT * FROM ledger_entries WHERE tenant_id = $1 AND sequence_number >= $2 AND sequence_number <= $3 ORDER BY sequence_number ASC',
    [tenantId, startSeq, endSeq]
  );
  return result.rows;
}

export async function getAdjacentEntries(
  tenantId: string,
  sequenceNumber: number
): Promise<{ previous: LedgerEntry | null; next: LedgerEntry | null }> {
  const prevResult = await pool.query(
    'SELECT * FROM ledger_entries WHERE tenant_id = $1 AND sequence_number = $2',
    [tenantId, sequenceNumber - 1]
  );
  const nextResult = await pool.query(
    'SELECT * FROM ledger_entries WHERE tenant_id = $1 AND sequence_number = $2',
    [tenantId, sequenceNumber + 1]
  );
  return {
    previous: prevResult.rows[0] || null,
    next: nextResult.rows[0] || null,
  };
}

export async function getAllActiveTenantIds(): Promise<string[]> {
  const result = await pool.query(
    'SELECT id FROM tenants WHERE is_active = true'
  );
  return result.rows.map((r: { id: string }) => r.id);
}

// === Anomaly Detection Queries ===

export async function getWindowStats(
  tenantId: string,
  from: string,
  to: string
): Promise<WindowStats> {
  // Core stats: counts, averages, sequence range
  const statsResult = await pool.query(
    `SELECT
      COUNT(*)::int as total_records,
      AVG(score) as avg_score,
      STDDEV(score) as stddev_score,
      COUNT(*) FILTER (WHERE decision = 'BLOCK')::int as block_count,
      COUNT(*) FILTER (WHERE decision = 'ALLOW')::int as allow_count,
      COUNT(*) FILTER (WHERE decision = 'REVIEW')::int as review_count,
      MIN(sequence_number) as min_sequence,
      MAX(sequence_number) as max_sequence,
      MIN(ingested_at) as first_ingested,
      MAX(ingested_at) as last_ingested
    FROM ledger_entries
    WHERE tenant_id = $1 AND ingested_at >= $2 AND ingested_at < $3`,
    [tenantId, from, to]
  );

  const stats = statsResult.rows[0];

  // Reason code frequency (flatten JSONB array and count)
  const reasonResult = await pool.query(
    `SELECT code, COUNT(*)::int as freq
     FROM ledger_entries, jsonb_array_elements_text(reason_codes) AS code
     WHERE tenant_id = $1 AND ingested_at >= $2 AND ingested_at < $3
     GROUP BY code
     ORDER BY freq DESC`,
    [tenantId, from, to]
  );

  const reason_code_freq: Record<string, number> = {};
  for (const row of reasonResult.rows) {
    reason_code_freq[row.code] = row.freq;
  }

  // Model versions seen in window
  const modelResult = await pool.query(
    `SELECT DISTINCT model_version
     FROM ledger_entries
     WHERE tenant_id = $1 AND ingested_at >= $2 AND ingested_at < $3
       AND model_version IS NOT NULL`,
    [tenantId, from, to]
  );

  return {
    total_records: stats.total_records,
    avg_score: stats.avg_score !== null ? parseFloat(stats.avg_score) : null,
    stddev_score: stats.stddev_score !== null ? parseFloat(stats.stddev_score) : null,
    block_count: stats.block_count,
    allow_count: stats.allow_count,
    review_count: stats.review_count,
    reason_code_freq,
    model_versions: modelResult.rows.map((r: { model_version: string }) => r.model_version),
    min_sequence: stats.min_sequence,
    max_sequence: stats.max_sequence,
    first_ingested: stats.first_ingested,
    last_ingested: stats.last_ingested,
  };
}

export async function insertAnomalyAlert(alert: {
  tenant_id: string;
  type: AnomalyType;
  severity: AnomalySeverity;
  confidence: number;
  title: string;
  description: string;
  details: Record<string, unknown>;
  affected_from: number | null;
  affected_to: number | null;
}): Promise<AnomalyAlert> {
  const result = await pool.query(
    `INSERT INTO anomaly_alerts (
      tenant_id, type, severity, confidence, title, description, details,
      affected_from, affected_to
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING *`,
    [
      alert.tenant_id,
      alert.type,
      alert.severity,
      alert.confidence,
      alert.title,
      alert.description,
      JSON.stringify(alert.details),
      alert.affected_from,
      alert.affected_to,
    ]
  );
  return result.rows[0];
}

export async function listAnomalyAlerts(
  tenantId: string,
  filters: AnomalyAlertFilters
): Promise<{ rows: AnomalyAlert[]; totalCount: number }> {
  const conditions: string[] = ['tenant_id = $1'];
  const params: unknown[] = [tenantId];
  let idx = 2;

  if (filters.type) {
    conditions.push(`type = $${idx}`);
    params.push(filters.type);
    idx++;
  }
  if (filters.severity) {
    conditions.push(`severity = $${idx}`);
    params.push(filters.severity);
    idx++;
  }
  if (filters.acknowledged !== undefined) {
    conditions.push(`acknowledged = $${idx}`);
    params.push(filters.acknowledged);
    idx++;
  }
  if (filters.from) {
    conditions.push(`detected_at >= $${idx}`);
    params.push(filters.from);
    idx++;
  }
  if (filters.to) {
    conditions.push(`detected_at <= $${idx}`);
    params.push(filters.to);
    idx++;
  }

  // Cursor-based pagination
  if (filters.cursor) {
    try {
      const cursorTs = Buffer.from(filters.cursor, 'base64').toString('utf-8');
      conditions.push(`detected_at < $${idx}`);
      params.push(cursorTs);
      idx++;
    } catch {
      // Invalid cursor, ignore
    }
  }

  const where = conditions.join(' AND ');
  const limit = Math.min(filters.limit || 50, 200);

  // Count without cursor
  const countConditions = conditions.filter(c => !c.includes('detected_at <') || c.includes('detected_at >='));
  const countParams = params.slice(0, countConditions.length);
  const countResult = await pool.query(
    `SELECT COUNT(*)::int as count FROM anomaly_alerts WHERE ${countConditions.join(' AND ')}`,
    countParams
  );

  const result = await pool.query(
    `SELECT * FROM anomaly_alerts WHERE ${where} ORDER BY detected_at DESC LIMIT $${idx}`,
    [...params, limit + 1]
  );

  const hasMore = result.rows.length > limit;
  const rows = hasMore ? result.rows.slice(0, limit) : result.rows;

  return {
    rows,
    totalCount: countResult.rows[0].count,
  };
}

export async function getAnomalyAlert(tenantId: string, alertId: string): Promise<AnomalyAlert | null> {
  const result = await pool.query(
    'SELECT * FROM anomaly_alerts WHERE tenant_id = $1 AND id = $2',
    [tenantId, alertId]
  );
  return result.rows[0] || null;
}

export async function acknowledgeAlert(tenantId: string, alertId: string): Promise<AnomalyAlert | null> {
  const result = await pool.query(
    `UPDATE anomaly_alerts SET acknowledged = true, acknowledged_at = NOW()
     WHERE tenant_id = $1 AND id = $2
     RETURNING *`,
    [tenantId, alertId]
  );
  return result.rows[0] || null;
}

export async function getLatestBaseline(tenantId: string): Promise<TenantBaseline | null> {
  const result = await pool.query(
    'SELECT * FROM tenant_baselines WHERE tenant_id = $1 ORDER BY window_start DESC LIMIT 1',
    [tenantId]
  );
  return result.rows[0] || null;
}

export async function upsertBaseline(baseline: {
  tenant_id: string;
  window_start: string;
  window_end: string;
  total_records: number;
  avg_score: number | null;
  stddev_score: number | null;
  block_rate: number | null;
  allow_rate: number | null;
  review_rate: number | null;
  reason_code_freq: Record<string, number>;
  model_versions: string[];
  avg_velocity: number | null;
}): Promise<TenantBaseline> {
  const result = await pool.query(
    `INSERT INTO tenant_baselines (
      tenant_id, window_start, window_end, total_records,
      avg_score, stddev_score, block_rate, allow_rate, review_rate,
      reason_code_freq, model_versions, avg_velocity
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (tenant_id, window_start) DO UPDATE SET
      window_end = EXCLUDED.window_end,
      total_records = EXCLUDED.total_records,
      avg_score = EXCLUDED.avg_score,
      stddev_score = EXCLUDED.stddev_score,
      block_rate = EXCLUDED.block_rate,
      allow_rate = EXCLUDED.allow_rate,
      review_rate = EXCLUDED.review_rate,
      reason_code_freq = EXCLUDED.reason_code_freq,
      model_versions = EXCLUDED.model_versions,
      avg_velocity = EXCLUDED.avg_velocity,
      computed_at = NOW()
    RETURNING *`,
    [
      baseline.tenant_id,
      baseline.window_start,
      baseline.window_end,
      baseline.total_records,
      baseline.avg_score,
      baseline.stddev_score,
      baseline.block_rate,
      baseline.allow_rate,
      baseline.review_rate,
      JSON.stringify(baseline.reason_code_freq),
      JSON.stringify(baseline.model_versions),
      baseline.avg_velocity,
    ]
  );
  return result.rows[0];
}

export async function getRecentAlertByType(
  tenantId: string,
  type: AnomalyType,
  since: string
): Promise<AnomalyAlert | null> {
  const result = await pool.query(
    'SELECT * FROM anomaly_alerts WHERE tenant_id = $1 AND type = $2 AND detected_at >= $3 ORDER BY detected_at DESC LIMIT 1',
    [tenantId, type, since]
  );
  return result.rows[0] || null;
}
