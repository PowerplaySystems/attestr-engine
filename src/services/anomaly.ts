import { config } from '../config.ts';
import {
  getAllActiveTenantIds,
  getWindowStats,
  getLatestBaseline,
  upsertBaseline,
  insertAnomalyAlert,
  getRecentAlertByType,
} from '../db/queries.ts';
import type {
  AnomalyAlert,
  AnomalyType,
  AnomalySeverity,
  TenantBaseline,
  WindowStats,
} from '../types/index.ts';

// === Entry Point — called by background processor ===

export async function processAllTenantAnomalies(): Promise<number> {
  const tenantIds = await getAllActiveTenantIds();
  let totalAlerts = 0;

  for (const tenantId of tenantIds) {
    try {
      totalAlerts += await analyzeTenant(tenantId);
    } catch (err) {
      // Log but don't stop processing other tenants
      console.error(`Anomaly analysis failed for tenant ${tenantId}:`, err);
    }
  }

  return totalAlerts;
}

// === Per-Tenant Analysis ===

async function analyzeTenant(tenantId: string): Promise<number> {
  const now = new Date();

  // Current window: last 1 hour
  const currentFrom = new Date(now.getTime() - config.anomalyCurrentWindowMinutes * 60 * 1000);
  const currentStats = await getWindowStats(tenantId, currentFrom.toISOString(), now.toISOString());

  // No records in current window — nothing to analyze
  if (currentStats.total_records === 0) return 0;

  // Baseline window: last 24 hours
  const baselineFrom = new Date(now.getTime() - config.anomalyBaselineHours * 60 * 60 * 1000);
  const baselineStats = await getWindowStats(tenantId, baselineFrom.toISOString(), now.toISOString());

  // Not enough baseline data — skip to avoid false positives
  if (baselineStats.total_records < config.anomalyMinRecords) return 0;

  // Update/create baseline
  const baselineHours = (now.getTime() - baselineFrom.getTime()) / (1000 * 60 * 60);
  const baseline = await upsertBaseline({
    tenant_id: tenantId,
    window_start: baselineFrom.toISOString(),
    window_end: now.toISOString(),
    total_records: baselineStats.total_records,
    avg_score: baselineStats.avg_score,
    stddev_score: baselineStats.stddev_score,
    block_rate: baselineStats.total_records > 0
      ? baselineStats.block_count / baselineStats.total_records
      : null,
    allow_rate: baselineStats.total_records > 0
      ? baselineStats.allow_count / baselineStats.total_records
      : null,
    review_rate: baselineStats.total_records > 0
      ? baselineStats.review_count / baselineStats.total_records
      : null,
    reason_code_freq: baselineStats.reason_code_freq,
    model_versions: baselineStats.model_versions,
    avg_velocity: baselineHours > 0
      ? baselineStats.total_records / baselineHours
      : null,
  });

  // Run all 6 detectors
  const detectors = [
    detectScoreDrift,
    detectBlockRateAnomaly,
    detectRecordingGap,
    detectReasonCodeShift,
    detectModelTransition,
    detectVelocityAnomaly,
  ];

  let alertsCreated = 0;
  const dedupSince = new Date(now.getTime() - 60 * 60 * 1000).toISOString(); // 1 hour dedup window

  for (const detector of detectors) {
    const finding = detector(tenantId, currentStats, baseline);
    if (finding) {
      // Dedup: skip if same type alert exists within last hour
      const recent = await getRecentAlertByType(tenantId, finding.type as AnomalyType, dedupSince);
      if (!recent) {
        await insertAnomalyAlert(finding);
        alertsCreated++;
      }
    }
  }

  return alertsCreated;
}

// === Detection Algorithms ===

interface AlertCandidate {
  tenant_id: string;
  type: AnomalyType;
  severity: AnomalySeverity;
  confidence: number;
  title: string;
  description: string;
  details: Record<string, unknown>;
  affected_from: number | null;
  affected_to: number | null;
}

// 1. Score Distribution Drift — z-score of current mean vs baseline
function detectScoreDrift(
  tenantId: string,
  current: WindowStats,
  baseline: TenantBaseline
): AlertCandidate | null {
  if (current.avg_score === null || baseline.avg_score === null) return null;
  if (baseline.stddev_score === null || baseline.stddev_score === 0) return null;

  const zScore = Math.abs(current.avg_score - baseline.avg_score) / baseline.stddev_score;

  if (zScore < 2.0) return null;

  const severity = computeSeverity(zScore);
  const direction = current.avg_score > baseline.avg_score ? 'increased' : 'decreased';

  return {
    tenant_id: tenantId,
    type: 'score_drift',
    severity,
    confidence: computeConfidence(zScore),
    title: `Score distribution ${direction} significantly`,
    description: `Average score ${direction} from ${baseline.avg_score.toFixed(3)} to ${current.avg_score.toFixed(3)} (z-score: ${zScore.toFixed(2)}). This may indicate model drift or a change in traffic patterns.`,
    details: {
      baseline_avg: baseline.avg_score,
      current_avg: current.avg_score,
      baseline_stddev: baseline.stddev_score,
      z_score: parseFloat(zScore.toFixed(4)),
      direction,
      current_window_records: current.total_records,
    },
    affected_from: current.min_sequence,
    affected_to: current.max_sequence,
  };
}

// 2. Block Rate Anomaly — proportion change detection
function detectBlockRateAnomaly(
  tenantId: string,
  current: WindowStats,
  baseline: TenantBaseline
): AlertCandidate | null {
  if (current.total_records < 10) return null; // Need meaningful sample
  if (baseline.block_rate === null) return null;

  const currentBlockRate = current.block_count / current.total_records;
  const delta = Math.abs(currentBlockRate - baseline.block_rate);

  // Standard error for proportion
  const se = Math.sqrt(
    (baseline.block_rate * (1 - baseline.block_rate)) / current.total_records
  );
  const zScore = se > 0 ? delta / se : 0;

  // Trigger: >15 percentage point shift OR z > 2.5
  if (delta < 0.15 && zScore < 2.5) return null;

  const severity = computeSeverity(Math.max(zScore, delta * 10));
  const direction = currentBlockRate > baseline.block_rate ? 'spiked' : 'dropped';

  return {
    tenant_id: tenantId,
    type: 'block_rate',
    severity,
    confidence: computeConfidence(zScore),
    title: `Block rate ${direction} to ${(currentBlockRate * 100).toFixed(1)}%`,
    description: `Block rate ${direction} from ${(baseline.block_rate * 100).toFixed(1)}% to ${(currentBlockRate * 100).toFixed(1)}% (${(delta * 100).toFixed(1)}pp change). Review recent decisions for unusual patterns.`,
    details: {
      baseline_block_rate: baseline.block_rate,
      current_block_rate: parseFloat(currentBlockRate.toFixed(4)),
      delta_pp: parseFloat((delta * 100).toFixed(2)),
      z_score: parseFloat(zScore.toFixed(4)),
      current_blocks: current.block_count,
      current_total: current.total_records,
    },
    affected_from: current.min_sequence,
    affected_to: current.max_sequence,
  };
}

// 3. Recording Gap — velocity drop detection
function detectRecordingGap(
  tenantId: string,
  current: WindowStats,
  baseline: TenantBaseline
): AlertCandidate | null {
  if (baseline.avg_velocity === null || baseline.avg_velocity === 0) return null;

  // Calculate current velocity (records per hour)
  const windowHours = config.anomalyCurrentWindowMinutes / 60;
  const currentVelocity = current.total_records / windowHours;

  // Trigger: current velocity < 20% of expected
  const ratio = currentVelocity / baseline.avg_velocity;
  if (ratio >= 0.2) return null;

  const severity: AnomalySeverity = ratio < 0.05 ? 'critical' : ratio < 0.1 ? 'high' : 'medium';

  return {
    tenant_id: tenantId,
    type: 'recording_gap',
    severity,
    confidence: Math.min(0.999, 1 - ratio), // Higher confidence when ratio is lower
    title: `Recording velocity dropped to ${(ratio * 100).toFixed(0)}% of normal`,
    description: `Expected ~${baseline.avg_velocity.toFixed(0)} records/hour but only received ${currentVelocity.toFixed(0)}. This could indicate an ingestion failure, upstream outage, or configuration issue.`,
    details: {
      baseline_velocity: baseline.avg_velocity,
      current_velocity: parseFloat(currentVelocity.toFixed(2)),
      ratio: parseFloat(ratio.toFixed(4)),
      expected_records: Math.round(baseline.avg_velocity * windowHours),
      actual_records: current.total_records,
    },
    affected_from: current.min_sequence,
    affected_to: current.max_sequence,
  };
}

// 4. Reason Code Distribution Shift — cosine similarity
function detectReasonCodeShift(
  tenantId: string,
  current: WindowStats,
  baseline: TenantBaseline
): AlertCandidate | null {
  const baselineFreq = baseline.reason_code_freq;
  const currentFreq = current.reason_code_freq;

  // Need both to have reason codes
  const baselineCodes = Object.keys(baselineFreq);
  const currentCodes = Object.keys(currentFreq);
  if (baselineCodes.length === 0 || currentCodes.length === 0) return null;

  // Build union of all codes
  const allCodes = [...new Set([...baselineCodes, ...currentCodes])];

  // Compute cosine similarity
  const baselineVec = allCodes.map(c => baselineFreq[c] || 0);
  const currentVec = allCodes.map(c => currentFreq[c] || 0);

  const dotProduct = baselineVec.reduce((sum, b, i) => sum + b * currentVec[i], 0);
  const magBaseline = Math.sqrt(baselineVec.reduce((sum, v) => sum + v * v, 0));
  const magCurrent = Math.sqrt(currentVec.reduce((sum, v) => sum + v * v, 0));

  if (magBaseline === 0 || magCurrent === 0) return null;

  const similarity = dotProduct / (magBaseline * magCurrent);

  if (similarity >= 0.7) return null; // Similar enough

  // Find new codes not in baseline
  const newCodes = currentCodes.filter(c => !baselineCodes.includes(c));

  const severity: AnomalySeverity = similarity < 0.3 ? 'high' : similarity < 0.5 ? 'medium' : 'low';

  return {
    tenant_id: tenantId,
    type: 'reason_shift',
    severity,
    confidence: parseFloat((1 - similarity).toFixed(3)),
    title: `Reason code distribution shifted (${(similarity * 100).toFixed(0)}% similarity)`,
    description: `Reason code patterns have changed significantly from baseline.${newCodes.length > 0 ? ` New codes detected: ${newCodes.join(', ')}.` : ''} This may indicate policy changes or new fraud patterns.`,
    details: {
      cosine_similarity: parseFloat(similarity.toFixed(4)),
      new_codes: newCodes,
      baseline_top_codes: Object.entries(baselineFreq)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([code, freq]) => ({ code, freq })),
      current_top_codes: Object.entries(currentFreq)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([code, freq]) => ({ code, freq })),
    },
    affected_from: current.min_sequence,
    affected_to: current.max_sequence,
  };
}

// 5. Model Version Transition — new version detection
function detectModelTransition(
  tenantId: string,
  current: WindowStats,
  baseline: TenantBaseline
): AlertCandidate | null {
  if (current.model_versions.length === 0) return null;

  const baselineVersions = new Set(baseline.model_versions);
  const newVersions = current.model_versions.filter(v => !baselineVersions.has(v));

  if (newVersions.length === 0) return null;

  return {
    tenant_id: tenantId,
    type: 'model_transition',
    severity: 'medium',
    confidence: 0.95, // High confidence — deterministic detection
    title: `New model version detected: ${newVersions.join(', ')}`,
    description: `Model version${newVersions.length > 1 ? 's' : ''} ${newVersions.join(', ')} appeared in the last hour. Previously seen: ${baseline.model_versions.join(', ') || 'none'}. Monitor decision patterns for expected behavior changes.`,
    details: {
      new_versions: newVersions,
      baseline_versions: baseline.model_versions,
      current_versions: current.model_versions,
    },
    affected_from: current.min_sequence,
    affected_to: current.max_sequence,
  };
}

// 6. Velocity Anomaly — ingestion rate spike
function detectVelocityAnomaly(
  tenantId: string,
  current: WindowStats,
  baseline: TenantBaseline
): AlertCandidate | null {
  if (baseline.avg_velocity === null || baseline.avg_velocity === 0) return null;

  const windowHours = config.anomalyCurrentWindowMinutes / 60;
  const currentVelocity = current.total_records / windowHours;

  // We need a rough stddev for velocity — estimate from baseline
  // Assume stddev ~ 30% of mean for reasonable traffic patterns
  const estimatedStddev = baseline.avg_velocity * 0.3;
  if (estimatedStddev === 0) return null;

  const zScore = (currentVelocity - baseline.avg_velocity) / estimatedStddev;

  // Only flag spikes (z > 3.0), not drops (handled by recording_gap)
  if (zScore < 3.0) return null;

  const severity = computeSeverity(zScore);

  return {
    tenant_id: tenantId,
    type: 'velocity',
    severity,
    confidence: computeConfidence(zScore),
    title: `Ingestion rate spiked to ${currentVelocity.toFixed(0)} records/hour`,
    description: `Ingestion velocity is ${(currentVelocity / baseline.avg_velocity).toFixed(1)}x the baseline rate of ${baseline.avg_velocity.toFixed(0)}/hour (z-score: ${zScore.toFixed(2)}). This could indicate batch processing, replay, or upstream issues.`,
    details: {
      baseline_velocity: baseline.avg_velocity,
      current_velocity: parseFloat(currentVelocity.toFixed(2)),
      z_score: parseFloat(zScore.toFixed(4)),
      multiplier: parseFloat((currentVelocity / baseline.avg_velocity).toFixed(2)),
    },
    affected_from: current.min_sequence,
    affected_to: current.max_sequence,
  };
}

// === Helpers ===

function computeSeverity(zScore: number): AnomalySeverity {
  if (zScore >= 4.0) return 'critical';
  if (zScore >= 3.0) return 'high';
  if (zScore >= 2.5) return 'medium';
  return 'low';
}

function computeConfidence(zScore: number): number {
  // Map z-score to confidence (0-1) using simplified normal CDF approximation
  // At z=2.0 → ~0.977, z=3.0 → ~0.999, z=4.0 → ~0.99997
  const t = 1 / (1 + 0.2316419 * Math.abs(zScore));
  const d = 0.3989423 * Math.exp(-zScore * zScore / 2);
  const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
  const cdf = zScore > 0 ? 1 - p : p;
  return parseFloat(Math.min(0.999, cdf).toFixed(3));
}
