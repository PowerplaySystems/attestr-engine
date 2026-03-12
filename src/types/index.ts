// === API Request Types ===

export interface DecisionPayload {
  event_id: string;
  decision: string;
  score?: number;
  reason_codes: string[];
  feature_contributions?: Record<string, number>;
  model_version?: string;
  policy_version?: string;
  decided_at: string;
  metadata?: Record<string, unknown>;
  input_hash?: string; // SHA-256 of raw input data for dual-attestation
}

// === Database Types ===

export interface Tenant {
  id: string;
  name: string;
  api_key_hash: string;
  hmac_secret: string; // stored as plain for HMAC computation (not a password)
  tier: string;
  logo_url: string | null;
  created_at: string;
  is_active: boolean;
}

export interface LedgerEntry {
  id: string;
  tenant_id: string;
  sequence_number: number;
  event_id: string;
  decision: string;
  score: number | null;
  reason_codes: string[];
  feature_contributions: Record<string, number> | null;
  model_version: string | null;
  policy_version: string | null;
  decided_at: string;
  metadata: Record<string, unknown> | null;
  input_hash: string | null;
  record_hash: string;
  previous_hash: string;
  platform_signature: string;
  ingested_at: string;
}

// === API Response Types ===

export interface IngestResponse {
  ledger_entry_id: string;
  sequence_number: number;
  record_hash: string;
  previous_hash: string;
  platform_signature: string;
  ingested_at: string;
}

export interface DecisionResponse extends LedgerEntry {}

export interface ListDecisionsResponse {
  records: LedgerEntry[];
  pagination: {
    cursor: string | null;
    has_more: boolean;
  };
  total_count: number;
}

// === Merkle Tree Types ===

export interface MerkleNode {
  level: number;
  index: number;
  hash: string;
}

export interface MerkleTree {
  version: number;
  size: number;
  leaf_hashes: string[];
  nodes: MerkleNode[];
  root_hash: string;
}

export interface MerkleBatch {
  id: string;
  tenant_id: string;
  batch_number: number;
  start_sequence: number;
  end_sequence: number;
  root_hash: string;
  root_signature: string;
  tree_data: MerkleTree;
  created_at: string;
}

export interface MerkleProofSibling {
  hash: string;
  direction: 'left' | 'right'; // which side the sibling is on
}

export interface MerkleProofPath {
  leaf_index: number;
  leaf_hash: string;
  siblings: MerkleProofSibling[];
  root_hash: string;
}

// === Evidence & Verification Types ===

export interface HashChainProof {
  previous_hash: string;
  previous_record_hash: string | null; // the actual hash of the prior entry (null if genesis)
  next_hash: string | null; // the next entry's previous_hash (null if latest)
  chain_valid: boolean;
}

export interface MerkleProofData {
  batch_id: string;
  batch_number: number;
  batch_root: string;
  proof_path: MerkleProofSibling[];
  root_signature: string;
  proof_valid: boolean;
}

export interface EvidencePacket {
  version: '1.0';
  generated_at: string;
  record: LedgerEntry;
  integrity: {
    record_hash: string;
    hash_chain: HashChainProof;
    merkle_proof: MerkleProofData | null; // null if not yet batched
    platform_signature: string;
    signature_valid: boolean;
  };
  verification_key: string; // platform Ed25519 public key (base64)
}

export interface VerificationCheck {
  hash_valid: boolean;
  chain_valid: boolean;
  signature_valid: boolean;
  merkle_valid: boolean;
  merkle_note?: string; // e.g. "not yet batched"
  input_hash_present: boolean; // dual-attestation: client provided input hash
}

export interface VerificationResult {
  event_id: string;
  status: 'VERIFIED' | 'TAMPERED';
  checks: VerificationCheck;
  verified_at: string;
}

// === Anomaly Detection Types ===

export type AnomalyType = 'score_drift' | 'block_rate' | 'recording_gap' | 'reason_shift' | 'model_transition' | 'velocity';
export type AnomalySeverity = 'low' | 'medium' | 'high' | 'critical';

export interface AnomalyAlert {
  id: string;
  tenant_id: string;
  type: AnomalyType;
  severity: AnomalySeverity;
  confidence: number;
  title: string;
  description: string;
  details: Record<string, unknown>;
  affected_from: number | null;
  affected_to: number | null;
  acknowledged: boolean;
  acknowledged_at: string | null;
  detected_at: string;
}

export interface TenantBaseline {
  id: string;
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
  computed_at: string;
}

export interface WindowStats {
  total_records: number;
  avg_score: number | null;
  stddev_score: number | null;
  block_count: number;
  allow_count: number;
  review_count: number;
  reason_code_freq: Record<string, number>;
  model_versions: string[];
  min_sequence: number | null;
  max_sequence: number | null;
  first_ingested: string | null;
  last_ingested: string | null;
}

export interface AnomalyAlertFilters {
  type?: AnomalyType;
  severity?: AnomalySeverity;
  acknowledged?: boolean;
  from?: string;
  to?: string;
  cursor?: string;
  limit?: number;
}

// === Quota Enforcement ===

export class QuotaExceededError extends Error {
  public readonly currentUsage: number;
  public readonly limit: number;
  public readonly resetsAt: string;

  constructor(currentUsage: number, limit: number, resetsAt: string) {
    super(`Monthly record limit exceeded: ${currentUsage}/${limit}`);
    this.name = 'QuotaExceededError';
    this.currentUsage = currentUsage;
    this.limit = limit;
    this.resetsAt = resetsAt;
  }
}

// === Query Filter Types ===

export interface ListFilters {
  from?: string;
  to?: string;
  decision?: string;
  min_score?: number;
  max_score?: number;
  cursor?: string;
  limit?: number;
}

// === Fastify Augmentation ===

declare module 'fastify' {
  interface FastifyRequest {
    tenant?: Tenant;
  }
}
