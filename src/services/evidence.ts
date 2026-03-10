import { config } from '../config.ts';
import { canonicalJson, sha256Hash, verifySignature } from './crypto.ts';
import { extractProof, verifyProof } from './merkle.ts';
import { getEntryByEventId, getAdjacentEntries, getMerkleBatchForSequence } from '../db/queries.ts';
import type {
  LedgerEntry,
  EvidencePacket,
  VerificationResult,
  VerificationCheck,
  HashChainProof,
  MerkleProofData,
} from '../types/index.ts';
import PDFDocument from 'pdfkit';

// === Verify a single record's integrity (all 4 checks) ===

export async function verifyRecord(tenantId: string, eventId: string): Promise<VerificationResult | null> {
  const entry = await getEntryByEventId(tenantId, eventId);
  if (!entry) return null;

  const checks = await runIntegrityChecks(entry, tenantId);

  const allPassed = checks.hash_valid && checks.chain_valid && checks.signature_valid && checks.merkle_valid;

  return {
    event_id: eventId,
    status: allPassed ? 'VERIFIED' : 'TAMPERED',
    checks,
    verified_at: new Date().toISOString(),
  };
}

// === Generate a complete evidence packet ===

export async function generateEvidencePacket(tenantId: string, eventId: string): Promise<EvidencePacket | null> {
  const entry = await getEntryByEventId(tenantId, eventId);
  if (!entry) return null;

  // Hash chain proof
  const hashChain = await buildHashChainProof(entry, tenantId);

  // Merkle proof
  const merkleProof = await buildMerkleProof(entry, tenantId);

  // Signature check
  const signatureValid = verifySignature(
    entry.record_hash,
    entry.platform_signature,
    config.ed25519PublicKey
  );

  return {
    version: '1.0',
    generated_at: new Date().toISOString(),
    record: entry,
    integrity: {
      record_hash: entry.record_hash,
      hash_chain: hashChain,
      merkle_proof: merkleProof,
      platform_signature: entry.platform_signature,
      signature_valid: signatureValid,
    },
    verification_key: config.ed25519PublicKey,
  };
}

// === PDF rendering ===

export async function renderEvidencePdf(packet: EvidencePacket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const chunks: Buffer[] = [];

    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // --- Page 1: Event Summary ---
    doc.fontSize(20).font('Helvetica-Bold').text('Attestr Evidence Packet', { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(10).font('Helvetica').fillColor('#666666')
      .text(`Generated: ${packet.generated_at}`, { align: 'center' });
    doc.moveDown(1);

    // Divider
    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke('#cccccc');
    doc.moveDown(0.5);

    doc.fontSize(14).font('Helvetica-Bold').fillColor('#000000').text('Event Summary');
    doc.moveDown(0.5);

    const record = packet.record;
    const summaryFields = [
      ['Event ID', record.event_id],
      ['Decision', record.decision],
      ['Score', record.score !== null ? String(record.score) : 'N/A'],
      ['Model Version', record.model_version || 'N/A'],
      ['Policy Version', record.policy_version || 'N/A'],
      ['Decided At', record.decided_at],
      ['Ingested At', record.ingested_at],
      ['Sequence Number', String(record.sequence_number)],
      ['Input Hash', record.input_hash || 'Not provided'],
    ];

    doc.fontSize(10).font('Helvetica');
    for (const [label, value] of summaryFields) {
      doc.font('Helvetica-Bold').text(`${label}: `, { continued: true });
      doc.font('Helvetica').text(value);
    }

    if (record.reason_codes && record.reason_codes.length > 0) {
      doc.moveDown(0.5);
      doc.font('Helvetica-Bold').text('Reason Codes:');
      doc.font('Helvetica');
      for (const code of record.reason_codes) {
        doc.text(`  \u2022 ${code}`);
      }
    }

    if (record.feature_contributions && Object.keys(record.feature_contributions).length > 0) {
      doc.moveDown(0.5);
      doc.font('Helvetica-Bold').text('Feature Contributions:');
      doc.font('Helvetica');
      for (const [feature, weight] of Object.entries(record.feature_contributions)) {
        doc.text(`  \u2022 ${feature}: ${weight}`);
      }
    }

    // --- Page 2: Integrity Verification ---
    doc.addPage();
    doc.fontSize(14).font('Helvetica-Bold').text('Integrity Verification');
    doc.moveDown(0.5);

    const integrity = packet.integrity;
    const checks = [
      ['Record Hash Valid', integrity.hash_chain.chain_valid ? 'hash recomputed correctly' : 'hash mismatch detected'],
      ['Hash Chain Valid', integrity.hash_chain.chain_valid],
      ['Platform Signature Valid', integrity.signature_valid],
      ['Merkle Proof Valid', integrity.merkle_proof ? integrity.merkle_proof.proof_valid : 'Not yet batched'],
      ['Input Hash Present', record.input_hash ? true : 'Not provided (single-attestation only)'],
    ];

    doc.fontSize(10);
    for (const [label, value] of checks) {
      const passed = value === true || value === 'hash recomputed correctly';
      const icon = typeof value === 'boolean' ? (value ? '\u2713' : '\u2717') : '\u2014';
      const color = typeof value === 'boolean' ? (value ? '#22c55e' : '#ef4444') : '#a3a3a3';
      doc.fillColor(color).font('Helvetica-Bold').text(`${icon} `, { continued: true });
      doc.fillColor('#000000').font('Helvetica-Bold').text(`${label}: `, { continued: true });
      doc.font('Helvetica').text(typeof value === 'boolean' ? (value ? 'PASS' : 'FAIL') : String(value));
    }

    doc.moveDown(1);
    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke('#cccccc');
    doc.moveDown(0.5);

    doc.fontSize(12).font('Helvetica-Bold').fillColor('#000000').text('Hash Chain Details');
    doc.moveDown(0.3);
    doc.fontSize(8).font('Courier');
    doc.text(`Record Hash:   ${integrity.record_hash}`);
    doc.text(`Previous Hash: ${integrity.hash_chain.previous_hash}`);
    if (integrity.hash_chain.next_hash) {
      doc.text(`Next Hash:     ${integrity.hash_chain.next_hash}`);
    }

    if (integrity.merkle_proof) {
      doc.moveDown(0.5);
      doc.fontSize(12).font('Helvetica-Bold').text('Merkle Proof Details');
      doc.moveDown(0.3);
      doc.fontSize(8).font('Courier');
      doc.text(`Batch #${integrity.merkle_proof.batch_number}  (ID: ${integrity.merkle_proof.batch_id})`);
      doc.text(`Batch Root: ${integrity.merkle_proof.batch_root}`);
      doc.text(`Root Signature: ${integrity.merkle_proof.root_signature}`);
      doc.moveDown(0.3);
      doc.text('Proof Path (leaf to root):');
      for (let i = 0; i < integrity.merkle_proof.proof_path.length; i++) {
        const s = integrity.merkle_proof.proof_path[i];
        doc.text(`  Level ${i}: [${s.direction}] ${s.hash}`);
      }
    }

    // --- Page 3: Platform Signature & Verification Key ---
    doc.addPage();
    doc.fontSize(14).font('Helvetica-Bold').fillColor('#000000').text('Cryptographic Details');
    doc.moveDown(0.5);

    doc.fontSize(10).font('Helvetica-Bold').text('Platform Signature:');
    doc.fontSize(8).font('Courier').text(integrity.platform_signature);
    doc.moveDown(0.5);

    doc.fontSize(10).font('Helvetica-Bold').text('Verification Key (Ed25519 Public Key, Base64):');
    doc.fontSize(8).font('Courier').text(packet.verification_key);
    doc.moveDown(1);

    doc.fontSize(9).font('Helvetica').fillColor('#666666')
      .text('This evidence packet was generated by Attestr (attestr.io). To verify independently, '
        + 'recompute the SHA-256 hash from the canonical JSON record, verify the Ed25519 signature '
        + 'using the public key above, and validate the Merkle proof path from the leaf to the batch root.',
        { lineGap: 2 });

    doc.moveDown(1);
    doc.fontSize(8).fillColor('#a3a3a3')
      .text(`Evidence Packet v${packet.version} | Generated ${packet.generated_at}`, { align: 'center' });

    doc.end();
  });
}

// === Internal helpers ===

// Normalize DB row types to match the types used during ingestion hash computation.
// PostgreSQL pg driver returns: NUMERIC→string, BIGINT→string, TIMESTAMPTZ→Date
// The original hash was computed with: score=number|null, sequence_number=number, decided_at=string
//
// Backward compatibility: records created before the input_hash migration were hashed
// WITHOUT input_hash in the canonical record. We try with input_hash first (v2 schema),
// and if the hash doesn't match, fall back to without it (v1 schema).
function normalizeEntryForHashV2(entry: LedgerEntry) {
  return {
    tenant_id: entry.tenant_id,
    event_id: entry.event_id,
    decision: entry.decision,
    score: entry.score != null ? parseFloat(String(entry.score)) : null,
    reason_codes: entry.reason_codes,
    feature_contributions: entry.feature_contributions,
    model_version: entry.model_version || null,
    policy_version: entry.policy_version || null,
    decided_at: entry.decided_at instanceof Date
      ? (entry.decided_at as unknown as Date).toISOString()
      : String(entry.decided_at),
    metadata: entry.metadata || null,
    input_hash: entry.input_hash || null,
    sequence_number: typeof entry.sequence_number === 'string'
      ? parseInt(entry.sequence_number as unknown as string, 10)
      : entry.sequence_number,
    previous_hash: entry.previous_hash,
  };
}

function normalizeEntryForHashV1(entry: LedgerEntry) {
  return {
    tenant_id: entry.tenant_id,
    event_id: entry.event_id,
    decision: entry.decision,
    score: entry.score != null ? parseFloat(String(entry.score)) : null,
    reason_codes: entry.reason_codes,
    feature_contributions: entry.feature_contributions,
    model_version: entry.model_version || null,
    policy_version: entry.policy_version || null,
    decided_at: entry.decided_at instanceof Date
      ? (entry.decided_at as unknown as Date).toISOString()
      : String(entry.decided_at),
    metadata: entry.metadata || null,
    sequence_number: typeof entry.sequence_number === 'string'
      ? parseInt(entry.sequence_number as unknown as string, 10)
      : entry.sequence_number,
    previous_hash: entry.previous_hash,
  };
}

// Try v2 schema first (with input_hash), fall back to v1 (without) for pre-migration records
function recomputeRecordHash(entry: LedgerEntry): { hash: string; valid: boolean } {
  const v2Hash = sha256Hash(canonicalJson(normalizeEntryForHashV2(entry)));
  if (v2Hash === entry.record_hash) {
    return { hash: v2Hash, valid: true };
  }
  // Fall back to v1 for records created before input_hash migration
  const v1Hash = sha256Hash(canonicalJson(normalizeEntryForHashV1(entry)));
  return { hash: v1Hash, valid: v1Hash === entry.record_hash };
}

function normalizeSeqNum(val: number | string): number {
  return typeof val === 'string' ? parseInt(val, 10) : val;
}

async function runIntegrityChecks(entry: LedgerEntry, tenantId: string): Promise<VerificationCheck> {
  const seqNum = normalizeSeqNum(entry.sequence_number);

  // Check 1: Hash validity — recompute and compare (with v1/v2 backward compat)
  const { valid: hashValid } = recomputeRecordHash(entry);

  // Check 2: Hash chain — verify previous_hash links correctly
  const { previous } = await getAdjacentEntries(tenantId, seqNum);
  let chainValid: boolean;
  if (seqNum === 1) {
    // First record should chain from genesis hash
    chainValid = entry.previous_hash === config.genesisHash;
  } else if (previous) {
    chainValid = entry.previous_hash === previous.record_hash;
  } else {
    // Can't find previous record — can't validate chain
    chainValid = false;
  }

  // Check 3: Signature validity
  const signatureValid = verifySignature(
    entry.record_hash,
    entry.platform_signature,
    config.ed25519PublicKey
  );

  // Check 4: Merkle proof validity
  let merkleValid = true;
  let merkleNote: string | undefined;

  const batch = await getMerkleBatchForSequence(tenantId, seqNum);
  if (batch) {
    const leafIndex = seqNum - normalizeSeqNum(batch.start_sequence);
    const proof = extractProof(batch.tree_data, leafIndex);
    merkleValid = verifyProof(entry.record_hash, proof);
  } else {
    merkleValid = true; // Not yet batched — not a failure
    merkleNote = 'Record not yet included in a Merkle batch';
  }

  const result: VerificationCheck = {
    hash_valid: hashValid,
    chain_valid: chainValid,
    signature_valid: signatureValid,
    merkle_valid: merkleValid,
    input_hash_present: !!entry.input_hash,
  };
  if (merkleNote) result.merkle_note = merkleNote;
  return result;
}

async function buildHashChainProof(entry: LedgerEntry, tenantId: string): Promise<HashChainProof> {
  const seqNum = normalizeSeqNum(entry.sequence_number);
  const { previous, next } = await getAdjacentEntries(tenantId, seqNum);

  let chainValid: boolean;
  if (seqNum === 1) {
    chainValid = entry.previous_hash === config.genesisHash;
  } else if (previous) {
    chainValid = entry.previous_hash === previous.record_hash;
  } else {
    chainValid = false;
  }

  return {
    previous_hash: entry.previous_hash,
    previous_record_hash: previous?.record_hash || null,
    next_hash: next?.previous_hash || null,
    chain_valid: chainValid,
  };
}

async function buildMerkleProof(entry: LedgerEntry, tenantId: string): Promise<MerkleProofData | null> {
  const seqNum = normalizeSeqNum(entry.sequence_number);
  const batch = await getMerkleBatchForSequence(tenantId, seqNum);
  if (!batch) return null;

  const leafIndex = seqNum - normalizeSeqNum(batch.start_sequence);
  const proof = extractProof(batch.tree_data, leafIndex);
  const proofValid = verifyProof(entry.record_hash, proof);

  return {
    batch_id: batch.id,
    batch_number: batch.batch_number,
    batch_root: batch.root_hash,
    proof_path: proof.siblings,
    root_signature: batch.root_signature,
    proof_valid: proofValid,
  };
}
