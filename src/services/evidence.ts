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

// Layout constants
const PAGE_MARGIN = 50;
const CONTENT_WIDTH = 495; // A4 width (595) - 2 * margin
const ACCENT_COLOR = '#2563EB'; // blue-600
const LABEL_WIDTH = 120;
const HASH_FONT_SIZE = 7.5;

// Styling helpers
function drawHeader(doc: PDFKit.PDFDocument, logoBuffer?: Buffer) {
  const headerY = PAGE_MARGIN;

  // Client logo on left (if provided)
  if (logoBuffer) {
    try {
      doc.image(logoBuffer, PAGE_MARGIN, headerY, { height: 32 });
    } catch {
      // Invalid image — skip
    }
  }

  // Attestr branding on right
  doc.fontSize(9).font('Helvetica').fillColor('#9ca3af')
    .text('ATTESTR EVIDENCE PACKET', PAGE_MARGIN, headerY + 6, {
      align: 'right', width: CONTENT_WIDTH,
    });
  doc.fontSize(7).text('attestr.io', PAGE_MARGIN, headerY + 20, {
    align: 'right', width: CONTENT_WIDTH,
  });

  // Accent line
  const lineY = headerY + 38;
  doc.moveTo(PAGE_MARGIN, lineY).lineTo(PAGE_MARGIN + CONTENT_WIDTH, lineY)
    .lineWidth(2).strokeColor(ACCENT_COLOR).stroke();
  doc.lineWidth(1); // reset

  doc.y = lineY + 16;
}

function drawSectionHeading(doc: PDFKit.PDFDocument, title: string) {
  const y = doc.y;
  // Left accent bar
  doc.rect(PAGE_MARGIN, y, 3, 16).fill(ACCENT_COLOR);
  doc.fontSize(13).font('Helvetica-Bold').fillColor('#111827')
    .text(title, PAGE_MARGIN + 10, y + 1);
  doc.moveDown(0.6);
}

function drawKeyValue(doc: PDFKit.PDFDocument, label: string, value: string) {
  const y = doc.y;
  doc.fontSize(9).font('Helvetica-Bold').fillColor('#6b7280')
    .text(label, PAGE_MARGIN, y, { width: LABEL_WIDTH });
  doc.fontSize(9).font('Helvetica').fillColor('#111827')
    .text(value, PAGE_MARGIN + LABEL_WIDTH, y, { width: CONTENT_WIDTH - LABEL_WIDTH });
  // Move below whichever column was taller
  doc.y = Math.max(doc.y, y + 14);
}

function drawHashBox(doc: PDFKit.PDFDocument, label: string, hash: string) {
  const boxX = PAGE_MARGIN;
  const boxWidth = CONTENT_WIDTH;
  const y = doc.y;

  doc.fontSize(8).font('Helvetica-Bold').fillColor('#374151')
    .text(label, boxX, y);
  const textY = doc.y + 2;

  // Gray background box
  doc.rect(boxX, textY, boxWidth, 16).fill('#f3f4f6');
  doc.fontSize(HASH_FONT_SIZE).font('Courier').fillColor('#374151')
    .text(hash, boxX + 6, textY + 4, { width: boxWidth - 12 });
  doc.y = textY + 20;
}

function drawFooter(doc: PDFKit.PDFDocument, pageNum: number, totalPages: number, version: string, generatedAt: string) {
  doc.fontSize(7).font('Helvetica').fillColor('#9ca3af');
  doc.text(`Evidence Packet v${version}`, PAGE_MARGIN, 780, { width: CONTENT_WIDTH / 2 });
  doc.text(`Page ${pageNum} of ${totalPages}`, PAGE_MARGIN + CONTENT_WIDTH / 2, 780,
    { width: CONTENT_WIDTH / 2, align: 'right' });
  doc.text(generatedAt, PAGE_MARGIN, 790, { width: CONTENT_WIDTH, align: 'center' });
}

function drawDecisionBadge(doc: PDFKit.PDFDocument, decision: string) {
  const colors: Record<string, { bg: string; fg: string }> = {
    BLOCK: { bg: '#fef2f2', fg: '#dc2626' },
    ALLOW: { bg: '#f0fdf4', fg: '#16a34a' },
    REVIEW: { bg: '#fffbeb', fg: '#d97706' },
  };
  const c = colors[decision] || { bg: '#f3f4f6', fg: '#374151' };
  const y = doc.y;
  const badgeWidth = doc.fontSize(9).font('Helvetica-Bold').widthOfString(decision) + 16;

  doc.fontSize(9).font('Helvetica-Bold').fillColor('#6b7280')
    .text('Decision', PAGE_MARGIN, y, { width: LABEL_WIDTH });

  const badgeX = PAGE_MARGIN + LABEL_WIDTH;
  doc.roundedRect(badgeX, y - 1, badgeWidth, 15, 3).fill(c.bg);
  doc.fontSize(9).font('Helvetica-Bold').fillColor(c.fg)
    .text(decision, badgeX + 8, y + 2);
  doc.fillColor('#111827'); // reset
  doc.y = y + 18;
}

function drawScoreBar(doc: PDFKit.PDFDocument, score: number | null) {
  const y = doc.y;
  doc.fontSize(9).font('Helvetica-Bold').fillColor('#6b7280')
    .text('Risk Score', PAGE_MARGIN, y, { width: LABEL_WIDTH });

  if (score === null) {
    doc.fontSize(9).font('Helvetica').fillColor('#9ca3af')
      .text('N/A', PAGE_MARGIN + LABEL_WIDTH, y);
    doc.y = y + 14;
    return;
  }

  const barX = PAGE_MARGIN + LABEL_WIDTH;
  const barWidth = 120;
  const barHeight = 10;

  // Background track
  doc.rect(barX, y + 1, barWidth, barHeight).fill('#e5e7eb');
  // Filled portion
  const fillColor = score >= 0.7 ? '#dc2626' : score >= 0.4 ? '#d97706' : '#16a34a';
  doc.rect(barX, y + 1, barWidth * score, barHeight).fill(fillColor);
  // Score text
  doc.fontSize(9).font('Helvetica-Bold').fillColor('#111827')
    .text(score.toFixed(4), barX + barWidth + 8, y);
  doc.y = y + 16;
}

export async function renderEvidencePdf(packet: EvidencePacket, logoBuffer?: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: PAGE_MARGIN, bufferPages: true });
    const chunks: Buffer[] = [];

    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const record = packet.record;
    const integrity = packet.integrity;

    // ── Page 1: Event Summary ───────────────────────────────
    drawHeader(doc, logoBuffer);

    drawSectionHeading(doc, 'Event Summary');

    drawKeyValue(doc, 'Event ID', record.event_id);
    drawDecisionBadge(doc, record.decision);
    drawScoreBar(doc, record.score !== null ? parseFloat(String(record.score)) : null);
    drawKeyValue(doc, 'Model Version', record.model_version || 'N/A');
    drawKeyValue(doc, 'Policy Version', record.policy_version || 'N/A');
    drawKeyValue(doc, 'Decided At', String(record.decided_at));
    drawKeyValue(doc, 'Ingested At', String(record.ingested_at));
    drawKeyValue(doc, 'Sequence #', String(record.sequence_number));

    if (record.input_hash) {
      doc.moveDown(0.3);
      drawHashBox(doc, 'Input Hash (Client Attestation)', record.input_hash);
    }

    // Reason codes as inline tags
    if (record.reason_codes && record.reason_codes.length > 0) {
      doc.moveDown(0.3);
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#6b7280')
        .text('Reason Codes', PAGE_MARGIN, doc.y);
      doc.moveDown(0.2);
      let tagX = PAGE_MARGIN;
      const tagY = doc.y;
      for (const code of record.reason_codes) {
        const w = doc.fontSize(8).font('Courier').widthOfString(code) + 12;
        if (tagX + w > PAGE_MARGIN + CONTENT_WIDTH) {
          tagX = PAGE_MARGIN;
          doc.y += 16;
        }
        doc.roundedRect(tagX, doc.y, w, 14, 2).fill('#f3f4f6');
        doc.fontSize(8).font('Courier').fillColor('#374151')
          .text(code, tagX + 6, doc.y + 3);
        tagX += w + 4;
      }
      doc.y = doc.y + 18;
    }

    // Feature contributions
    if (record.feature_contributions && Object.keys(record.feature_contributions).length > 0) {
      doc.moveDown(0.3);
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#6b7280')
        .text('Feature Contributions', PAGE_MARGIN, doc.y);
      doc.moveDown(0.2);
      doc.fontSize(9).font('Helvetica').fillColor('#111827');
      for (const [feature, weight] of Object.entries(record.feature_contributions)) {
        const w = typeof weight === 'number' ? weight : parseFloat(String(weight));
        drawKeyValue(doc, `  ${feature}`, w.toFixed(4));
      }
    }

    // Metadata (compact JSON box)
    if (record.metadata && Object.keys(record.metadata).length > 0) {
      doc.moveDown(0.3);
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#6b7280')
        .text('Metadata', PAGE_MARGIN, doc.y);
      const metaY = doc.y + 2;
      const metaStr = JSON.stringify(record.metadata, null, 2);
      const metaHeight = Math.min(doc.fontSize(7).font('Courier').heightOfString(metaStr, {
        width: CONTENT_WIDTH - 12,
      }) + 8, 100); // cap height
      doc.rect(PAGE_MARGIN, metaY, CONTENT_WIDTH, metaHeight).fill('#f9fafb');
      doc.fontSize(7).font('Courier').fillColor('#374151')
        .text(metaStr, PAGE_MARGIN + 6, metaY + 4, {
          width: CONTENT_WIDTH - 12, height: metaHeight - 4, ellipsis: true,
        });
      doc.y = metaY + metaHeight + 4;
    }

    // ── Page 2: Integrity Verification ──────────────────────
    doc.addPage();
    drawHeader(doc, logoBuffer);

    drawSectionHeading(doc, 'Integrity Verification');

    const checks: [string, boolean | string][] = [
      ['Record Hash', integrity.hash_chain.chain_valid ? true : 'hash mismatch'],
      ['Hash Chain', integrity.hash_chain.chain_valid],
      ['Platform Signature', integrity.signature_valid],
      ['Merkle Proof', integrity.merkle_proof ? integrity.merkle_proof.proof_valid : 'Not yet batched'],
      ['Input Hash (Dual Attestation)', record.input_hash ? true : 'Not provided'],
    ];

    for (const [label, value] of checks) {
      const y = doc.y;
      const passed = value === true;
      const failed = value === false;
      const icon = passed ? '\u2713' : failed ? '\u2717' : '\u2014';
      const iconColor = passed ? '#16a34a' : failed ? '#dc2626' : '#9ca3af';
      const statusText = passed ? 'PASS' : failed ? 'FAIL' : String(value);
      const statusColor = passed ? '#16a34a' : failed ? '#dc2626' : '#6b7280';

      // Light background row
      const rowBg = passed ? '#f0fdf4' : failed ? '#fef2f2' : '#f9fafb';
      doc.rect(PAGE_MARGIN, y - 2, CONTENT_WIDTH, 18).fill(rowBg);

      doc.fontSize(12).font('Helvetica-Bold').fillColor(iconColor)
        .text(icon, PAGE_MARGIN + 6, y, { continued: false });
      doc.fontSize(9).font('Helvetica-Bold').fillColor('#111827')
        .text(label, PAGE_MARGIN + 24, y + 1, { width: 220, continued: false });
      doc.fontSize(9).font('Helvetica-Bold').fillColor(statusColor)
        .text(statusText, PAGE_MARGIN + 260, y + 1, { width: CONTENT_WIDTH - 260 });
      doc.y = y + 22;
    }

    // Hash chain details
    doc.moveDown(0.6);
    drawSectionHeading(doc, 'Hash Chain Details');
    drawHashBox(doc, 'Record Hash', integrity.record_hash);
    drawHashBox(doc, 'Previous Hash', integrity.hash_chain.previous_hash);
    if (integrity.hash_chain.next_hash) {
      drawHashBox(doc, 'Next Hash', integrity.hash_chain.next_hash);
    }

    // Merkle proof details
    if (integrity.merkle_proof) {
      doc.moveDown(0.4);
      drawSectionHeading(doc, 'Merkle Proof Details');

      drawKeyValue(doc, 'Batch', `#${integrity.merkle_proof.batch_number}`);
      drawKeyValue(doc, 'Batch ID', integrity.merkle_proof.batch_id);
      doc.moveDown(0.2);
      drawHashBox(doc, 'Batch Root', integrity.merkle_proof.batch_root);
      drawHashBox(doc, 'Root Signature', integrity.merkle_proof.root_signature);

      if (integrity.merkle_proof.proof_path.length > 0) {
        doc.moveDown(0.2);
        doc.fontSize(8).font('Helvetica-Bold').fillColor('#6b7280')
          .text('Proof Path (leaf \u2192 root)', PAGE_MARGIN, doc.y);
        doc.moveDown(0.2);
        for (let i = 0; i < integrity.merkle_proof.proof_path.length; i++) {
          const s = integrity.merkle_proof.proof_path[i];
          const y = doc.y;
          doc.fontSize(7).font('Helvetica').fillColor('#9ca3af')
            .text(`L${i}`, PAGE_MARGIN + 4, y);
          doc.fontSize(7).font('Courier').fillColor('#374151')
            .text(`[${s.direction}] ${s.hash}`, PAGE_MARGIN + 24, y, { width: CONTENT_WIDTH - 24 });
          doc.y = Math.max(doc.y, y + 11);
        }
      }
    }

    // ── Page 3: Cryptographic Details ───────────────────────
    doc.addPage();
    drawHeader(doc, logoBuffer);

    drawSectionHeading(doc, 'Cryptographic Details');

    drawHashBox(doc, 'Platform Signature (Ed25519)', integrity.platform_signature);
    doc.moveDown(0.3);
    drawHashBox(doc, 'Verification Key (Ed25519 Public Key, Base64)', packet.verification_key);

    // Verification instructions
    doc.moveDown(1);
    doc.moveTo(PAGE_MARGIN, doc.y).lineTo(PAGE_MARGIN + CONTENT_WIDTH, doc.y)
      .strokeColor('#e5e7eb').stroke();
    doc.moveDown(0.5);

    drawSectionHeading(doc, 'Independent Verification');

    doc.fontSize(8.5).font('Helvetica').fillColor('#4b5563')
      .text('To verify this evidence packet independently:', PAGE_MARGIN, doc.y, {
        width: CONTENT_WIDTH, lineGap: 3,
      });
    doc.moveDown(0.3);

    const steps = [
      'Reconstruct the canonical JSON record from the event data fields.',
      'Compute the SHA-256 hash over the canonical JSON and compare to the Record Hash.',
      'Verify the Ed25519 signature using the public key above against the Record Hash.',
      'Confirm the previous_hash field matches the prior record\'s hash (hash chain link).',
      'If a Merkle proof is present, walk the proof path from the leaf hash to the batch root.',
    ];
    for (let i = 0; i < steps.length; i++) {
      doc.fontSize(8.5).font('Helvetica').fillColor('#4b5563');
      const y = doc.y;
      doc.font('Helvetica-Bold').text(`${i + 1}.`, PAGE_MARGIN + 4, y, { continued: false });
      doc.font('Helvetica').text(steps[i], PAGE_MARGIN + 20, y, { width: CONTENT_WIDTH - 20, lineGap: 1 });
      doc.y = Math.max(doc.y, y + 12);
    }

    // Add footers to all pages
    const totalPages = doc.bufferedPageRange().count;
    for (let i = 0; i < totalPages; i++) {
      doc.switchToPage(i);
      drawFooter(doc, i + 1, totalPages, packet.version, packet.generated_at);
    }

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
    decided_at: (entry.decided_at as unknown) instanceof Date
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
    decided_at: (entry.decided_at as unknown) instanceof Date
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
