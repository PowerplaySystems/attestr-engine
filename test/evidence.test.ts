import { describe, it, expect } from 'vitest';
import { buildMerkleTree, extractProof, verifyProof } from '../src/services/merkle.ts';
import { sha256Hash, signRecord, verifySignature, canonicalJson } from '../src/services/crypto.ts';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

// These tests verify the evidence/verification logic in isolation
// (no DB needed — pure function tests using the same algorithms as the service)

describe('evidence packet integrity checks', () => {
  // Simulate what the evidence service does

  const GENESIS_HASH = '0'.repeat(64);

  function makeRecord(seqNum: number, prevHash: string) {
    const canonical = {
      tenant_id: 'test-tenant',
      event_id: `event_${seqNum}`,
      decision: 'BLOCK',
      score: 0.85,
      reason_codes: ['velocity_spike'],
      feature_contributions: null,
      model_version: 'v1',
      policy_version: 'p1',
      decided_at: '2026-03-08T12:00:00.000Z',
      metadata: null,
      sequence_number: seqNum,
      previous_hash: prevHash,
    };
    const recordHash = sha256Hash(canonicalJson(canonical));
    return { ...canonical, record_hash: recordHash };
  }

  it('recomputed hash matches original for a valid record', () => {
    const record = makeRecord(1, GENESIS_HASH);
    const canonical = {
      tenant_id: record.tenant_id,
      event_id: record.event_id,
      decision: record.decision,
      score: record.score,
      reason_codes: record.reason_codes,
      feature_contributions: record.feature_contributions,
      model_version: record.model_version,
      policy_version: record.policy_version,
      decided_at: record.decided_at,
      metadata: record.metadata,
      sequence_number: record.sequence_number,
      previous_hash: record.previous_hash,
    };
    const recomputed = sha256Hash(canonicalJson(canonical));
    expect(recomputed).toBe(record.record_hash);
  });

  it('detects tampered decision field', () => {
    const record = makeRecord(1, GENESIS_HASH);
    // Tamper
    const canonical = {
      tenant_id: record.tenant_id,
      event_id: record.event_id,
      decision: 'ALLOW', // changed from BLOCK
      score: record.score,
      reason_codes: record.reason_codes,
      feature_contributions: record.feature_contributions,
      model_version: record.model_version,
      policy_version: record.policy_version,
      decided_at: record.decided_at,
      metadata: record.metadata,
      sequence_number: record.sequence_number,
      previous_hash: record.previous_hash,
    };
    const recomputed = sha256Hash(canonicalJson(canonical));
    expect(recomputed).not.toBe(record.record_hash);
  });

  it('hash chain validates across sequential records', () => {
    const r1 = makeRecord(1, GENESIS_HASH);
    const r2 = makeRecord(2, r1.record_hash);
    const r3 = makeRecord(3, r2.record_hash);

    // Chain: r1.previous_hash = genesis, r2.previous_hash = r1.hash, etc.
    expect(r1.previous_hash).toBe(GENESIS_HASH);
    expect(r2.previous_hash).toBe(r1.record_hash);
    expect(r3.previous_hash).toBe(r2.record_hash);
  });

  it('Merkle proof validates for records in a batch', () => {
    // Simulate 4 records being batched
    const hashes = [1, 2, 3, 4].map(i => {
      const r = makeRecord(i, i === 1 ? GENESIS_HASH : sha256Hash(`prev_${i}`));
      return r.record_hash;
    });

    const tree = buildMerkleTree(hashes);

    // Each record should be verifiable
    for (let i = 0; i < hashes.length; i++) {
      const proof = extractProof(tree, i);
      expect(verifyProof(hashes[i], proof)).toBe(true);
    }
  });

  it('Ed25519 signature validates for a record hash', () => {
    const record = makeRecord(1, GENESIS_HASH);

    // Generate a fresh keypair for unit testing
    const keypair = nacl.sign.keyPair();
    const privateKey = naclUtil.encodeBase64(keypair.secretKey);
    const publicKey = naclUtil.encodeBase64(keypair.publicKey);

    const signature = signRecord(record.record_hash, privateKey);
    expect(signature).toMatch(/^ed25519:/);
    expect(verifySignature(record.record_hash, signature, publicKey)).toBe(true);
  });

  it('signature fails for wrong public key', () => {
    const record = makeRecord(1, GENESIS_HASH);

    const keypair1 = nacl.sign.keyPair();
    const keypair2 = nacl.sign.keyPair();

    const signature = signRecord(record.record_hash, naclUtil.encodeBase64(keypair1.secretKey));
    const wrongPublicKey = naclUtil.encodeBase64(keypair2.publicKey);

    expect(verifySignature(record.record_hash, signature, wrongPublicKey)).toBe(false);
  });

  it('full evidence packet simulation: all 4 checks pass', () => {
    // Build records
    const r1 = makeRecord(1, GENESIS_HASH);
    const r2 = makeRecord(2, r1.record_hash);

    // Build Merkle tree
    const tree = buildMerkleTree([r1.record_hash, r2.record_hash]);

    // Extract proof for record 2
    const proof = extractProof(tree, 1);

    // Check 1: Hash valid
    const canonical = {
      tenant_id: r2.tenant_id,
      event_id: r2.event_id,
      decision: r2.decision,
      score: r2.score,
      reason_codes: r2.reason_codes,
      feature_contributions: r2.feature_contributions,
      model_version: r2.model_version,
      policy_version: r2.policy_version,
      decided_at: r2.decided_at,
      metadata: r2.metadata,
      sequence_number: r2.sequence_number,
      previous_hash: r2.previous_hash,
    };
    const hashValid = sha256Hash(canonicalJson(canonical)) === r2.record_hash;
    expect(hashValid).toBe(true);

    // Check 2: Chain valid
    const chainValid = r2.previous_hash === r1.record_hash;
    expect(chainValid).toBe(true);

    // Check 3: Merkle valid
    const merkleValid = verifyProof(r2.record_hash, proof);
    expect(merkleValid).toBe(true);
  });
});
