import { computeHmac } from '../src/services/crypto.ts';

const BASE = process.env.API_BASE_URL || 'http://localhost:3001';
const TENANT_ID = '2ac7d2ca-0579-40ea-bc6f-6450af45de26';
const HMAC_SECRET = '8738157f09d33bf6e28cc1799e606869172876fd1f9d99d1a128c53450397ce7';

function sign(method: string, path: string, body: string = '') {
  const timestamp = new Date().toISOString();
  const signature = computeHmac(method, path, timestamp, body, HMAC_SECRET);
  return { timestamp, signature };
}

async function main() {
  console.log('=== Attestr E2E Test ===\n');

  // 1. Health check
  const health = await fetch(`${BASE}/health`);
  console.log('1. Health:', (await health.json() as { status: string }).status);

  // 2. POST a decision
  const body = JSON.stringify({
    event_id: 'e2e_test_001',
    decision: 'BLOCK',
    score: 0.92,
    reason_codes: ['velocity_spike', 'new_account'],
    feature_contributions: { transaction_amount: 0.35, account_age_days: 0.28 },
    model_version: 'xgb-v2.4.1',
    policy_version: 'policy-2026-Q1',
    decided_at: '2026-03-08T14:32:01.441Z',
    metadata: { channel: 'ACH', amount_cents: 485000 },
  });

  const { timestamp: t1, signature: s1 } = sign('POST', '/v1/decisions', body);
  const postRes = await fetch(`${BASE}/v1/decisions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t1,
      'X-Signature': s1,
    },
    body,
  });
  const postData = await postRes.json();
  console.log(`2. POST /v1/decisions: ${postRes.status} (${postRes.status === 201 ? 'PASS' : 'FAIL'})`);
  console.log(`   Ledger ID: ${(postData as { ledger_entry_id: string }).ledger_entry_id}`);
  console.log(`   Hash: ${(postData as { record_hash: string }).record_hash}`);
  console.log(`   Signature: ${(postData as { platform_signature: string }).platform_signature?.slice(0, 30)}...`);

  // 3. GET the decision back
  const { timestamp: t2, signature: s2 } = sign('GET', '/v1/decisions/e2e_test_001');
  const getRes = await fetch(`${BASE}/v1/decisions/e2e_test_001`, {
    headers: {
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t2,
      'X-Signature': s2,
    },
  });
  const getData = await getRes.json() as { event_id: string; decision: string; record_hash: string; previous_hash: string };
  console.log(`3. GET /v1/decisions/e2e_test_001: ${getRes.status} (${getRes.status === 200 ? 'PASS' : 'FAIL'})`);
  console.log(`   Decision: ${getData.decision}, Score hash chain: prev=${getData.previous_hash?.slice(0, 20)}...`);

  // 4. Idempotency: POST same event_id again
  const { timestamp: t3, signature: s3 } = sign('POST', '/v1/decisions', body);
  const idempRes = await fetch(`${BASE}/v1/decisions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t3,
      'X-Signature': s3,
    },
    body,
  });
  console.log(`4. Idempotency: ${idempRes.status} (${idempRes.status === 200 ? 'PASS — returned existing' : 'FAIL'})`);

  // 5. POST a second decision and verify hash chain
  const body2 = JSON.stringify({
    event_id: 'e2e_test_002',
    decision: 'ALLOW',
    score: 0.15,
    reason_codes: ['low_risk'],
    decided_at: '2026-03-08T14:35:00.000Z',
  });
  const { timestamp: t4, signature: s4 } = sign('POST', '/v1/decisions', body2);
  const postRes2 = await fetch(`${BASE}/v1/decisions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t4,
      'X-Signature': s4,
    },
    body: body2,
  });
  const postData2 = await postRes2.json() as { previous_hash: string; record_hash: string };
  const chainValid = postData2.previous_hash === (postData as { record_hash: string }).record_hash;
  console.log(`5. Hash chain: record 2 previous_hash === record 1 record_hash? ${chainValid ? 'PASS' : 'FAIL'}`);

  // 6. List decisions
  const { timestamp: t5, signature: s5 } = sign('GET', '/v1/decisions');
  const listRes = await fetch(`${BASE}/v1/decisions`, {
    headers: {
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t5,
      'X-Signature': s5,
    },
  });
  const listData = await listRes.json() as { total_count: number; records: unknown[] };
  console.log(`6. GET /v1/decisions: ${listRes.status}, ${listData.total_count} records (${listData.total_count >= 2 ? 'PASS' : 'FAIL'})`);

  // 7. Auth failure test
  const badRes = await fetch(`${BASE}/v1/decisions`, {
    headers: {
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': new Date().toISOString(),
      'X-Signature': 'bad_signature',
    },
  });
  console.log(`7. Bad auth: ${badRes.status} (${badRes.status === 401 ? 'PASS — rejected' : 'FAIL'})`);

  // === Phase 2 Tests ===

  // 8. Public key endpoint (no auth required)
  const pubKeyRes = await fetch(`${BASE}/v1/public-key`);
  const pubKeyData = await pubKeyRes.json() as { algorithm: string; public_key: string; format: string };
  console.log(`8. GET /v1/public-key: ${pubKeyRes.status} (${pubKeyRes.status === 200 && pubKeyData.algorithm === 'Ed25519' ? 'PASS' : 'FAIL'})`);
  console.log(`   Algorithm: ${pubKeyData.algorithm}, Key: ${pubKeyData.public_key?.slice(0, 20)}...`);

  // 9. Verify a record
  const verifyBody = JSON.stringify({});
  const { timestamp: t6, signature: s6 } = sign('POST', '/v1/decisions/e2e_test_001/verify', verifyBody);
  const verifyRes = await fetch(`${BASE}/v1/decisions/e2e_test_001/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t6,
      'X-Signature': s6,
    },
    body: verifyBody,
  });
  const verifyData = await verifyRes.json() as {
    status: string;
    checks: { hash_valid: boolean; chain_valid: boolean; signature_valid: boolean; merkle_valid: boolean; merkle_note?: string };
  };
  const allChecksPass = verifyData.checks.hash_valid && verifyData.checks.chain_valid && verifyData.checks.signature_valid && verifyData.checks.merkle_valid;
  console.log(`9. POST /v1/decisions/e2e_test_001/verify: ${verifyRes.status} (${verifyData.status === 'VERIFIED' && allChecksPass ? 'PASS' : 'FAIL'})`);
  console.log(`   Status: ${verifyData.status} | hash=${verifyData.checks.hash_valid} chain=${verifyData.checks.chain_valid} sig=${verifyData.checks.signature_valid} merkle=${verifyData.checks.merkle_valid}`);
  if (verifyData.checks.merkle_note) {
    console.log(`   Note: ${verifyData.checks.merkle_note}`);
  }

  // 10. Get evidence packet (JSON)
  const { timestamp: t7, signature: s7 } = sign('GET', '/v1/decisions/e2e_test_001/evidence');
  const evidenceRes = await fetch(`${BASE}/v1/decisions/e2e_test_001/evidence?format=json`, {
    headers: {
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t7,
      'X-Signature': s7,
    },
  });
  const evidenceData = await evidenceRes.json() as {
    evidence_packet: {
      version: string;
      record: { event_id: string };
      integrity: { record_hash: string; signature_valid: boolean };
      verification_key: string;
    };
  };
  const packetValid = evidenceData.evidence_packet?.version === '1.0'
    && evidenceData.evidence_packet?.record?.event_id === 'e2e_test_001'
    && evidenceData.evidence_packet?.integrity?.signature_valid === true
    && evidenceData.evidence_packet?.verification_key;
  console.log(`10. GET /v1/decisions/e2e_test_001/evidence: ${evidenceRes.status} (${packetValid ? 'PASS' : 'FAIL'})`);
  console.log(`    Packet v${evidenceData.evidence_packet?.version}, sig_valid=${evidenceData.evidence_packet?.integrity?.signature_valid}`);

  // 11. Get evidence as PDF
  const { timestamp: t8, signature: s8 } = sign('GET', '/v1/decisions/e2e_test_001/evidence');
  const pdfRes = await fetch(`${BASE}/v1/decisions/e2e_test_001/evidence?format=pdf`, {
    headers: {
      'X-Tenant-Id': TENANT_ID,
      'X-Timestamp': t8,
      'X-Signature': s8,
    },
  });
  const contentType = pdfRes.headers.get('content-type') || '';
  const pdfBuffer = await pdfRes.arrayBuffer();
  const isPdf = contentType.includes('application/pdf') && pdfBuffer.byteLength > 0;
  console.log(`11. GET /v1/decisions/e2e_test_001/evidence?format=pdf: ${pdfRes.status} (${isPdf ? 'PASS' : 'FAIL'})`);
  console.log(`    Content-Type: ${contentType}, Size: ${pdfBuffer.byteLength} bytes`);

  console.log('\n=== Done ===');
}

main().catch(console.error);
