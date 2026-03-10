import { describe, it, expect } from 'vitest';
import {
  canonicalJson,
  sha256Hash,
  generateEd25519Keypair,
  signRecord,
  verifySignature,
  computeHmac,
  verifyHmac,
} from '../src/services/crypto.ts';

describe('canonicalJson', () => {
  it('sorts object keys alphabetically', () => {
    const obj = { z: 1, a: 2, m: 3 };
    expect(canonicalJson(obj)).toBe('{"a":2,"m":3,"z":1}');
  });

  it('sorts nested object keys', () => {
    const obj = { b: { z: 1, a: 2 }, a: 1 };
    expect(canonicalJson(obj)).toBe('{"a":1,"b":{"a":2,"z":1}}');
  });

  it('preserves array order', () => {
    const obj = { arr: [3, 1, 2] };
    expect(canonicalJson(obj)).toBe('{"arr":[3,1,2]}');
  });

  it('handles null values', () => {
    const obj = { a: null, b: 1 };
    expect(canonicalJson(obj)).toBe('{"a":null,"b":1}');
  });

  it('produces identical output for differently-ordered inputs', () => {
    const a = { event_id: 'test', decision: 'BLOCK', score: 0.9 };
    const b = { score: 0.9, event_id: 'test', decision: 'BLOCK' };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
  });
});

describe('sha256Hash', () => {
  it('produces a sha256-prefixed hex hash', () => {
    const hash = sha256Hash('hello');
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('produces deterministic output', () => {
    expect(sha256Hash('test')).toBe(sha256Hash('test'));
  });

  it('produces different hashes for different inputs', () => {
    expect(sha256Hash('a')).not.toBe(sha256Hash('b'));
  });
});

describe('Ed25519 signing', () => {
  it('generates a valid keypair', () => {
    const keypair = generateEd25519Keypair();
    expect(keypair.publicKey).toBeTruthy();
    expect(keypair.privateKey).toBeTruthy();
    // Ed25519 public key is 32 bytes = 44 base64 chars
    expect(keypair.publicKey.length).toBe(44);
    // Ed25519 secret key is 64 bytes = 88 base64 chars
    expect(keypair.privateKey.length).toBe(88);
  });

  it('signs and verifies a hash', () => {
    const keypair = generateEd25519Keypair();
    const hash = sha256Hash('test record');
    const signature = signRecord(hash, keypair.privateKey);

    expect(signature).toMatch(/^ed25519:/);
    expect(verifySignature(hash, signature, keypair.publicKey)).toBe(true);
  });

  it('rejects invalid signature', () => {
    const keypair1 = generateEd25519Keypair();
    const keypair2 = generateEd25519Keypair();
    const hash = sha256Hash('test record');
    const signature = signRecord(hash, keypair1.privateKey);

    // Wrong public key
    expect(verifySignature(hash, signature, keypair2.publicKey)).toBe(false);
  });

  it('rejects tampered hash', () => {
    const keypair = generateEd25519Keypair();
    const hash = sha256Hash('original');
    const signature = signRecord(hash, keypair.privateKey);

    const tamperedHash = sha256Hash('tampered');
    expect(verifySignature(tamperedHash, signature, keypair.publicKey)).toBe(false);
  });
});

describe('HMAC', () => {
  it('computes deterministic HMAC', () => {
    const hmac1 = computeHmac('POST', '/v1/decisions', '2026-03-08T00:00:00Z', '{"test":true}', 'secret');
    const hmac2 = computeHmac('POST', '/v1/decisions', '2026-03-08T00:00:00Z', '{"test":true}', 'secret');
    expect(hmac1).toBe(hmac2);
  });

  it('produces different HMAC for different secrets', () => {
    const hmac1 = computeHmac('POST', '/v1/decisions', '2026-03-08T00:00:00Z', '{}', 'secret1');
    const hmac2 = computeHmac('POST', '/v1/decisions', '2026-03-08T00:00:00Z', '{}', 'secret2');
    expect(hmac1).not.toBe(hmac2);
  });

  it('verifies matching HMAC', () => {
    const hmac = computeHmac('POST', '/v1/decisions', '2026-03-08T00:00:00Z', '{}', 'secret');
    expect(verifyHmac(hmac, hmac)).toBe(true);
  });

  it('rejects non-matching HMAC', () => {
    const hmac1 = computeHmac('POST', '/v1/decisions', '2026-03-08T00:00:00Z', '{}', 'secret1');
    const hmac2 = computeHmac('POST', '/v1/decisions', '2026-03-08T00:00:00Z', '{}', 'secret2');
    expect(verifyHmac(hmac1, hmac2)).toBe(false);
  });
});
