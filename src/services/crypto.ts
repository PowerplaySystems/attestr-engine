import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

// === Canonical JSON (RFC 8785 — JSON Canonicalization Scheme) ===

export function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      // Sort object keys
      return Object.keys(value).sort().reduce((sorted: Record<string, unknown>, key) => {
        sorted[key] = (value as Record<string, unknown>)[key];
        return sorted;
      }, {});
    }
    return value;
  });
}

// === SHA-256 Hashing ===

export function sha256Hash(data: string): string {
  return 'sha256:' + createHash('sha256').update(data, 'utf-8').digest('hex');
}

// === Ed25519 Signing ===

export function generateEd25519Keypair(): { publicKey: string; privateKey: string } {
  const keypair = nacl.sign.keyPair();
  return {
    publicKey: naclUtil.encodeBase64(keypair.publicKey),
    privateKey: naclUtil.encodeBase64(keypair.secretKey),
  };
}

export function signRecord(hash: string, privateKeyBase64: string): string {
  const privateKey = naclUtil.decodeBase64(privateKeyBase64);
  // Strip the 'sha256:' prefix for signing, sign the raw hex hash
  const hashBytes = naclUtil.decodeUTF8(hash.replace('sha256:', ''));
  const signature = nacl.sign.detached(hashBytes, privateKey);
  return 'ed25519:' + naclUtil.encodeBase64(signature);
}

export function verifySignature(hash: string, signatureStr: string, publicKeyBase64: string): boolean {
  try {
    const publicKey = naclUtil.decodeBase64(publicKeyBase64);
    const hashBytes = naclUtil.decodeUTF8(hash.replace('sha256:', ''));
    const signature = naclUtil.decodeBase64(signatureStr.replace('ed25519:', ''));
    return nacl.sign.detached.verify(hashBytes, signature, publicKey);
  } catch {
    return false;
  }
}

// === Merkle Tree Hash Helper ===

export function hashPair(a: string, b: string): string {
  // Strip 'sha256:' prefix if present, concatenate raw hex, re-hash
  const aHex = a.replace('sha256:', '');
  const bHex = b.replace('sha256:', '');
  return sha256Hash(aHex + bHex);
}

// === HMAC-SHA256 for Request Authentication ===

export function computeHmac(
  method: string,
  path: string,
  timestamp: string,
  body: string,
  secret: string
): string {
  const message = `${method}\n${path}\n${timestamp}\n${body}`;
  return createHmac('sha256', secret).update(message, 'utf-8').digest('hex');
}

export function verifyHmac(
  expected: string,
  actual: string
): boolean {
  try {
    const expectedBuf = Buffer.from(expected, 'hex');
    const actualBuf = Buffer.from(actual, 'hex');
    if (expectedBuf.length !== actualBuf.length) return false;
    return timingSafeEqual(expectedBuf, actualBuf);
  } catch {
    return false;
  }
}
