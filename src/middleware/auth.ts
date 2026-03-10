import type { FastifyRequest, FastifyReply } from 'fastify';
import { config } from '../config.ts';
import { computeHmac, verifyHmac } from '../services/crypto.ts';
import { getTenantById } from '../db/queries.ts';

export async function authenticateRequest(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const tenantId = request.headers['x-tenant-id'] as string | undefined;
  const timestamp = request.headers['x-timestamp'] as string | undefined;
  const signature = request.headers['x-signature'] as string | undefined;

  // Check required headers
  if (!tenantId || !timestamp || !signature) {
    reply.code(401).send({
      error: 'Missing required authentication headers',
      detail: 'Requests must include X-Tenant-Id, X-Timestamp, and X-Signature headers.',
    });
    return;
  }

  // Check timestamp freshness (replay protection)
  const requestTime = new Date(timestamp).getTime();
  const now = Date.now();
  if (isNaN(requestTime) || Math.abs(now - requestTime) > config.maxRequestAgeMs) {
    reply.code(401).send({
      error: 'Request timestamp expired or invalid',
      detail: 'X-Timestamp must be a valid ISO 8601 date within 5 minutes of current time.',
    });
    return;
  }

  // Look up tenant
  const tenant = await getTenantById(tenantId);
  if (!tenant) {
    reply.code(401).send({
      error: 'Invalid tenant',
      detail: 'Tenant not found or inactive.',
    });
    return;
  }

  // Compute expected HMAC using raw body (preserves original JSON for signature match)
  const body = (request as any).rawBody || '';
  const expectedHmac = computeHmac(
    request.method,
    request.url.split('?')[0], // path without query string
    timestamp,
    body,
    tenant.hmac_secret
  );

  // Verify signature with timing-safe comparison
  if (!verifyHmac(expectedHmac, signature)) {
    reply.code(401).send({
      error: 'Invalid signature',
      detail: 'HMAC-SHA256 signature does not match.',
    });
    return;
  }

  // Attach tenant to request for downstream use
  request.tenant = tenant;
}
