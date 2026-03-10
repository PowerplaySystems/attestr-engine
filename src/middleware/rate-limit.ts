import type { FastifyInstance } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { config } from '../config.ts';

export async function registerRateLimit(app: FastifyInstance): Promise<void> {
  await app.register(rateLimit, {
    max: (request) => {
      const tier = request.tenant?.tier || 'free';
      return config.rateLimits[tier] || config.rateLimits.free;
    },
    timeWindow: '1 minute',
    keyGenerator: (request) => {
      // Rate limit per tenant, not per IP
      return (request.headers['x-tenant-id'] as string) || request.ip;
    },
    errorResponseBuilder: (_request, context) => {
      return {
        error: 'Rate limit exceeded',
        detail: `You have exceeded the ${context.max} requests per minute limit. Retry after ${context.after}.`,
      };
    },
  });
}
