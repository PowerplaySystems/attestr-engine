import type { FastifyInstance } from 'fastify';
import { authenticateRequest } from '../middleware/auth.ts';
import { ingestDecision, toIngestResponse, getDecision, listDecisions } from '../services/ledger.ts';
import type { DecisionPayload, ListFilters } from '../types/index.ts';

// JSON Schema for request validation
const decisionBodySchema = {
  type: 'object',
  required: ['event_id', 'decision', 'reason_codes', 'decided_at'],
  properties: {
    event_id: { type: 'string', minLength: 1, maxLength: 255 },
    decision: { type: 'string', minLength: 1, maxLength: 50 },
    score: { type: 'number', minimum: 0, maximum: 1 },
    reason_codes: {
      type: 'array',
      items: { type: 'string' },
      minItems: 0,
      maxItems: 100,
    },
    feature_contributions: {
      type: 'object',
      additionalProperties: { type: 'number' },
    },
    model_version: { type: 'string', maxLength: 100 },
    policy_version: { type: 'string', maxLength: 100 },
    decided_at: { type: 'string', format: 'date-time' },
    metadata: { type: 'object' },
    input_hash: { type: 'string', minLength: 64, maxLength: 64, pattern: '^[a-f0-9]{64}$' },
  },
  additionalProperties: false,
};

export async function decisionRoutes(app: FastifyInstance): Promise<void> {
  // All routes require authentication (preHandler runs after body parsing so rawBody is available)
  app.addHook('preHandler', authenticateRequest);

  // POST /v1/decisions — Ingest a decision record
  app.post<{ Body: DecisionPayload }>('/v1/decisions', {
    schema: { body: decisionBodySchema },
  }, async (request, reply) => {
    const tenantId = request.tenant!.id;
    const payload = request.body;

    try {
      const { entry, created } = await ingestDecision(tenantId, payload);
      const response = toIngestResponse(entry);

      return reply.code(created ? 201 : 200).send(response);
    } catch (error: unknown) {
      // Handle unique constraint violation (race condition on idempotency)
      if (error && typeof error === 'object' && 'code' in error && (error as { code: string }).code === '23505') {
        // Unique violation — event_id already exists, fetch and return
        const existing = await getDecision(tenantId, payload.event_id);
        if (existing) {
          return reply.code(200).send(toIngestResponse(existing));
        }
      }
      throw error;
    }
  });

  // GET /v1/decisions/:event_id — Retrieve a single decision record
  app.get<{ Params: { event_id: string } }>('/v1/decisions/:event_id', async (request, reply) => {
    const tenantId = request.tenant!.id;
    const { event_id } = request.params;

    const entry = await getDecision(tenantId, event_id);
    if (!entry) {
      return reply.code(404).send({
        error: 'Not found',
        detail: `Decision record with event_id "${event_id}" not found.`,
      });
    }

    return reply.code(200).send(entry);
  });

  // GET /v1/decisions — List/search decision records
  app.get<{ Querystring: ListFilters }>('/v1/decisions', async (request, reply) => {
    const tenantId = request.tenant!.id;
    const filters: ListFilters = {
      from: request.query.from,
      to: request.query.to,
      decision: request.query.decision,
      min_score: request.query.min_score ? Number(request.query.min_score) : undefined,
      max_score: request.query.max_score ? Number(request.query.max_score) : undefined,
      cursor: request.query.cursor,
      limit: request.query.limit ? Number(request.query.limit) : 50,
    };

    const result = await listDecisions(tenantId, filters);
    return reply.code(200).send(result);
  });
}
