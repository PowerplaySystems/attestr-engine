import type { FastifyInstance } from 'fastify';
import { authenticateRequest } from '../middleware/auth.ts';
import {
  listAnomalyAlerts,
  getAnomalyAlert,
  acknowledgeAlert,
} from '../db/queries.ts';
import type { AnomalyType, AnomalySeverity } from '../types/index.ts';

export async function anomalyRoutes(app: FastifyInstance): Promise<void> {
  // GET /v1/anomalies — List anomaly alerts for tenant
  app.get<{
    Querystring: {
      type?: AnomalyType;
      severity?: AnomalySeverity;
      acknowledged?: string;
      from?: string;
      to?: string;
      cursor?: string;
      limit?: string;
    };
  }>('/v1/anomalies', {
    preHandler: authenticateRequest,
    schema: {
      querystring: {
        type: 'object',
        properties: {
          type: { type: 'string', enum: ['score_drift', 'block_rate', 'recording_gap', 'reason_shift', 'model_transition', 'velocity'] },
          severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
          acknowledged: { type: 'string', enum: ['true', 'false'] },
          from: { type: 'string', format: 'date-time' },
          to: { type: 'string', format: 'date-time' },
          cursor: { type: 'string' },
          limit: { type: 'string', pattern: '^[0-9]+$' },
        },
      },
    },
  }, async (request, reply) => {
    const tenantId = request.tenant!.id;
    const q = request.query;

    const { rows, totalCount } = await listAnomalyAlerts(tenantId, {
      type: q.type,
      severity: q.severity,
      acknowledged: q.acknowledged !== undefined ? q.acknowledged === 'true' : undefined,
      from: q.from,
      to: q.to,
      cursor: q.cursor,
      limit: q.limit ? parseInt(q.limit, 10) : undefined,
    });

    const limit = q.limit ? Math.min(parseInt(q.limit, 10), 200) : 50;
    const lastRow = rows[rows.length - 1];
    const cursor = rows.length === limit && lastRow
      ? Buffer.from(lastRow.detected_at).toString('base64')
      : null;

    return reply.code(200).send({
      alerts: rows,
      pagination: {
        cursor,
        has_more: rows.length === limit,
      },
      total_count: totalCount,
    });
  });

  // GET /v1/anomalies/:id — Get single anomaly alert detail
  app.get<{ Params: { id: string } }>('/v1/anomalies/:id', {
    preHandler: authenticateRequest,
    schema: {
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
      },
    },
  }, async (request, reply) => {
    const tenantId = request.tenant!.id;
    const { id } = request.params;

    const alert = await getAnomalyAlert(tenantId, id);
    if (!alert) {
      return reply.code(404).send({
        error: 'Not found',
        detail: 'Anomaly alert not found for the given id.',
      });
    }

    return reply.code(200).send(alert);
  });

  // POST /v1/anomalies/:id/acknowledge — Acknowledge an alert
  app.post<{ Params: { id: string } }>('/v1/anomalies/:id/acknowledge', {
    preHandler: authenticateRequest,
    schema: {
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'string', format: 'uuid' },
        },
      },
    },
  }, async (request, reply) => {
    const tenantId = request.tenant!.id;
    const { id } = request.params;

    const alert = await acknowledgeAlert(tenantId, id);
    if (!alert) {
      return reply.code(404).send({
        error: 'Not found',
        detail: 'Anomaly alert not found for the given id.',
      });
    }

    return reply.code(200).send({
      acknowledged: true,
      acknowledged_at: alert.acknowledged_at,
    });
  });
}
