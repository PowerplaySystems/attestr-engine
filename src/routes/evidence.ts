import type { FastifyInstance } from 'fastify';
import { authenticateRequest } from '../middleware/auth.ts';
import { verifyRecord, generateEvidencePacket, renderEvidencePdf } from '../services/evidence.ts';
import { config } from '../config.ts';

export async function evidenceRoutes(app: FastifyInstance): Promise<void> {
  // === Public key endpoint (no auth) ===
  app.get('/v1/public-key', async (_request, reply) => {
    return reply.code(200).send({
      algorithm: 'Ed25519',
      public_key: config.ed25519PublicKey,
      format: 'base64',
    });
  });

  // === Authenticated routes ===

  // POST /v1/decisions/:event_id/verify — Verify record integrity
  app.post<{ Params: { event_id: string } }>('/v1/decisions/:event_id/verify', {
    preHandler: authenticateRequest,
  }, async (request, reply) => {
    const tenantId = request.tenant!.id;
    const { event_id } = request.params;

    const result = await verifyRecord(tenantId, event_id);
    if (!result) {
      return reply.code(404).send({
        error: 'Not found',
        detail: `Decision record with event_id "${event_id}" not found.`,
      });
    }

    return reply.code(200).send(result);
  });

  // GET /v1/decisions/:event_id/evidence — Get evidence packet (JSON or PDF)
  app.get<{ Params: { event_id: string }; Querystring: { format?: string } }>('/v1/decisions/:event_id/evidence', {
    preHandler: authenticateRequest,
  }, async (request, reply) => {
    const tenantId = request.tenant!.id;
    const { event_id } = request.params;
    const format = (request.query.format || 'json').toLowerCase();

    if (format !== 'json' && format !== 'pdf') {
      return reply.code(400).send({
        error: 'Invalid format',
        detail: 'Query parameter "format" must be "json" or "pdf".',
      });
    }

    const packet = await generateEvidencePacket(tenantId, event_id);
    if (!packet) {
      return reply.code(404).send({
        error: 'Not found',
        detail: `Decision record with event_id "${event_id}" not found.`,
      });
    }

    if (format === 'pdf') {
      const pdfBuffer = await renderEvidencePdf(packet);
      return reply
        .code(200)
        .header('Content-Type', 'application/pdf')
        .header('Content-Disposition', `attachment; filename="evidence_${event_id}_${Date.now()}.pdf"`)
        .send(pdfBuffer);
    }

    return reply.code(200).send({ evidence_packet: packet });
  });
}
