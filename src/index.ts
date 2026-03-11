import Fastify from 'fastify';
import cors from '@fastify/cors';
import { config } from './config.ts';
import { registerRateLimit } from './middleware/rate-limit.ts';
import { decisionRoutes } from './routes/decisions.ts';
import { evidenceRoutes } from './routes/evidence.ts';
import { anomalyRoutes } from './routes/anomalies.ts';
import { processAllPendingBatches } from './services/merkle.ts';
import { processAllTenantAnomalies } from './services/anomaly.ts';

const app = Fastify({
  logger: config.nodeEnv === 'production'
    ? { level: 'info' }
    : true,
});

// Capture raw request body before Fastify parses it.
// Required for HMAC signature verification — the signature is computed over
// the exact bytes the client sent, not a re-serialized version.
app.addHook('preParsing', async (request, reply, payload) => {
  const MAX_BODY_SIZE = 1_000_000; // 1 MB
  const chunks: Buffer[] = [];
  let totalSize = 0;
  for await (const chunk of payload) {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
    totalSize += buf.length;
    if (totalSize > MAX_BODY_SIZE) {
      reply.code(413).send({ error: 'Payload too large', detail: 'Request body must not exceed 1 MB.' });
      return;
    }
    chunks.push(buf);
  }
  const rawBody = Buffer.concat(chunks).toString('utf-8');
  (request as any).rawBody = rawBody;

  const { Readable } = await import('node:stream');
  return Readable.from([rawBody]);
});

// Health check (no auth required)
app.get('/health', async () => {
  return { status: 'ok', service: 'attestr', version: '1.0.0' };
});

// Register plugins and routes
let batchInterval: ReturnType<typeof setInterval> | null = null;
let anomalyInterval: ReturnType<typeof setInterval> | null = null;

async function bootstrap(): Promise<void> {
  // CORS — allow dashboard origin
  await app.register(cors, {
    origin: config.dashboardUrl || (config.nodeEnv === 'production' ? false : true),
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Tenant-Id', 'X-Timestamp', 'X-Signature'],
  });

  await registerRateLimit(app);
  await app.register(decisionRoutes);
  await app.register(evidenceRoutes);
  await app.register(anomalyRoutes);

  // Register shutdown hook before listening
  app.addHook('onClose', async () => {
    if (batchInterval) clearInterval(batchInterval);
    if (anomalyInterval) clearInterval(anomalyInterval);
  });

  try {
    await app.listen({ port: config.port, host: '0.0.0.0' });
    console.log(`\n  Attestr API running on http://localhost:${config.port}`);
    console.log(`  Health check: http://localhost:${config.port}/health`);
    console.log(`  Public key:   http://localhost:${config.port}/v1/public-key\n`);

    // Start Merkle batch processor (runs periodically)
    batchInterval = setInterval(async () => {
      try {
        const count = await processAllPendingBatches(config.merkleBatchSize);
        if (count > 0) {
          app.log.info(`Merkle batch processor: created ${count} batch(es)`);
        }
      } catch (err) {
        app.log.error(err, 'Merkle batch processor error');
      }
    }, config.merkleBatchIntervalMs);

    // Start anomaly detection processor (runs periodically)
    anomalyInterval = setInterval(async () => {
      try {
        const count = await processAllTenantAnomalies();
        if (count > 0) {
          app.log.info(`Anomaly detector: found ${count} anomaly alert(s)`);
        }
      } catch (err) {
        app.log.error(err, 'Anomaly detector error');
      }
    }, config.anomalyIntervalMs);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

bootstrap();
