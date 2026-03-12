import 'dotenv/config';

export const config = {
  port: parseInt(process.env.PORT || '3001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  databaseUrl: process.env.DATABASE_URL || '',
  ed25519PrivateKey: process.env.ED25519_PRIVATE_KEY || '',
  ed25519PublicKey: process.env.ED25519_PUBLIC_KEY || '',
  // Auth
  maxRequestAgeMs: 5 * 60 * 1000, // 5 minutes — reject older requests
  // Rate limiting defaults (per minute)
  rateLimits: {
    free: 10,
    starter: 100,
    pro: 1000,
    enterprise: 10000,
  } as Record<string, number>,
  // Monthly record limits per tier
  recordLimits: {
    free: 500,
    starter: 10_000,
    pro: 100_000,
    enterprise: Infinity,
  } as Record<string, number>,
  // Ledger
  genesisHash: '0'.repeat(64), // SHA-256 zero hash for first record in chain
  // Merkle batching
  merkleBatchSize: parseInt(process.env.MERKLE_BATCH_SIZE || '1000', 10),
  merkleBatchIntervalMs: parseInt(process.env.MERKLE_BATCH_INTERVAL_MS || '60000', 10),
  // Dashboard
  dashboardUrl: process.env.DASHBOARD_URL || 'http://localhost:3000',
  // Anomaly detection
  anomalyIntervalMs: parseInt(process.env.ANOMALY_INTERVAL_MS || '300000', 10), // 5 minutes
  anomalyBaselineHours: 24,
  anomalyCurrentWindowMinutes: 60,
  anomalyMinRecords: 50, // minimum baseline records before alerting
};
