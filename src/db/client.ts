import pg from 'pg';
import { config } from '../config.ts';

// Fix PostgreSQL type parsing: BIGINT and NUMERIC come back as strings by default.
// This causes bugs like `"1110" + 1 = "11101"` (string concatenation instead of math).
// OID 20 = INT8 (BIGINT), OID 1700 = NUMERIC
pg.types.setTypeParser(20, (val: string) => parseInt(val, 10));
pg.types.setTypeParser(1700, (val: string) => parseFloat(val));

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.databaseUrl,
  ssl: config.nodeEnv === 'production' || config.databaseUrl.includes('supabase')
    ? { rejectUnauthorized: true }
    : undefined,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err);
});
