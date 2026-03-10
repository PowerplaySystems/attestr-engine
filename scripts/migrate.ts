import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import 'dotenv/config';

const { Pool } = pg;

async function migrate() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL?.includes('supabase')
      ? { rejectUnauthorized: false }
      : undefined,
  });

  const sqlDir = join(import.meta.dirname, '..', 'sql');
  const files = readdirSync(sqlDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  console.log(`Running ${files.length} migrations...\n`);

  for (const file of files) {
    const sql = readFileSync(join(sqlDir, file), 'utf-8');
    console.log(`  Executing: ${file}`);
    try {
      await pool.query(sql);
      console.log(`  ✓ ${file} — done`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  ✗ ${file} — FAILED: ${message}`);
      process.exit(1);
    }
  }

  console.log('\nAll migrations completed successfully.');
  await pool.end();
}

migrate();
