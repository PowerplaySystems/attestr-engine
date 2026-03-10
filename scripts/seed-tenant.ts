import { randomBytes, createHash } from 'node:crypto';
import pg from 'pg';
import 'dotenv/config';

const { Pool } = pg;

async function seed() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL?.includes('supabase')
      ? { rejectUnauthorized: false }
      : undefined,
  });

  const tenantName = process.argv[2] || 'Test Tenant';

  // Generate credentials
  const apiKey = randomBytes(32).toString('hex');
  const hmacSecret = randomBytes(32).toString('hex');
  const apiKeyHash = createHash('sha256').update(apiKey).digest('hex');

  // Insert tenant
  const result = await pool.query(
    `INSERT INTO tenants (name, api_key_hash, hmac_secret, tier)
     VALUES ($1, $2, $3, $4)
     RETURNING id, name, tier, created_at`,
    [tenantName, apiKeyHash, hmacSecret, 'starter']
  );

  const tenant = result.rows[0];

  console.log('\n  ✓ Tenant created successfully.\n');
  console.log('  ┌─────────────────────────────────────────────────────────────────────┐');
  console.log(`  │  Tenant ID:    ${tenant.id}  │`);
  console.log(`  │  Name:         ${tenantName.padEnd(51)}│`);
  console.log(`  │  Tier:         ${tenant.tier.padEnd(51)}│`);
  console.log('  ├─────────────────────────────────────────────────────────────────────┤');
  console.log(`  │  API Key:      ${apiKey}  │`);
  console.log(`  │  HMAC Secret:  ${hmacSecret}  │`);
  console.log('  └─────────────────────────────────────────────────────────────────────┘');
  console.log('\n  ⚠  Save these credentials now. The HMAC secret cannot be recovered.\n');

  console.log('  Example curl:\n');
  console.log(`  curl -X POST http://localhost:3000/v1/decisions \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -H "X-Tenant-Id: ${tenant.id}" \\`);
  console.log(`    -H "X-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.000Z)" \\`);
  console.log(`    -H "X-Signature: <computed HMAC>" \\`);
  console.log(`    -d '{"event_id":"test_001","decision":"BLOCK","reason_codes":["test"],"decided_at":"2026-03-08T14:32:01Z"}'\n`);

  await pool.end();
}

seed();
