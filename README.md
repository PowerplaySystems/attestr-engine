# Attestr Engine

Cryptographically signed, append-only fraud decision ledger. You make the decision, we make it provable.

Attestr captures every fraud decision your system makes &mdash; BLOCK, ALLOW, REVIEW &mdash; and seals it into an immutable, hash-chained, digitally signed ledger. When an examiner asks "why did you block this payment?", you hand them a tamper-proof evidence packet instead of a database query.

## What It Does

```
Your fraud engine              Attestr                        Examiner
      |                           |                              |
      |-- POST /v1/decisions ---->|                              |
      |                           |-- hash-chain (SHA-256)       |
      |                           |-- sign (Ed25519)             |
      |                           |-- store (append-only)        |
      |<-- { record_hash, sig } --|                              |
      |                           |                              |
      |                     ... months later ...                 |
      |                           |                              |
      |                           |<-- GET /v1/.../evidence -----|
      |                           |-- verify integrity           |
      |                           |-- generate PDF               |
      |                           |-- evidence packet ---------->|
```

## Cryptographic Guarantees

| Layer | Method | What It Proves |
|-------|--------|----------------|
| Hash Chain | `H(n) = SHA-256(H(n-1) + data)` | No record was inserted, deleted, or reordered |
| Digital Signatures | `sig = Ed25519(privkey, hash)` | Record was created by the platform, not forged |
| Merkle Proofs | `root = H(H(a,b), H(c,d))` | Record belongs to a batch without revealing other records |
| HMAC Authentication | `HMAC-SHA256(method + path + ts + body)` | Request came from an authorized tenant |
| Input Hash | `SHA-256(raw_input)` | Decision can be traced back to the original transaction data |

## Anomaly Detection

The engine includes a background anomaly detection processor that continuously analyzes your decision stream:

- **Score Drift** &mdash; z-score analysis detects when score distributions shift
- **Block Rate** &mdash; proportion tests flag unusual decision ratio changes
- **Recording Gaps** &mdash; velocity monitoring catches ingestion failures
- **Reason Code Shifts** &mdash; cosine similarity detects pattern changes
- **Model Transitions** &mdash; automatic detection of new model versions
- **Velocity Spikes** &mdash; flags abnormal ingestion rates

All detection uses deterministic statistical methods. No external AI APIs. No data leaves your infrastructure.

## Quick Start

```bash
# Clone
git clone https://github.com/PowerplaySystems/attestr-engine.git
cd attestr-engine

# Install
npm install

# Generate Ed25519 signing keys
npm run generate-keys

# Configure
# Edit .env with your PostgreSQL connection string

# Run migrations
npm run migrate

# Create a test tenant
npm run seed "My Company"
# Save the Tenant ID and HMAC Secret printed to console

# Start the server
npm run dev
```

## API Endpoints

### Decisions

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/decisions` | Ingest a fraud decision |
| `GET` | `/v1/decisions/:event_id` | Get a single decision record |
| `GET` | `/v1/decisions` | List decisions (with filters + cursor pagination) |

### Verification & Evidence

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/decisions/:event_id/verify` | Verify record integrity (hash, chain, signature, Merkle) |
| `GET` | `/v1/decisions/:event_id/evidence` | Generate evidence packet (JSON) |
| `GET` | `/v1/decisions/:event_id/evidence?format=pdf` | Generate evidence packet (PDF) |
| `GET` | `/v1/public-key` | Get platform Ed25519 public key for offline verification |

### Anomalies

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/anomalies` | List anomaly alerts |
| `GET` | `/v1/anomalies/:id` | Get anomaly alert detail |
| `POST` | `/v1/anomalies/:id/acknowledge` | Acknowledge an alert |

## Authentication

Every request (except `/health` and `/v1/public-key`) requires HMAC-SHA256 authentication:

```
Headers:
  X-Tenant-Id:  <your-tenant-uuid>
  X-Timestamp:  <ISO-8601 datetime, must be within 5 minutes>
  X-Signature:  <HMAC-SHA256 hex digest>

Signature = HMAC-SHA256(
  key: tenant_hmac_secret,
  message: METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + BODY
)
```

### Example: Ingest a Decision

```bash
TENANT_ID="your-tenant-id"
HMAC_SECRET="your-hmac-secret"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
BODY='{"event_id":"txn_001","decision":"BLOCK","score":0.92,"reason_codes":["velocity_spike","new_device"],"decided_at":"2026-03-10T14:30:00Z"}'

SIGNATURE=$(echo -n "POST
/v1/decisions
${TIMESTAMP}
${BODY}" | openssl dgst -sha256 -hmac "${HMAC_SECRET}" -hex | awk '{print $2}')

curl -X POST http://localhost:3001/v1/decisions \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: ${TENANT_ID}" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "X-Signature: ${SIGNATURE}" \
  -d "${BODY}"
```

### Response

```json
{
  "ledger_entry_id": "a1b2c3d4-...",
  "sequence_number": 42,
  "record_hash": "sha256:6ab29f...",
  "previous_hash": "sha256:f8c3e1...",
  "platform_signature": "ed25519:D0jmEv...",
  "ingested_at": "2026-03-10T14:30:01.234Z"
}
```

## Decision Payload

```typescript
{
  event_id: string;          // Unique transaction/event ID (idempotent)
  decision: string;          // "BLOCK" | "ALLOW" | "REVIEW" | custom
  score?: number;            // 0.0 - 1.0 confidence score
  reason_codes: string[];    // Why this decision was made
  feature_contributions?: {  // Per-feature importance weights
    [feature: string]: number;
  };
  model_version?: string;    // "v2.1.0"
  policy_version?: string;   // "policy_2026Q1"
  decided_at: string;        // ISO 8601 timestamp of the decision
  metadata?: object;         // Arbitrary JSON (customer tier, channel, etc.)
  input_hash?: string;       // SHA-256 of raw input for dual-attestation
}
```

## Dual Attestation (Input Hash)

For the strongest audit trail, clients can hash the raw transaction input before sending it:

```
input_hash = SHA-256(raw_transaction_json)
```

This creates **dual attestation**: the decision is signed by Attestr, and the input hash can be independently verified against the source system. If a record has an `input_hash`, it gets "dual attestation" status. Without it, "single attestation" &mdash; both are valid, dual is stronger.

## Project Structure

```
src/
  index.ts                 # Fastify entry point + background processors
  config.ts                # Environment configuration
  types/index.ts           # TypeScript interfaces
  db/
    client.ts              # PostgreSQL connection pool
    queries.ts             # All database queries
  middleware/
    auth.ts                # HMAC-SHA256 request authentication
    rate-limit.ts          # Per-tenant rate limiting
  routes/
    decisions.ts           # Decision CRUD endpoints
    evidence.ts            # Verification + evidence generation
    anomalies.ts           # Anomaly alert endpoints
  services/
    crypto.ts              # SHA-256, Ed25519, HMAC utilities
    ledger.ts              # Decision ingestion + hash chaining
    merkle.ts              # Merkle tree building + batch processing
    evidence.ts            # Integrity verification + PDF generation
    anomaly.ts             # Statistical anomaly detection engine
sql/
  001-009                  # Database migrations (run in order)
scripts/
  generate-keys.ts         # Generate Ed25519 keypair
  migrate.ts               # Run all SQL migrations
  seed-tenant.ts           # Create a test tenant with credentials
test/
  crypto.test.ts           # 16 tests: hashing, signing, verification
  merkle.test.ts           # 20 tests: tree building, proofs, verification
  evidence.test.ts         # 7 tests: integrity checks, normalization
  e2e.ts                   # 11 tests: full API integration
```

## Running Tests

```bash
# Unit tests (43 tests)
npm test

# Watch mode
npm run test:watch

# E2E tests (requires running server)
npm run dev &
npx tsx test/e2e.ts
```

## Dashboard

The companion [Attestr Dashboard](./dashboard) provides a web UI for browsing your ledger, investigating decisions, and sharing access with compliance teams.

### Features

- **Overview** &mdash; Key metrics, chain health status, decision distribution, and recent activity at a glance
- **Getting Started** &mdash; In-app API integration guide with code examples (curl, Node.js, Python) pre-filled with your credentials
- **Event Search** &mdash; Filter and investigate decision records with cursor-based pagination
- **Evidence Export** &mdash; Generate cryptographic evidence packets (JSON or PDF) for any decision
- **Ledger Health** &mdash; Real-time hash chain verification and Merkle batch status
- **Anomaly Alerts** &mdash; Monitor score drift, block rate spikes, recording gaps, and other statistical anomalies

### Team Access &amp; Auditor Invites

Admins can invite compliance officers or auditors via email from **Settings &rarr; Auditor Access**. Invited users get read-only access to events, evidence, ledger health, and anomaly alerts &mdash; they cannot modify settings, manage API credentials, or invite others.

| Role | Can View | Can Modify Settings | Can Invite |
|------|----------|-------------------|------------|
| Admin | Everything | Yes | Yes |
| Auditor | Events, Evidence, Health, Anomalies | No | No |

### Running the Dashboard

```bash
cd dashboard
npm install
cp .env.example .env.local  # Configure Supabase + database credentials
npm run dev                  # Starts on http://localhost:3000
```

## Stack

- **Runtime**: Node.js + TypeScript
- **Framework**: Fastify 5
- **Database**: PostgreSQL
- **Cryptography**: tweetnacl (Ed25519), Node.js crypto (SHA-256, HMAC)
- **PDF Generation**: PDFKit
- **Tests**: Vitest
- **Dashboard**: Next.js 15, Supabase Auth, Tailwind CSS

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | &mdash; | PostgreSQL connection string |
| `ED25519_PRIVATE_KEY` | &mdash; | Base64-encoded Ed25519 private key |
| `ED25519_PUBLIC_KEY` | &mdash; | Base64-encoded Ed25519 public key |
| `PORT` | `3001` | Server port |
| `NODE_ENV` | `development` | Environment |
| `DASHBOARD_URL` | `http://localhost:3000` | CORS origin for dashboard |
| `MERKLE_BATCH_SIZE` | `1000` | Records per Merkle batch |
| `MERKLE_BATCH_INTERVAL_MS` | `60000` | Merkle processor interval |
| `ANOMALY_INTERVAL_MS` | `300000` | Anomaly detection interval (5 min) |

## License

MIT
