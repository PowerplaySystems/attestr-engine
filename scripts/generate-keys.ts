import { generateEd25519Keypair } from '../src/services/crypto.ts';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const envPath = join(import.meta.dirname, '..', '.env');

function main() {
  const keypair = generateEd25519Keypair();

  console.log('\nGenerated Ed25519 keypair:\n');
  console.log(`  Public Key:  ${keypair.publicKey}`);
  console.log(`  Private Key: ${keypair.privateKey}`);

  // Update .env file
  if (existsSync(envPath)) {
    let envContent = readFileSync(envPath, 'utf-8');
    envContent = envContent.replace(/^ED25519_PRIVATE_KEY=.*$/m, `ED25519_PRIVATE_KEY=${keypair.privateKey}`);
    envContent = envContent.replace(/^ED25519_PUBLIC_KEY=.*$/m, `ED25519_PUBLIC_KEY=${keypair.publicKey}`);
    writeFileSync(envPath, envContent);
    console.log('\n  ✓ Updated .env file with new keys.');
  } else {
    // Create .env from .env.example and populate keys
    const examplePath = join(import.meta.dirname, '..', '.env.example');
    let envContent = existsSync(examplePath)
      ? readFileSync(examplePath, 'utf-8')
      : 'DATABASE_URL=\nED25519_PRIVATE_KEY=\nED25519_PUBLIC_KEY=\nPORT=3000\nNODE_ENV=development\n';
    envContent = envContent.replace(/^ED25519_PRIVATE_KEY=.*$/m, `ED25519_PRIVATE_KEY=${keypair.privateKey}`);
    envContent = envContent.replace(/^ED25519_PUBLIC_KEY=.*$/m, `ED25519_PUBLIC_KEY=${keypair.publicKey}`);
    writeFileSync(envPath, envContent);
    console.log('\n  ✓ Created .env file with new keys.');
  }

  console.log('\n  IMPORTANT: Keep the private key secret. The public key can be shared with tenants for offline verification.\n');
}

main();
