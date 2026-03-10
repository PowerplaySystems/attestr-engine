import { sha256Hash, hashPair, signRecord } from './crypto.ts';
import { config } from '../config.ts';
import { getLastMerkleBatch, getEntriesInRange, insertMerkleBatch } from '../db/queries.ts';
import { getAllActiveTenantIds } from '../db/queries.ts';
import type { MerkleTree, MerkleNode, MerkleProofPath, MerkleProofSibling } from '../types/index.ts';

// === Build a binary Merkle tree from an array of leaf hashes ===

export function buildMerkleTree(leafHashes: string[]): MerkleTree {
  if (leafHashes.length === 0) {
    throw new Error('Cannot build Merkle tree with zero leaves');
  }

  const nodes: MerkleNode[] = [];

  // Level 0: leaves
  let currentLevel = leafHashes.map((hash, index) => {
    const node: MerkleNode = { level: 0, index, hash };
    nodes.push(node);
    return hash;
  });

  let level = 0;
  while (currentLevel.length > 1) {
    // If odd count, duplicate last
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }

    const nextLevel: string[] = [];
    level++;

    for (let i = 0; i < currentLevel.length; i += 2) {
      const combined = hashPair(currentLevel[i], currentLevel[i + 1]);
      const node: MerkleNode = { level, index: i / 2, hash: combined };
      nodes.push(node);
      nextLevel.push(combined);
    }

    currentLevel = nextLevel;
  }

  return {
    version: 1,
    size: leafHashes.length,
    leaf_hashes: leafHashes,
    nodes,
    root_hash: currentLevel[0],
  };
}

// === Extract a proof path from a built tree ===

export function extractProof(tree: MerkleTree, leafIndex: number): MerkleProofPath {
  if (leafIndex < 0 || leafIndex >= tree.size) {
    throw new Error(`Leaf index ${leafIndex} out of range [0, ${tree.size - 1}]`);
  }

  const siblings: MerkleProofSibling[] = [];

  // We need to walk up the tree level by level, collecting the sibling at each level
  // First, rebuild the level structure from nodes
  const levels: string[][] = [];
  const maxLevel = tree.nodes[tree.nodes.length - 1].level;

  for (let l = 0; l <= maxLevel; l++) {
    const levelNodes = tree.nodes
      .filter(n => n.level === l)
      .sort((a, b) => a.index - b.index)
      .map(n => n.hash);
    levels.push(levelNodes);
  }

  let currentIndex = leafIndex;

  for (let l = 0; l < levels.length - 1; l++) {
    const levelHashes = levels[l];

    // If odd count, duplicate last (same as tree building logic)
    if (levelHashes.length % 2 !== 0) {
      levelHashes.push(levelHashes[levelHashes.length - 1]);
    }

    if (currentIndex % 2 === 0) {
      // Current is left child, sibling is on the right
      siblings.push({
        hash: levelHashes[currentIndex + 1],
        direction: 'right',
      });
    } else {
      // Current is right child, sibling is on the left
      siblings.push({
        hash: levelHashes[currentIndex - 1],
        direction: 'left',
      });
    }

    // Move to parent index
    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    leaf_index: leafIndex,
    leaf_hash: tree.leaf_hashes[leafIndex],
    siblings,
    root_hash: tree.root_hash,
  };
}

// === Verify a Merkle proof path ===

export function verifyProof(leafHash: string, proof: MerkleProofPath): boolean {
  let current = leafHash;

  for (const sibling of proof.siblings) {
    if (sibling.direction === 'right') {
      // Sibling is on the right → current is left child
      current = hashPair(current, sibling.hash);
    } else {
      // Sibling is on the left → current is right child
      current = hashPair(sibling.hash, current);
    }
  }

  return current === proof.root_hash;
}

// === Process pending Merkle batches for all tenants ===

export async function processAllPendingBatches(batchSize: number): Promise<number> {
  const tenantIds = await getAllActiveTenantIds();
  let totalBatches = 0;

  for (const tenantId of tenantIds) {
    totalBatches += await processPendingBatches(tenantId, batchSize);
  }

  return totalBatches;
}

// === Process pending batches for a single tenant ===

export async function processPendingBatches(tenantId: string, batchSize: number): Promise<number> {
  let batchesCreated = 0;

  // Keep processing as long as there are enough un-batched records
  while (true) {
    // Find where the last batch ended
    const lastBatch = await getLastMerkleBatch(tenantId);
    const startSequence = lastBatch ? lastBatch.end_sequence + 1 : 1;
    const nextBatchNumber = lastBatch ? lastBatch.batch_number + 1 : 1;

    // Fetch entries for this batch
    const endSequence = startSequence + batchSize - 1;
    const entries = await getEntriesInRange(tenantId, startSequence, endSequence);

    // Only create a batch if we have at least batchSize records
    if (entries.length < batchSize) {
      break;
    }

    // Build Merkle tree from record hashes
    const leafHashes = entries.map(e => e.record_hash);
    const tree = buildMerkleTree(leafHashes);

    // Sign the root
    const rootSignature = signRecord(tree.root_hash, config.ed25519PrivateKey);

    // Store batch
    await insertMerkleBatch({
      tenant_id: tenantId,
      batch_number: nextBatchNumber,
      start_sequence: startSequence,
      end_sequence: startSequence + entries.length - 1,
      root_hash: tree.root_hash,
      root_signature: rootSignature,
      tree_data: tree,
    });

    batchesCreated++;
  }

  return batchesCreated;
}
