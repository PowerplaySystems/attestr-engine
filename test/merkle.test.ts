import { describe, it, expect } from 'vitest';
import { buildMerkleTree, extractProof, verifyProof } from '../src/services/merkle.ts';
import { sha256Hash, hashPair } from '../src/services/crypto.ts';

describe('buildMerkleTree', () => {
  it('builds a tree with a single leaf', () => {
    const leaf = sha256Hash('record_1');
    const tree = buildMerkleTree([leaf]);

    expect(tree.version).toBe(1);
    expect(tree.size).toBe(1);
    expect(tree.leaf_hashes).toEqual([leaf]);
    expect(tree.root_hash).toBe(leaf);
    // Single leaf: only one node at level 0
    expect(tree.nodes).toHaveLength(1);
    expect(tree.nodes[0]).toEqual({ level: 0, index: 0, hash: leaf });
  });

  it('builds a tree with two leaves', () => {
    const a = sha256Hash('record_a');
    const b = sha256Hash('record_b');
    const tree = buildMerkleTree([a, b]);

    expect(tree.size).toBe(2);
    expect(tree.root_hash).toBe(hashPair(a, b));
    // 2 leaf nodes + 1 root = 3 nodes
    expect(tree.nodes).toHaveLength(3);
  });

  it('builds a tree with four leaves (power of 2)', () => {
    const leaves = [1, 2, 3, 4].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);

    expect(tree.size).toBe(4);
    // Level 0: 4 leaves, Level 1: 2 nodes, Level 2: 1 root = 7
    expect(tree.nodes).toHaveLength(7);

    // Verify root manually
    const h01 = hashPair(leaves[0], leaves[1]);
    const h23 = hashPair(leaves[2], leaves[3]);
    const expectedRoot = hashPair(h01, h23);
    expect(tree.root_hash).toBe(expectedRoot);
  });

  it('builds a tree with odd number of leaves (duplicates last)', () => {
    const leaves = [1, 2, 3].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);

    expect(tree.size).toBe(3);

    // With 3 leaves, leaf 3 gets duplicated:
    // Level 0: [L0, L1, L2, L2]
    // Level 1: [hash(L0,L1), hash(L2,L2)]
    // Level 2: root
    const h01 = hashPair(leaves[0], leaves[1]);
    const h22 = hashPair(leaves[2], leaves[2]);
    const expectedRoot = hashPair(h01, h22);
    expect(tree.root_hash).toBe(expectedRoot);
  });

  it('builds a tree with 7 leaves', () => {
    const leaves = Array.from({ length: 7 }, (_, i) => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);

    expect(tree.size).toBe(7);
    // Root should be deterministic
    expect(tree.root_hash).toMatch(/^sha256:/);
  });

  it('throws for empty input', () => {
    expect(() => buildMerkleTree([])).toThrow('Cannot build Merkle tree with zero leaves');
  });

  it('is deterministic — same input always gives same tree', () => {
    const leaves = [1, 2, 3, 4, 5].map(i => sha256Hash(`record_${i}`));
    const tree1 = buildMerkleTree(leaves);
    const tree2 = buildMerkleTree(leaves);

    expect(tree1.root_hash).toBe(tree2.root_hash);
    expect(tree1.nodes).toEqual(tree2.nodes);
  });
});

describe('extractProof', () => {
  it('extracts proof for each leaf in a 4-leaf tree', () => {
    const leaves = [1, 2, 3, 4].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);

    for (let i = 0; i < 4; i++) {
      const proof = extractProof(tree, i);
      expect(proof.leaf_index).toBe(i);
      expect(proof.leaf_hash).toBe(leaves[i]);
      expect(proof.root_hash).toBe(tree.root_hash);
      // 4-leaf tree has 2 levels of siblings
      expect(proof.siblings).toHaveLength(2);
    }
  });

  it('proof for index 0 has right sibling at level 0', () => {
    const leaves = [1, 2, 3, 4].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);
    const proof = extractProof(tree, 0);

    // At level 0, index 0 is left child → sibling (index 1) is on the right
    expect(proof.siblings[0].direction).toBe('right');
    expect(proof.siblings[0].hash).toBe(leaves[1]);
  });

  it('proof for index 1 has left sibling at level 0', () => {
    const leaves = [1, 2, 3, 4].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);
    const proof = extractProof(tree, 1);

    // At level 0, index 1 is right child → sibling (index 0) is on the left
    expect(proof.siblings[0].direction).toBe('left');
    expect(proof.siblings[0].hash).toBe(leaves[0]);
  });

  it('throws for out-of-range index', () => {
    const tree = buildMerkleTree([sha256Hash('a')]);
    expect(() => extractProof(tree, 1)).toThrow('out of range');
    expect(() => extractProof(tree, -1)).toThrow('out of range');
  });

  it('handles single-leaf tree', () => {
    const leaf = sha256Hash('only');
    const tree = buildMerkleTree([leaf]);
    const proof = extractProof(tree, 0);

    expect(proof.leaf_hash).toBe(leaf);
    expect(proof.siblings).toHaveLength(0);
    expect(proof.root_hash).toBe(leaf);
  });
});

describe('verifyProof', () => {
  it('verifies a valid proof for all positions in a 4-leaf tree', () => {
    const leaves = [1, 2, 3, 4].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);

    for (let i = 0; i < 4; i++) {
      const proof = extractProof(tree, i);
      expect(verifyProof(leaves[i], proof)).toBe(true);
    }
  });

  it('rejects a tampered leaf hash', () => {
    const leaves = [1, 2, 3, 4].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);
    const proof = extractProof(tree, 0);

    const tamperedHash = sha256Hash('tampered');
    expect(verifyProof(tamperedHash, proof)).toBe(false);
  });

  it('rejects a proof with tampered sibling', () => {
    const leaves = [1, 2, 3, 4].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);
    const proof = extractProof(tree, 0);

    // Tamper with first sibling
    const tampered = { ...proof, siblings: [...proof.siblings] };
    tampered.siblings[0] = { ...tampered.siblings[0], hash: sha256Hash('tampered') };
    expect(verifyProof(leaves[0], tampered)).toBe(false);
  });

  it('verifies with odd-count trees', () => {
    const leaves = [1, 2, 3, 5, 7].map(i => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);

    for (let i = 0; i < leaves.length; i++) {
      const proof = extractProof(tree, i);
      expect(verifyProof(leaves[i], proof)).toBe(true);
    }
  });

  it('verifies with large tree (100 leaves)', () => {
    const leaves = Array.from({ length: 100 }, (_, i) => sha256Hash(`record_${i}`));
    const tree = buildMerkleTree(leaves);

    // Check first, middle, and last
    for (const idx of [0, 49, 99]) {
      const proof = extractProof(tree, idx);
      expect(verifyProof(leaves[idx], proof)).toBe(true);
    }
  });
});

describe('hashPair', () => {
  it('is deterministic', () => {
    const a = sha256Hash('foo');
    const b = sha256Hash('bar');
    expect(hashPair(a, b)).toBe(hashPair(a, b));
  });

  it('is order-dependent', () => {
    const a = sha256Hash('foo');
    const b = sha256Hash('bar');
    expect(hashPair(a, b)).not.toBe(hashPair(b, a));
  });

  it('returns sha256-prefixed hash', () => {
    const a = sha256Hash('x');
    const b = sha256Hash('y');
    expect(hashPair(a, b)).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});
