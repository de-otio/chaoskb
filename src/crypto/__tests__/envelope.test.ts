import { describe, it, expect } from 'vitest';
import { encryptPayload, decryptEnvelope } from '../envelope.js';
import { deriveKeySet } from '../hkdf.js';
import type {
  CanaryPayload,
  ChunkPayload,
  DerivedKeySet,
  Envelope,
  SourcePayload,
} from '../types.js';

function createTestKeySet(): DerivedKeySet {
  const masterKey = new Uint8Array(32).fill(0x42);
  return deriveKeySet(masterKey);
}

function disposeKeySet(ks: DerivedKeySet): void {
  ks.contentKey.dispose();
  ks.metadataKey.dispose();
  ks.embeddingKey.dispose();
  ks.commitKey.dispose();
}

describe('Envelope v1', () => {
  describe('canary payload round-trip', () => {
    it('should encrypt and decrypt a canary payload', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };

      const { envelope } = encryptPayload(payload, keys);

      expect(envelope.v).toBe(1);
      expect(envelope.id).toMatch(/^b_/);
      expect(envelope.enc.alg).toBe('XChaCha20-Poly1305');
      expect(envelope.enc.kid).toBe('CEK');
      expect(typeof envelope.enc.ct).toBe('string');
      expect(typeof envelope.enc['ct.len']).toBe('number');
      expect(typeof envelope.enc.commit).toBe('string');

      const result = decryptEnvelope(envelope, keys);
      expect(result.payload).toEqual(payload);

      disposeKeySet(keys);
    });
  });

  describe('source payload round-trip', () => {
    it('should encrypt and decrypt a source payload', () => {
      const keys = createTestKeySet();
      const payload: SourcePayload = {
        type: 'source',
        url: 'https://example.com/article',
        title: 'Test Article',
        tags: ['rust', 'programming'],
        chunkCount: 2,
        chunkIds: ['b_chunk1', 'b_chunk2'],
      };

      const { envelope } = encryptPayload(payload, keys, 'MEK');

      expect(envelope.enc.kid).toBe('MEK');

      const result = decryptEnvelope(envelope, keys);
      expect(result.payload.type).toBe('source');
      expect((result.payload as SourcePayload).url).toBe('https://example.com/article');
      expect((result.payload as SourcePayload).title).toBe('Test Article');
      expect((result.payload as SourcePayload).tags).toEqual(['rust', 'programming']);
      expect((result.payload as SourcePayload).chunkCount).toBe(2);

      disposeKeySet(keys);
    });
  });

  describe('chunk payload round-trip', () => {
    it('should encrypt and decrypt a chunk payload', () => {
      const keys = createTestKeySet();
      const payload: ChunkPayload = {
        type: 'chunk',
        sourceId: 'b_source123',
        index: 0,
        model: 'snowflake-arctic-embed-s@384',
        content: 'In Rust, each value has a single owner...',
        tokenCount: 487,
        embedding: [0.0234, -0.0891, 0.0412],
      };

      const { envelope } = encryptPayload(payload, keys);

      const result = decryptEnvelope(envelope, keys);
      expect(result.payload.type).toBe('chunk');
      const chunk = result.payload as ChunkPayload;
      expect(chunk.sourceId).toBe('b_source123');
      expect(chunk.content).toBe('In Rust, each value has a single owner...');
      expect(chunk.embedding).toEqual([0.0234, -0.0891, 0.0412]);

      disposeKeySet(keys);
    });
  });

  describe('envelope structure', () => {
    it('should include ct.len matching decoded ciphertext length', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };

      const { envelope } = encryptPayload(payload, keys);

      const rawCt = Buffer.from(envelope.enc.ct, 'base64');
      expect(rawCt.length).toBe(envelope.enc['ct.len']);

      disposeKeySet(keys);
    });

    it('should produce valid ISO 8601 timestamp', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };

      const { envelope } = encryptPayload(payload, keys);

      // Should be parseable as a date
      const date = new Date(envelope.ts);
      expect(date.getTime()).not.toBeNaN();

      disposeKeySet(keys);
    });

    it('should return bytes as serialized JSON', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };

      const { envelope, bytes } = encryptPayload(payload, keys);

      const decoded = JSON.parse(new TextDecoder().decode(bytes));
      expect(decoded.v).toBe(envelope.v);
      expect(decoded.id).toBe(envelope.id);
      expect(decoded.enc.ct).toBe(envelope.enc.ct);

      disposeKeySet(keys);
    });
  });

  describe('version check', () => {
    it('should reject unsupported envelope versions', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      const badEnvelope = { ...envelope, v: 2 as any };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow(/unsupported envelope version/i);

      disposeKeySet(keys);
    });
  });

  describe('ct.len validation', () => {
    it('should reject envelopes with mismatched ct.len', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      const badEnvelope: Envelope = {
        ...envelope,
        enc: { ...envelope.enc, 'ct.len': envelope.enc['ct.len'] + 1 },
      };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow(/ciphertext length mismatch/i);

      disposeKeySet(keys);
    });
  });

  describe('AAD mismatch rejection', () => {
    it('should fail if blob ID is changed', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      // Change the blob ID — this should cause both AAD mismatch and commitment failure
      const badEnvelope: Envelope = { ...envelope, id: 'b_tampered_id' };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow();

      disposeKeySet(keys);
    });

    it('should fail if kid is changed', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      // Change kid — commitment uses the original rawCt but AAD changes
      const badEnvelope: Envelope = {
        ...envelope,
        enc: { ...envelope.enc, kid: 'MEK' as any },
      };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow();

      disposeKeySet(keys);
    });
  });

  describe('commitment mismatch rejection', () => {
    it('should fail if commitment is wrong', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      // Tamper with commitment
      const fakeCommit = Buffer.alloc(32, 0xff).toString('base64');
      const badEnvelope: Envelope = {
        ...envelope,
        enc: { ...envelope.enc, commit: fakeCommit },
      };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow(/authentication failed/i);

      disposeKeySet(keys);
    });
  });

  describe('wrong keys', () => {
    it('should fail to decrypt with different master key', () => {
      const keys1 = createTestKeySet();
      const masterKey2 = new Uint8Array(32).fill(0x99);
      const keys2 = deriveKeySet(masterKey2);

      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys1);

      // Commitment verification should fail because commit key is different
      expect(() => decryptEnvelope(envelope, keys2)).toThrow();

      disposeKeySet(keys1);
      disposeKeySet(keys2);
    });
  });

  describe('default kid', () => {
    it('should default to CEK', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };

      const { envelope } = encryptPayload(payload, keys);
      expect(envelope.enc.kid).toBe('CEK');

      disposeKeySet(keys);
    });
  });
});
