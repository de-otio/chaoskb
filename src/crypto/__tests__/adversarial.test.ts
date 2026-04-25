import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { aeadEncrypt, aeadDecrypt } from '../aead.js';
import { encryptPayload, decryptEnvelope } from '../envelope.js';
import { deriveKeySet } from '../hkdf.js';
import { computeCommitment, verifyCommitment } from '../commitment.js';
import type { CanaryPayload, DerivedKeySet, Envelope } from '../types.js';

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

describe('Adversarial tests', () => {
  describe('corrupted ciphertext', () => {
    it('should reject ciphertext with flipped bits', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      // Decode ct, flip a bit in the ciphertext portion (after nonce)
      const rawCt = Buffer.from(envelope.enc.ct, 'base64');
      rawCt[30] ^= 0x01; // flip a bit in the ciphertext area

      const badEnvelope: Envelope = {
        ...envelope,
        enc: {
          ...envelope.enc,
          ct: rawCt.toString('base64'),
        },
      };

      // Commitment will fail because rawCt changed
      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow();

      disposeKeySet(keys);
    });

    it('should reject ciphertext with appended bytes', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      const rawCt = Buffer.from(envelope.enc.ct, 'base64');
      const extended = Buffer.concat([rawCt, Buffer.from([0xff])]);

      const badEnvelope: Envelope = {
        ...envelope,
        enc: {
          ...envelope.enc,
          ct: extended.toString('base64'),
          'ct.len': extended.length,
        },
      };

      // Commitment will fail
      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow();

      disposeKeySet(keys);
    });
  });

  describe('truncated blobs', () => {
    it('should reject ciphertext shorter than minimum', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      // Truncate to just 10 bytes (less than nonce + tag + 1 = 41)
      const truncated = Buffer.alloc(10);

      const badEnvelope: Envelope = {
        ...envelope,
        enc: {
          ...envelope.enc,
          ct: truncated.toString('base64'),
          'ct.len': truncated.length,
        },
      };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow(/truncated ciphertext/i);

      disposeKeySet(keys);
    });

    it('should reject ct.len mismatch (truncated download)', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      // Keep original ct but increase ct.len
      const badEnvelope: Envelope = {
        ...envelope,
        enc: {
          ...envelope.enc,
          'ct.len': envelope.enc['ct.len'] + 100,
        },
      };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow(/ciphertext length mismatch/i);

      disposeKeySet(keys);
    });
  });

  describe('wrong keys', () => {
    it('should reject decryption with entirely different key set', () => {
      const keys1 = createTestKeySet();
      const keys2 = deriveKeySet(randomBytes(32));

      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys1);

      expect(() => decryptEnvelope(envelope, keys2)).toThrow();

      disposeKeySet(keys1);
      disposeKeySet(keys2);
    });
  });

  describe('AAD mismatch', () => {
    it('should fail when algorithm field is changed', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      const badEnvelope: Envelope = {
        ...envelope,
        enc: {
          ...envelope.enc,
          alg: 'AES-256-GCM', // changed algorithm
        },
      };

      // Commitment may or may not fail depending on order; either way decryption fails
      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow();

      disposeKeySet(keys);
    });

    it('should fail when version field is changed', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      // v=2 should be rejected at version check
      const badEnvelope = { ...envelope, v: 2 as any };
      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow(/unsupported envelope version/i);

      disposeKeySet(keys);
    });
  });

  describe('key commitment failure', () => {
    it('should reject blob substitution (swapped ciphertext between IDs)', () => {
      const keys = createTestKeySet();
      const payload1: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const payload2: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };

      const { envelope: env1 } = encryptPayload(payload1, keys);
      const { envelope: env2 } = encryptPayload(payload2, keys);

      // Swap ciphertext from env2 into env1's ID
      const swapped: Envelope = {
        ...env1, // keeps env1's ID
        enc: {
          ...env2.enc, // uses env2's ciphertext and commitment
        },
      };

      // Commitment binds to blob ID, so this should fail
      expect(() => decryptEnvelope(swapped, keys)).toThrow(/authentication failed/i);

      disposeKeySet(keys);
    });

    it('should reject if commitment is zeroed out', () => {
      const keys = createTestKeySet();
      const payload: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
      const { envelope } = encryptPayload(payload, keys);

      const badEnvelope: Envelope = {
        ...envelope,
        enc: {
          ...envelope.enc,
          commit: Buffer.alloc(32).toString('base64'),
        },
      };

      expect(() => decryptEnvelope(badEnvelope, keys)).toThrow(/authentication failed/i);

      disposeKeySet(keys);
    });
  });

  describe('nonce size validation', () => {
    it('should reject nonces that are too short', () => {
      const key = randomBytes(32);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);

      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);

      // Try to decrypt with a truncated nonce
      const shortNonce = nonce.slice(0, 12);
      expect(() => aeadDecrypt(key, shortNonce, ciphertext, tag, aad)).toThrow(
        /nonce must be 24 bytes/i,
      );
    });

    it('should reject nonces that are too long', () => {
      const key = randomBytes(32);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);

      const { ciphertext, tag } = aeadEncrypt(key, plaintext, aad);

      const longNonce = new Uint8Array(48);
      expect(() => aeadDecrypt(key, longNonce, ciphertext, tag, aad)).toThrow(
        /nonce must be 24 bytes/i,
      );
    });
  });

  describe('zero-length input', () => {
    it('should handle encryption of empty plaintext via AEAD', () => {
      const key = randomBytes(32);
      const aad = new Uint8Array(0);
      const empty = new Uint8Array(0);

      const { nonce, ciphertext, tag } = aeadEncrypt(key, empty, aad);
      expect(ciphertext.length).toBe(0);
      expect(tag.length).toBe(16);

      const decrypted = aeadDecrypt(key, nonce, ciphertext, tag, aad);
      expect(decrypted.length).toBe(0);
    });
  });

  describe('commitment edge cases', () => {
    it('should produce different commitments for different blob IDs', () => {
      const commitKey = randomBytes(32);
      const rawCt = randomBytes(64);

      const commit1 = computeCommitment(commitKey, 'b_id_one', rawCt);
      const commit2 = computeCommitment(commitKey, 'b_id_two', rawCt);

      expect(Buffer.from(commit1).equals(Buffer.from(commit2))).toBe(false);
    });

    it('should produce different commitments for different ciphertexts', () => {
      const commitKey = randomBytes(32);
      const rawCt1 = randomBytes(64);
      const rawCt2 = randomBytes(64);

      const commit1 = computeCommitment(commitKey, 'b_same_id', rawCt1);
      const commit2 = computeCommitment(commitKey, 'b_same_id', rawCt2);

      expect(Buffer.from(commit1).equals(Buffer.from(commit2))).toBe(false);
    });

    it('should verify correct commitment', () => {
      const commitKey = randomBytes(32);
      const rawCt = randomBytes(64);
      const blobId = 'b_test';

      const commit = computeCommitment(commitKey, blobId, rawCt);
      expect(verifyCommitment(commitKey, blobId, rawCt, commit)).toBe(true);
    });

    it('should reject commitment with wrong key', () => {
      const commitKey1 = randomBytes(32);
      const commitKey2 = randomBytes(32);
      const rawCt = randomBytes(64);
      const blobId = 'b_test';

      const commit = computeCommitment(commitKey1, blobId, rawCt);
      expect(verifyCommitment(commitKey2, blobId, rawCt, commit)).toBe(false);
    });
  });

  describe('tag tampering', () => {
    it('should reject if authentication tag is modified', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('sensitive data');
      const aad = new TextEncoder().encode('context');

      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);

      // Flip a bit in the tag
      const badTag = new Uint8Array(tag);
      badTag[0] ^= 0x01;

      expect(() => aeadDecrypt(key, nonce, ciphertext, badTag, aad)).toThrow();
    });
  });

  describe('ciphertext tampering', () => {
    it('should reject if ciphertext bytes are modified', () => {
      const key = randomBytes(32);
      const plaintext = new TextEncoder().encode('sensitive data');
      const aad = new TextEncoder().encode('context');

      const { nonce, ciphertext, tag } = aeadEncrypt(key, plaintext, aad);

      const badCt = new Uint8Array(ciphertext);
      badCt[0] ^= 0xff;

      expect(() => aeadDecrypt(key, nonce, badCt, tag, aad)).toThrow();
    });
  });
});
