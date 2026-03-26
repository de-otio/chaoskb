import { describe, it, expect } from 'vitest';
import {
  serializeEnvelopeCBOR,
  deserializeEnvelope,
  upgradeToV2,
  downgradeToV1,
} from '../envelope-cbor.js';
import type { Envelope, EnvelopeV2 } from '../types.js';

/** Create a sample v1 envelope for testing. */
function sampleV1(): Envelope {
  const ct = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const commit = Buffer.from([99, 98, 97, 96, 95, 94, 93, 92]);
  return {
    v: 1,
    id: 'b_test123',
    ts: '2026-03-20T10:00:00.000Z',
    enc: {
      alg: 'XChaCha20-Poly1305',
      kid: 'CEK',
      ct: ct.toString('base64'),
      'ct.len': ct.length,
      commit: commit.toString('base64'),
    },
  };
}

/** Create a sample v2 envelope for testing. */
function sampleV2(): EnvelopeV2 {
  return {
    v: 2,
    id: 'b_test456',
    ts: '2026-03-20T12:00:00.000Z',
    enc: {
      alg: 'XChaCha20-Poly1305',
      kid: 'CEK',
      ct: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
      commit: new Uint8Array([99, 98, 97, 96, 95, 94, 93, 92]),
    },
  };
}

describe('CBOR envelope serialization', () => {
  describe('serializeEnvelopeCBOR', () => {
    it('should serialize a v2 envelope to CBOR bytes', () => {
      const v2 = sampleV2();
      const bytes = serializeEnvelopeCBOR(v2);

      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBeGreaterThan(10);
      // Should start with magic header "CKB"
      expect(bytes[0]).toBe(0x43); // 'C'
      expect(bytes[1]).toBe(0x4b); // 'K'
      expect(bytes[2]).toBe(0x42); // 'B'
    });

    it('should produce smaller output than JSON+base64', () => {
      const v2 = sampleV2();
      const cborBytes = serializeEnvelopeCBOR(v2);

      // Compare with equivalent JSON v1
      const v1 = downgradeToV1(v2);
      const jsonBytes = new TextEncoder().encode(JSON.stringify(v1));

      // CBOR should be smaller (no base64 overhead)
      expect(cborBytes.length).toBeLessThan(jsonBytes.length);
    });
  });

  describe('deserializeEnvelope', () => {
    it('should round-trip a v2 envelope through CBOR', () => {
      const original = sampleV2();
      const bytes = serializeEnvelopeCBOR(original);
      const deserialized = deserializeEnvelope(bytes);

      expect(deserialized.v).toBe(2);
      const v2 = deserialized as EnvelopeV2;
      expect(v2.id).toBe(original.id);
      expect(v2.ts).toBe(original.ts);
      expect(v2.enc.alg).toBe(original.enc.alg);
      expect(v2.enc.kid).toBe(original.enc.kid);
      expect(new Uint8Array(v2.enc.ct)).toEqual(original.enc.ct);
      expect(new Uint8Array(v2.enc.commit)).toEqual(original.enc.commit);
    });

    it('should deserialize v1 JSON envelopes', () => {
      const v1 = sampleV1();
      const jsonBytes = new TextEncoder().encode(JSON.stringify(v1));
      const deserialized = deserializeEnvelope(jsonBytes);

      expect(deserialized.v).toBe(1);
      const parsed = deserialized as Envelope;
      expect(parsed.id).toBe(v1.id);
      expect(parsed.enc.ct).toBe(v1.enc.ct);
    });

    it('should auto-detect format by magic header', () => {
      const v2 = sampleV2();
      const cborBytes = serializeEnvelopeCBOR(v2);
      const v1 = sampleV1();
      const jsonBytes = new TextEncoder().encode(JSON.stringify(v1));

      // CBOR envelope
      const fromCbor = deserializeEnvelope(cborBytes);
      expect(fromCbor.v).toBe(2);

      // JSON envelope
      const fromJson = deserializeEnvelope(jsonBytes);
      expect(fromJson.v).toBe(1);
    });
  });

  describe('upgradeToV2', () => {
    it('should convert v1 to v2 with raw binary fields', () => {
      const v1 = sampleV1();
      const v2 = upgradeToV2(v1);

      expect(v2.v).toBe(2);
      expect(v2.id).toBe(v1.id);
      expect(v2.ts).toBe(v1.ts);
      expect(v2.enc.alg).toBe(v1.enc.alg);
      expect(v2.enc.kid).toBe(v1.enc.kid);
      expect(v2.enc.ct).toBeInstanceOf(Uint8Array);
      expect(v2.enc.commit).toBeInstanceOf(Uint8Array);
      // Binary ct should match decoded base64
      expect(v2.enc.ct).toEqual(new Uint8Array(Buffer.from(v1.enc.ct, 'base64')));
    });
  });

  describe('downgradeToV1', () => {
    it('should convert v2 to v1 with base64 fields', () => {
      const v2 = sampleV2();
      const v1 = downgradeToV1(v2);

      expect(v1.v).toBe(1);
      expect(v1.id).toBe(v2.id);
      expect(typeof v1.enc.ct).toBe('string');
      expect(typeof v1.enc.commit).toBe('string');
      expect(v1.enc['ct.len']).toBe(v2.enc.ct.length);
      // Decoded base64 should match original binary
      expect(new Uint8Array(Buffer.from(v1.enc.ct, 'base64'))).toEqual(v2.enc.ct);
    });

    it('should round-trip v1 -> v2 -> v1', () => {
      const original = sampleV1();
      const v2 = upgradeToV2(original);
      const roundTripped = downgradeToV1(v2);

      expect(roundTripped.v).toBe(original.v);
      expect(roundTripped.id).toBe(original.id);
      expect(roundTripped.enc.ct).toBe(original.enc.ct);
      expect(roundTripped.enc.commit).toBe(original.enc.commit);
      expect(roundTripped.enc['ct.len']).toBe(original.enc['ct.len']);
    });
  });

  describe('size comparison', () => {
    it('should save significant space with large ciphertext', () => {
      // Simulate a realistic chunk envelope (~4KB ciphertext)
      const largeCt = new Uint8Array(4096);
      for (let i = 0; i < largeCt.length; i++) largeCt[i] = i & 0xff;

      const v2: EnvelopeV2 = {
        v: 2,
        id: 'b_large_blob_test',
        ts: '2026-03-20T10:00:00.000Z',
        enc: {
          alg: 'XChaCha20-Poly1305',
          kid: 'CEK',
          ct: largeCt,
          commit: new Uint8Array(32),
        },
      };

      const cborSize = serializeEnvelopeCBOR(v2).length;
      const v1 = downgradeToV1(v2);
      const jsonSize = new TextEncoder().encode(JSON.stringify(v1)).length;

      // CBOR should save at least 25% on large payloads
      const savings = 1 - cborSize / jsonSize;
      expect(savings).toBeGreaterThan(0.25);
    });
  });
});
