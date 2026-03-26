/**
 * CBOR serialization for ChaosKB envelopes (v2 wire format).
 *
 * v2 envelopes store ciphertext and commitment as raw binary (Uint8Array)
 * instead of base64, saving ~33% size overhead on the ciphertext field.
 *
 * Backward compatibility: can read both v1 (JSON) and v2 (CBOR) envelopes.
 */

import { encode, decode } from 'cborg';
import type { Envelope, EnvelopeV2, AnyEnvelope } from './types.js';

/** CBOR tag used to identify ChaosKB envelopes (arbitrary, in private range). */
const CHAOSKB_CBOR_MAGIC = new Uint8Array([0x43, 0x4b, 0x42]); // "CKB"

/**
 * Serialize an envelope to CBOR binary format (v2).
 *
 * @param envelope - A v2 envelope with raw binary ct and commit.
 * @returns CBOR-encoded bytes.
 */
export function serializeEnvelopeCBOR(envelope: EnvelopeV2): Uint8Array {
  const cborPayload = {
    v: envelope.v,
    id: envelope.id,
    ts: envelope.ts,
    enc: {
      alg: envelope.enc.alg,
      kid: envelope.enc.kid,
      ct: envelope.enc.ct,
      commit: envelope.enc.commit,
    },
  };

  const cborBytes = encode(cborPayload);

  // Prepend magic header so we can distinguish CBOR from JSON
  const result = new Uint8Array(CHAOSKB_CBOR_MAGIC.length + cborBytes.length);
  result.set(CHAOSKB_CBOR_MAGIC, 0);
  result.set(cborBytes, CHAOSKB_CBOR_MAGIC.length);

  return result;
}

/**
 * Deserialize bytes into an envelope, auto-detecting the format.
 *
 * - If bytes start with "CKB" magic header, decode as CBOR (v2)
 * - If bytes start with '{', decode as JSON (v1)
 *
 * @param bytes - Raw envelope bytes.
 * @returns Parsed envelope (v1 or v2).
 */
export function deserializeEnvelope(bytes: Uint8Array): AnyEnvelope {
  // Check for CBOR magic header
  if (
    bytes.length >= CHAOSKB_CBOR_MAGIC.length &&
    bytes[0] === CHAOSKB_CBOR_MAGIC[0] &&
    bytes[1] === CHAOSKB_CBOR_MAGIC[1] &&
    bytes[2] === CHAOSKB_CBOR_MAGIC[2]
  ) {
    return deserializeCBOR(bytes.subarray(CHAOSKB_CBOR_MAGIC.length));
  }

  // Try JSON (v1)
  return deserializeJSON(bytes);
}

/**
 * Decode CBOR bytes into a v2 envelope.
 */
function deserializeCBOR(cborBytes: Uint8Array): EnvelopeV2 {
  const parsed = decode(cborBytes) as {
    v: number;
    id: string;
    ts: string;
    enc: {
      alg: string;
      kid: string;
      ct: Uint8Array;
      commit: Uint8Array;
    };
  };

  if (parsed.v !== 2) {
    throw new Error(`CBOR envelope has unexpected version: ${parsed.v}`);
  }

  return {
    v: 2,
    id: parsed.id,
    ts: parsed.ts,
    enc: {
      alg: parsed.enc.alg as EnvelopeV2['enc']['alg'],
      kid: parsed.enc.kid as EnvelopeV2['enc']['kid'],
      ct: new Uint8Array(parsed.enc.ct),
      commit: new Uint8Array(parsed.enc.commit),
    },
  };
}

/**
 * Decode JSON bytes into a v1 envelope.
 */
function deserializeJSON(bytes: Uint8Array): Envelope {
  const json = new TextDecoder().decode(bytes);
  const parsed = JSON.parse(json) as Envelope;

  if (parsed.v !== 1) {
    throw new Error(`JSON envelope has unexpected version: ${parsed.v}`);
  }

  return parsed;
}

/**
 * Convert a v1 (JSON) envelope to a v2 (CBOR) envelope.
 * Decodes base64 fields to raw binary.
 */
export function upgradeToV2(v1: Envelope): EnvelopeV2 {
  return {
    v: 2,
    id: v1.id,
    ts: v1.ts,
    enc: {
      alg: v1.enc.alg,
      kid: v1.enc.kid,
      ct: new Uint8Array(Buffer.from(v1.enc.ct, 'base64')),
      commit: new Uint8Array(Buffer.from(v1.enc.commit, 'base64')),
    },
  };
}

/**
 * Convert a v2 (CBOR) envelope back to v1 (JSON) format.
 * Encodes binary fields as base64.
 */
export function downgradeToV1(v2: EnvelopeV2): Envelope {
  const ctBase64 = Buffer.from(v2.enc.ct).toString('base64');
  return {
    v: 1,
    id: v2.id,
    ts: v2.ts,
    enc: {
      alg: v2.enc.alg,
      kid: v2.enc.kid,
      ct: ctBase64,
      'ct.len': v2.enc.ct.length,
      commit: Buffer.from(v2.enc.commit).toString('base64'),
    },
  };
}
