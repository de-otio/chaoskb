import { randomBytes } from 'node:crypto';
import { SecureBuffer } from '@de-otio/crypto-envelope';

import { generateBlobId } from './blob-id.js';
import { encryptPayload, decryptEnvelope } from './envelope.js';
import { deriveKeySet } from './hkdf.js';
import type {
  DerivedKeySet,
  DecryptResult,
  EncryptResult,
  Envelope,
  IEncryptionService,
  ISecureBuffer,
  KeyId,
  Payload,
} from './types.js';

/**
 * Concrete implementation of IEncryptionService.
 *
 * Wraps the standalone crypto functions into a single injectable service.
 * Scope: chaoskb's knowledge-base blob pipeline (source/chunk/canary
 * envelopes). Master-key wrapping, passphrase KDF, project keys, and
 * device/invite flows live in `@de-otio/keyring`.
 */
export class EncryptionService implements IEncryptionService {
  /** Generate a new random 32-byte master key in a SecureBuffer. */
  generateMasterKey(): ISecureBuffer {
    const tmp = randomBytes(32);
    try {
      return SecureBuffer.from(Buffer.from(tmp));
    } finally {
      tmp.fill(0);
    }
  }

  /** Derive all subkeys from a master key via HKDF-SHA256. */
  deriveKeys(masterKey: ISecureBuffer, salt?: Uint8Array): DerivedKeySet {
    return deriveKeySet(new Uint8Array(masterKey.buffer), salt);
  }

  /** Encrypt a payload into an envelope. */
  encrypt(payload: Payload, keys: DerivedKeySet, kid?: KeyId): EncryptResult {
    return encryptPayload(payload, keys, kid);
  }

  /** Decrypt an envelope into a payload. */
  decrypt(envelope: Envelope, keys: DerivedKeySet): DecryptResult {
    return decryptEnvelope(envelope, keys);
  }

  /** Generate a CSPRNG blob ID (b_ prefix + base62). */
  generateBlobId(): string {
    return generateBlobId();
  }
}
